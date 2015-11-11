# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import copy
import os
import subprocess

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import importutils
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload
from sqlalchemy.sql import expression as expr
from sqlalchemy.sql import false as sql_false

from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import utils
from neutron import context as n_context
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.extensions import l3
from neutron.extensions import providernet as pr_net
from neutron.i18n import _LE, _LI
from neutron import manager
from neutron.openstack.common import loopingcall
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.db.device_manager import hd_models
from neutron.plugins.cisco.db.l3 import l3_models
from neutron.plugins.cisco.device_manager import config
from neutron.plugins.cisco.extensions import ciscohostingdevicemanager
from neutron.plugins.cisco.extensions import ha
from neutron.plugins.cisco.extensions import routerhostingdevice
from neutron.plugins.cisco.extensions import routerrole
from neutron.plugins.cisco.extensions import routertype
from neutron.plugins.cisco.extensions import routertypeawarescheduler
from neutron.plugins.cisco.l3.drivers import driver_context
from neutron.plugins.common import constants as svc_constants

LOG = logging.getLogger(__name__)

EXTERNAL_GW_INFO = l3.EXTERNAL_GW_INFO
FLOATINGIP_STATUS_ACTIVE = l3_constants.FLOATINGIP_STATUS_ACTIVE
AGENT_TYPE_L3 = l3_constants.AGENT_TYPE_L3
AGENT_TYPE_L3_CFG = cisco_constants.AGENT_TYPE_L3_CFG
VM_CATEGORY = ciscohostingdevicemanager.VM_CATEGORY
L3_ROUTER_NAT = svc_constants.L3_ROUTER_NAT

ROUTER_APPLIANCE_OPTS = [
    cfg.StrOpt('default_router_type',
               default=cisco_constants.CSR1KV_ROUTER_TYPE,
               help=_("Default type of router to create")),
    cfg.StrOpt('namespace_router_type_name',
               default=cisco_constants.NAMESPACE_ROUTER_TYPE,
               help=_("Name of router type used for Linux network namespace "
                      "routers (i.e., Neutron's legacy routers in Network "
                      "nodes).")),
    cfg.IntOpt('backlog_processing_interval',
               default=10,
               help=_('Time in seconds between renewed scheduling attempts of '
                      'non-scheduled routers.')),
]

cfg.CONF.register_opts(ROUTER_APPLIANCE_OPTS, "routing")


class RouterCreateInternalError(n_exc.NeutronException):
    message = _("Router could not be created due to internal error.")


class RouterInternalError(n_exc.NeutronException):
    message = _("Internal error during router processing.")


class RouterBindingInfoError(n_exc.NeutronException):
    message = _("Could not get binding information for router %(router_id)s.")


class L3RouterApplianceDBMixin(extraroute_db.ExtraRoute_dbonly_mixin):
    """Mixin class implementing Neutron's routing service using appliances."""

    # Dictionary with loaded scheduler modules for different router types
    _router_schedulers = {}

    # Dictionary with loaded driver modules for different router types
    _router_drivers = {}

    # Id of router type used to represent Neutron's "legacy" Linux network
    # namespace routers
    _namespace_router_type_id = None

    # Set of ids of routers for which new scheduling attempts should
    # be made and the refresh setting and heartbeat for that.
    _backlogged_routers = set()
    _refresh_router_backlog = True
    _heartbeat = None

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_router_dict_routertype',
                     '_extend_router_dict_routerhostingdevice',
                     '_extend_router_dict_routerrole',
                     '_extend_router_dict_scheduling_info',
                     '_extend_router_dict_ha'])

    def _cisco_router_model_hook(self, context, original_model, query):
        query = query.join(l3_models.RouterHostingDeviceBinding,
                           (original_model.id ==
                            l3_models.RouterHostingDeviceBinding.router_id))
        return query

    def _cisco_router_result_filter_hook(self, query, filters):
        if filters:
            rt_values = filters.get(routertype.TYPE_ATTR, [])
            rhd_values = filters.get(routerhostingdevice.HOSTING_DEVICE_ATTR,
                                     [])
            role_values = filters.get(routerrole.ROUTER_ROLE_ATTR, [])
        else:
            return query
        if rt_values:
            query = query.filter(
                l3_models.RouterHostingDeviceBinding.router_type_id.in_(
                    rt_values))
        if rhd_values:
            query = query.filter(
                l3_models.RouterHostingDeviceBinding.hosting_device_id.in_(
                    rhd_values))
        if role_values:
            null_search = False
            r_values = []
            for idx, role_value in enumerate(role_values):
                if role_value == "None" or role_value is None:
                    null_search = True
                else:
                    r_values.append(role_value)
            if null_search is True and r_values:
                query = query.filter(expr.or_(
                    l3_models.RouterHostingDeviceBinding.role == expr.null(),
                    l3_models.RouterHostingDeviceBinding.role.in_(r_values)))
            elif r_values:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.role.in_(r_values))
            else:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.role == expr.null())
        return query

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        l3_db.Router,
        "cisco_router_model_hook",
        '_cisco_router_model_hook',
        None,
        '_cisco_router_result_filter_hook')

    def do_create_router(self, context, router, router_type_id, auto_schedule,
                         share_host, hosting_device_id=None, role=None,
                         inflated_slot_need=0):
        with context.session.begin(subtransactions=True):
            router_created = (super(L3RouterApplianceDBMixin, self).
                              create_router(context, router))
            r_hd_b_db = l3_models.RouterHostingDeviceBinding(
                router_id=router_created['id'],
                role=role,
                router_type_id=router_type_id,
                inflated_slot_need=inflated_slot_need,
                auto_schedule=auto_schedule,
                share_hosting_device=share_host,
                hosting_device_id=hosting_device_id)
            context.session.add(r_hd_b_db)
        router_created[routertype.TYPE_ATTR] = router_type_id
        router_created[routertypeawarescheduler.AUTO_SCHEDULE_ATTR] = (
            auto_schedule)
        router_created[routertypeawarescheduler.SHARE_HOST_ATTR] = share_host
        router_created[routerhostingdevice.HOSTING_DEVICE_ATTR] = (
            hosting_device_id)
        return router_created, r_hd_b_db

    def create_router(self, context, router):
        r = router['router']
        router_role = self._ensure_router_role_compliant(r)
        router_type = self._ensure_create_routertype_compliant(context, r)
        router_type_id = router_type['id']
        is_ha = (utils.is_extension_supported(self, ha.HA_ALIAS) and
                 router_type_id != self.get_namespace_router_type_id(context))
        if is_ha:
            # Ensure create spec is compliant with any HA
            ha_spec = self._ensure_create_ha_compliant(r, router_type)
        auto_schedule, share_host = self._ensure_router_scheduling_compliant(r)
        driver = self._get_router_type_driver(context,
                                              router_type_id)
        if driver:
            router_ctxt = driver_context.RouterContext(router)
            driver.create_router_precommit(context, router_ctxt)

        router_created, r_hd_b_db = self.do_create_router(
            context, router, router_type_id, auto_schedule, share_host, None,
            router_role)
        if is_ha:
            # process any HA
            self._create_redundancy_routers(context, router_created, ha_spec,
                                            r_hd_b_db.router)
        if auto_schedule is True:
            # backlog so this new router gets scheduled asynchronously
            self.backlog_router(context, r_hd_b_db)
        return router_created

    def _update_router_no_notify(self, context, router_id, router):
        r = router['router']
        old_router_db = self._get_router(context, router_id)
        old_router = self._make_router_dict(old_router_db)
        r_hd_binding_db = old_router_db.hosting_info
        is_ha = (utils.is_extension_supported(self, ha.HA_ALIAS) and
                 r_hd_binding_db.router_type_id !=
                 self.get_namespace_router_type_id(context))
        if is_ha:
            # Ensure update is compliant with any HA
            req_ha_settings = self._ensure_update_ha_compliant(r, old_router,
                                                               r_hd_binding_db)
        # Check if external gateway has changed so we may have to
        # update trunking
        old_ext_gw = (old_router_db.gw_port or {}).get('network_id')
        new_ext_gw = r.get(EXTERNAL_GW_INFO, attributes.ATTR_NOT_SPECIFIED)
        if new_ext_gw != attributes.ATTR_NOT_SPECIFIED:
            gateway_changed = old_ext_gw != (new_ext_gw or {}).get(
                'network_id')
        else:
            gateway_changed = False
        e_context = context.elevated()
        if old_ext_gw is not None and gateway_changed:
            # no need to schedule now since we're only doing this to tear-down
            # connectivity and there won't be any if not already scheduled
            self.add_type_and_hosting_device_info(
                e_context, old_router, r_hd_binding_db, schedule=False)
            p_drv = self._dev_mgr.get_hosting_device_plugging_driver(
                e_context,
                (old_router['hosting_device'] or {}).get('template_id'))
            if p_drv is not None:
                p_drv.teardown_logical_port_connectivity(
                    e_context, old_router_db.gw_port,
                    r_hd_binding_db.hosting_device_id)
            if is_ha:
                # process any HA
                self._teardown_redundancy_router_gw_connectivity(
                    context, old_router, old_router_db, p_drv)
        router_updated = (
            super(L3RouterApplianceDBMixin, self).update_router(
                context, router_id, router))
        if is_ha:
            # process any HA
            self._update_redundancy_routers(context, router_updated, router,
                                            req_ha_settings, old_router_db,
                                            gateway_changed)
        routers = [copy.deepcopy(router_updated)]
        driver = self._get_router_type_driver(context,
                                              r_hd_binding_db.router_type_id)
        if driver:
            router_ctxt = driver_context.RouterContext(routers[0], old_router)
            driver.update_router_postcommit(context, router_ctxt)
        return router_updated

    def update_router(self, context, id, router):
        router_updated = self._update_router_no_notify(context, id, router)
        self.add_type_and_hosting_device_info(context.elevated(),
                                              router_updated)
        router_type_id = self.get_router_type_id(context, id)
        driver = self._get_router_type_driver(context,
                                              router_type_id)
        if driver:
            router_ctxt = driver_context.RouterContext(router_updated,
                                                       router)
            driver.update_router_postcommit(context, router_ctxt)

        for ni in self.get_notifiers(context, [router_updated]):
            if ni['notifier']:
                ni['notifier'].routers_updated(context, ni['routers'])
        return router_updated

    #Todo(bobmel): Move this to l3_routertype_aware_schedulers_db later
    def _check_router_needs_rescheduling(self, context, router_id, gw_info):
        try:
            ns_routertype_id = self.get_namespace_router_type_id(context)
            router_type_id = self.get_router_type_id(context, router_id)
        except (AttributeError, n_exc.NeutronException):
            return
        if router_type_id != ns_routertype_id:
            LOG.debug('Router %(r_id)s is of type %(t_id)s which is not '
                      'hosted by l3 agents',
                      {'r_id': router_id, 't_id': router_type_id})
            return
        return super(L3RouterApplianceDBMixin,
                     self)._check_router_needs_rescheduling(context, router_id,
                                                            gw_info)

    def delete_router(self, context, router_id, unschedule=True):
        router_db = self._ensure_router_not_in_use(context, router_id)
        router = self._make_router_dict(router_db)
        router_type_id = self.get_router_type_id(context, router_id)
        driver = self._get_router_type_driver(context,
                                              router_type_id)
        if driver:
            router_ctxt = driver_context.RouterContext(router)
            driver.delete_router_precommit(context, router_ctxt)

        e_context = context.elevated()
        r_hd_binding_db = router_db.hosting_info
        # disable scheduling now since router is to be deleted and we're only
        # doing this to tear-down connectivity in case it is already scheduled
        self.add_type_and_hosting_device_info(
            e_context, router, r_hd_binding_db, schedule=False)
        if router_db.gw_port is not None:
            p_drv = self._dev_mgr.get_hosting_device_plugging_driver(
                e_context,
                (router['hosting_device'] or {}).get('template_id'))
            if p_drv is not None:
                LOG.debug("Tearing down connectivity for port %s",
                          router_db.gw_port.id)
                p_drv.teardown_logical_port_connectivity(
                    e_context, router_db.gw_port,
                    r_hd_binding_db.hosting_device_id)
        if unschedule is True:
            # conditionally remove router from backlog just to be sure
            self.remove_router_from_backlog(router_id)
        for ni in self.get_notifiers(context, [router]):
            if ni['notifier']:
                ni['notifier'].router_deleted(context, ni['routers'][0])
        # TODO(bobmel): Change status to PENDING_DELETE and delay actual
        # deletion from DB until cfg agent signals that it has deleted the
        # router from the hosting device.
        if router['hosting_device'] is not None and unschedule is True:
            LOG.debug("Unscheduling router %s", r_hd_binding_db.router_id)
            self.unschedule_router_from_hosting_device(context,
                                                       r_hd_binding_db)
            was_hosted = True
        else:
            was_hosted = False
        try:
            is_ha = (utils.is_extension_supported(self, ha.HA_ALIAS) and
                     r_hd_binding_db.router_type_id !=
                     self.get_namespace_router_type_id(context))
            if is_ha:
                # process any HA
                self._delete_redundancy_routers(context, router_db)
            super(L3RouterApplianceDBMixin, self).delete_router(context,
                                                                router_id)
        except n_exc.NeutronException:
            with excutils.save_and_reraise_exception():
                # put router back in backlog if deletion failed so that it
                # gets reinstated
                LOG.exception(_LE("Deletion of router %s failed. It will be "
                                  "re-hosted."), router_id)
                if was_hosted is True or r_hd_binding_db.auto_schedule is True:
                    LOG.info(_LI("Router %s will be re-hosted."), router_id)
                    self.backlog_router(context, r_hd_binding_db)

    def notify_router_interface_action(
            self, context, router_interface_info, routers, action):
        l3_method = '%s_router_interface' % action
        for ni in self.get_notifiers(context, routers):
            if ni['notifier']:
                ni['notifier'].routers_updated(context, ni['routers'],
                                               l3_method)
        mapping = {'add': 'create', 'remove': 'delete'}
        notifier = n_rpc.get_notifier('network')
        router_event = 'router.interface.%s' % mapping[action]
        notifier.info(context, router_event,
                      {'router_interface': router_interface_info})

    def add_router_interface(self, context, router_id, interface_info):
        info = (super(L3RouterApplianceDBMixin, self).
                add_router_interface(context, router_id, interface_info))
        context.session.expire_all()
        r_hd_binding_db = self._get_router_binding_info(context.elevated(),
                                                        router_id)
        is_ha = (utils.is_extension_supported(self, ha.HA_ALIAS) and
                 r_hd_binding_db.router_type_id !=
                 self.get_namespace_router_type_id(context))
        if is_ha:
            # process any HA
            self._add_redundancy_router_interfaces(
                context, self._make_router_dict(r_hd_binding_db.router),
                interface_info, self._core_plugin.get_port(context,
                                                           info['port_id']))
        routers = [self.get_router(context, router_id)]
        self.add_type_and_hosting_device_info(context.elevated(), routers[0])

        driver = self._get_router_type_driver(context,
                                              r_hd_binding_db.router_type_id)
        if driver:
            by_port, by_subnet = self._validate_interface_info(
                interface_info)
            if by_subnet:
                subnet_db = self._core_plugin._get_subnet(
                    context, interface_info['subnet_id'])
                port_db = self._get_router_port_db_on_subnet(
                    r_hd_binding_db.router, subnet_db)
            else:
                port_db = self._core_plugin.get_port(context,
                    interface_info['port_id'])
            port_ctxt = driver_context.RouterPortContext(port_db)
            driver.add_router_interface_postcommit(context, port_ctxt)

        self.notify_router_interface_action(context, info, routers, 'add')
        return info

    def _confirm_router_interface_not_in_use_on_subnet(
            self, context, router_id, port_db, subnet_id):
        port_subnet_ids = [fixed_ip['subnet_id']
                           for fixed_ip in port_db['fixed_ips']]
        if subnet_id and subnet_id not in port_subnet_ids:
            raise n_exc.SubnetMismatchForPort(port_id=port_db.id,
                                              subnet_id=subnet_id)
        for port_subnet_id in port_subnet_ids:
            self._confirm_router_interface_not_in_use(context, router_id,
                                                      port_subnet_id)

    def remove_router_interface(self, context, router_id, interface_info):
        remove_by_port, remove_by_subnet = self._validate_interface_info(
            interface_info, for_removal=True)
        e_context = context.elevated()
        r_hd_binding_db = self._get_router_binding_info(e_context, router_id)
        router_type_id = self.get_router_type_id(context, router_id)
        driver = self._get_router_type_driver(context,
                                              router_type_id)
        if remove_by_port:
            port_db = self._core_plugin._get_port(context,
                                                  interface_info['port_id'])
            self._confirm_router_interface_not_in_use_on_subnet(
                context, router_id, port_db, interface_info.get('subnet_id'))
        else:
            self._confirm_router_interface_not_in_use(
                context, router_id, interface_info['subnet_id'])
            subnet_db = self._core_plugin._get_subnet(
                context, interface_info['subnet_id'])
            port_db = self._get_router_port_db_on_subnet(
                r_hd_binding_db.router, subnet_db)
        if driver:
            port_ctxt = driver_context.RouterPortContext(port_db)
            driver.remove_router_interface_precommit(context, port_ctxt)

        routers = [self.get_router(context, router_id)]
        self.add_type_and_hosting_device_info(e_context, routers[0],
                                              r_hd_binding_db)
        p_drv = self._dev_mgr.get_hosting_device_plugging_driver(
            e_context, (routers[0]['hosting_device'] or {}).get('template_id'))
        if p_drv is not None:
            p_drv.teardown_logical_port_connectivity(
                e_context, port_db, r_hd_binding_db.hosting_device_id)
        is_ha = (utils.is_extension_supported(self, ha.HA_ALIAS) and
                 r_hd_binding_db.router_type_id !=
                 self.get_namespace_router_type_id(context))
        if is_ha:
            # process any HA
            self._remove_redundancy_router_interfaces(context, router_id,
                                                      port_db)
        info = super(L3RouterApplianceDBMixin, self).remove_router_interface(
            context, router_id, interface_info)
        self.notify_router_interface_action(context, info, routers, 'remove')
        return info

    def create_floatingip(self, context, floatingip,
                          initial_status=FLOATINGIP_STATUS_ACTIVE):
        info = super(L3RouterApplianceDBMixin, self).create_floatingip(
            context, floatingip, initial_status)
        router_ids = [info['router_id']] if info['router_id'] else []
        if info['router_id']:
            router_type_id = self.get_router_type_id(context, info['router_id'])
            driver = self._get_router_type_driver(context,
                                                  router_type_id)
            if driver:
                fip_ctxt = driver_context.FloatingipContext(
                        floatingip.get('floating_ip'))
                driver.update_floatingip_postcommit(context, fip_ctxt)
        self._notify_affected_routers(context, router_ids, 'create_floatingip')
        return info

    def update_floatingip(self, context, floatingip_id, floatingip):
        orig_fl_ip = super(L3RouterApplianceDBMixin, self).get_floatingip(
            context, floatingip_id)
        before_router_id = orig_fl_ip['router_id']
        info = super(L3RouterApplianceDBMixin, self).update_floatingip(
            context, floatingip_id, floatingip)
        router_ids = []
        if before_router_id:
            router_ids.append(before_router_id)
        r_id = info['router_id']
        if r_id and r_id != before_router_id:
            router_ids.append(r_id)
            router_type_id = self.get_router_type_id(context, r_id)
            driver = self._get_router_type_driver(context,
                                                  router_type_id)
            if driver:
                fip_ctxt = driver_context.FloatingipContext(
                        floatingip.get('floatingip'),
                        orig_fl_ip)
                driver.update_floatingip_postcommit(context, fip_ctxt)
        self._notify_affected_routers(context, router_ids, 'update_floatingip')
        return info

    def delete_floatingip(self, context, floatingip_id):
        floatingip_db = self._get_floatingip(context, floatingip_id)
        router_id = floatingip_db['router_id']
        super(L3RouterApplianceDBMixin, self).delete_floatingip(context,
                                                                floatingip_id)
        router_ids = [router_id] if router_id else []
        if router_id:
            router_type_id = self.get_router_type_id(context, router_id)
            driver = self._get_router_type_driver(context,
                                                  router_type_id)
            if driver:
                fip_ctxt = driver_context.FloatingipContext(
                        self._make_floatingip_dict(floatingip_db))
                driver.delete_floatingip_postcommit(context, fip_ctxt)
        self._notify_affected_routers(context, router_ids, 'delete_floatingip')

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        router_ids = super(L3RouterApplianceDBMixin,
                           self).disassociate_floatingips(context, port_id)
        if router_ids and do_notify:
            self._notify_affected_routers(context, list(router_ids),
                                          'disassociate_floatingips')
            # since caller assumes that we handled notifications on its
            # behalf, return nothing
            return []
        return router_ids

    def get_routers_count_extended(self, context, filters=None,
                                   invert_filters=None):
        qry = self._get_collection_query(context, l3_db.Router,
                                         filters)
        qry = self._apply_invert_filters_to_query(qry, l3_db.Router,
                                                  invert_filters)
        return qry.count()

    def _apply_invert_filters_to_query(self, query, model, invert_filters):
        if invert_filters:
            for key, values in invert_filters.iteritems():
                column = getattr(model, key, None)
                if column:
                    if not values:
                        query = query.filter(sql_false())
                        return query
                    filter_values = []
                    null_search = False
                    for idx, value in enumerate(values):
                        if value is None:
                            null_search = True
                        else:
                            filter_values.append(value)
                    if null_search is True:
                        query = query.filter(column != expr.null())
                    if filter_values:
                        query = query.filter(~column.in_(values))
        return query

    @lockutils.synchronized('routerbacklog', 'neutron-')
    def handle_non_responding_hosting_devices(self, context, hosting_devices,
                                              affected_resources):
        """Handle hosting devices determined to be "dead".

        This function is called by the hosting device manager.
        Service plugins are supposed to extend the 'affected_resources'
        dictionary. Hence, we add the uuid of Neutron routers that are
        hosted in <hosting_devices>.

        param: hosting_devices - list of dead hosting devices
        param: affected_resources - dict with list of affected logical
                                    resources per hosting device:
             {'hd_uuid1': {'routers': [uuid1, uuid2, ...],
                           'fw': [uuid1, ...],
                           ...},
              'hd_uuid2': {'routers': [uuid3, uuid4, ...],
                           'fw': [uuid1, ...],
                           ...},
             ...}
        """
        LOG.debug('Processing affected routers in dead hosting devices')
        with context.session.begin(subtransactions=True):
            for hd in hosting_devices:
                hd_bindings_db = self._get_hosting_device_bindings(context,
                                                                   hd['id'])
                router_ids = []
                for binding_db in hd_bindings_db:
                    self.unschedule_router_from_hosting_device(context,
                                                               binding_db)
                    binding_db.hosting_device_id = None
                    router_ids.append(binding_db.router_id)
                    if binding_db.auto_schedule is True:
                        self._backlog_router(context, binding_db)
                    try:
                        affected_resources[hd['id']].update(
                            {'routers': router_ids})
                    except KeyError:
                        affected_resources[hd['id']] = {'routers': router_ids}
        LOG.debug('Finished processing affected routers in dead hosting '
                  'devices')

    def get_sync_data(self, context, router_ids=None, active=None):
        # ensure only routers of namespace type are returned
        router_ids = self._get_relevant_router_ids(context, router_ids, True)
        return super(L3RouterApplianceDBMixin,
                     self).get_sync_data(context, router_ids, active)

    def get_sync_data_ext(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces.

        Adds information about hosting device as well as trunking.
        """
        # ensure that routers of namespace type are not returned
        router_ids = self._get_relevant_router_ids(context, router_ids)
        sync_data = super(L3RouterApplianceDBMixin,
                          self).get_sync_data(context, router_ids, active)
        for router in sync_data:
            self.add_type_and_hosting_device_info(context, router)
            if utils.is_extension_supported(self, ha.HA_ALIAS):
                # process any HA
                self._populate_ha_information(context, router)
            plg_drv = self._dev_mgr.get_hosting_device_plugging_driver(
                context,
                (router.get('hosting_device') or {}).get('template_id'))
            if plg_drv and router['hosting_device']:
                self._add_hosting_port_info(context, router, plg_drv)
        return sync_data

    def schedule_router_on_hosting_device(self, context, binding_info_db,
                                          hosting_device_id=None,
                                          slot_need=None, synchronized=True):
        LOG.info(_LI('Attempting to schedule router %s.'),
                 binding_info_db.router.id)
        if hosting_device_id is None:
            scheduler = self._get_router_type_scheduler(
                context, binding_info_db.router_type_id)
            if scheduler is None:
                LOG.debug('Aborting scheduling of router %(r_id)s as no '
                          'scheduler was found for its router type %(type)s.',
                          {'r_id': binding_info_db.router.id,
                           'type': binding_info_db.router_type_id})
                return False
            result = scheduler.schedule_router(self, context, binding_info_db)
        else:
            result = [hosting_device_id]
        if result is None:
            # No running hosting device is able to host this router
            return self._handle_failed_scheduling_no_host(
                context, binding_info_db, synchronized)
        else:
            # We have a candidate so try to allocate slots in and bind to it
            return self._try_allocate_slots_and_bind_to_host(
                context, binding_info_db, result[0], slot_need, synchronized)

    def _handle_failed_scheduling_no_host(self, context, binding_info_db,
                                          synchronized):
        if binding_info_db.auto_schedule is True:
            # so backlog it for another scheduling attempt later.
            if synchronized:
                self.backlog_router(context, binding_info_db)
            else:
                self._backlog_router(context, binding_info_db)
        # Inform device manager so that it can take appropriate
        # measures, e.g., spin up more hosting device VMs.
        routertype_db = binding_info_db.router_type
        self._dev_mgr.report_hosting_device_shortage(
            context, routertype_db.template, routertype_db.slot_need)
        return False

    def _try_allocate_slots_and_bind_to_host(
            self, context, binding_info_db, target_hosting_device_id,
            slot_need, synchronized):
        router_db = binding_info_db.router
        driver = self._get_router_type_driver(
            context, binding_info_db.router_type_id)
        e_context = context.elevated()
        selected_hd = self._dev_mgr.get_hosting_devices_qry(
            e_context, [target_hosting_device_id], load_agent=False).one()
        with context.session.begin(subtransactions=True):
            # use slot_need if specified (for router migration cases
            # where effective router type is different than router's
            # normal router type).
            acquired = self._dev_mgr.acquire_hosting_device_slots(
                e_context, selected_hd, router_db, 'router', L3_ROUTER_NAT,
                slot_need or binding_info_db.router_type.slot_need,
                exclusive=not binding_info_db.share_hosting_device)
            if acquired is True:
                binding_info_db.hosting_device_id = selected_hd['id']
                if synchronized:
                    self.remove_router_from_backlog(router_db['id'])
                else:
                    self._remove_router_from_backlog(router_db['id'])
                LOG.info(_LI('Successfully scheduled router %(r_id)s to '
                             'hosting device %(d_id)s'),
                         {'r_id': binding_info_db.router.id,
                          'd_id': binding_info_db.hosting_device_id})
                context.session.add(binding_info_db)
                if driver:
                    router_ctxt = driver_context.RouterContext(
                        self._make_router_dict(router_db))
                    driver.schedule_router_precommit(context, router_ctxt)
            else:
                LOG.debug('Could not allocated slots for router %(r_id)s '
                          'in hosting device %(d_id)s.',
                          {'r_id': binding_info_db.router.id,
                           'd_id': binding_info_db.hosting_device_id})
                if binding_info_db.auto_schedule is True:
                    # we got no slot so backlog it for another scheduling
                    # attempt later.
                    if synchronized:
                        self.backlog_router(context, binding_info_db)
                    else:
                        self._backlog_router(context, binding_info_db)
        if driver:
            router_ctxt = driver_context.RouterContext(
                self._make_router_dict(router_db))
            driver.schedule_router_postcommit(context, router_ctxt)
        return acquired

    def unschedule_router_from_hosting_device(self, context, binding_info_db):
        LOG.info(_LI('Attempting to un-schedule router %s.'),
                 binding_info_db.router_id)
        if binding_info_db.hosting_device is None:
            return False
        scheduler = self._get_router_type_scheduler(
            context, binding_info_db.router_type_id)
        if scheduler is None:
            return False
        driver = self._get_router_type_driver(context,
                                              binding_info_db.router_type_id)
        router_ctxt = driver_context.RouterContext(
                self._make_router_dict(binding_info_db.router))
        with context.session.begin(subtransactions=True):
            result = scheduler.unschedule_router(self, context,
                                                 binding_info_db)
            if result is True:
                # must use slot need for effective (i.e., current) router type
                slot_need = self._get_effective_slot_need(context,
                                                          binding_info_db)
                self._dev_mgr.release_hosting_device_slots(
                    context, binding_info_db.hosting_device,
                    binding_info_db.router, slot_need)
                LOG.info(_LI('Successfully un-scheduled router %(r_id)s from '
                             'hosting device %(d_id)s'),
                         {'r_id': binding_info_db.router_id,
                          'd_id': binding_info_db.hosting_device_id})
                if driver:
                    driver.unschedule_router_precommit(context, router_ctxt)
        if driver:
            driver.unschedule_router_postcommit(context, router_ctxt)

    def notify_routers_updated(self, context, router_ids,
                               operation=None, data=None):
        routers = []
        for r_id in router_ids:
            router = self.get_router(context, r_id)
            self.add_type_and_hosting_device_info(context.elevated(), router)
            routers.append(router)
        for ni in self.get_notifiers(context, routers):
            if ni['notifier']:
                ni['notifier'].routers_updated(context, ni['routers'],
                                               operation, data)

    def update_router_port_statuses(self, context, port_ids, status):
        """Function that gets called when asr plugin notifies about router port
           status changes. By default, all ports are created with status set to
           DOWN and when the ASR plugin creates the port it notifies the DB to
           change the status to ACTIVE.
        """
        for port_id in port_ids:
            self._core_plugin.update_port_status(context, port_id, status)

    def _notify_affected_routers(self, context, router_ids, operation):
        ha_supported = utils.is_extension_supported(self, ha.HA_ALIAS)
        valid_router_ids = []
        e_context = context.elevated()
        for main_router_id in router_ids:
            if main_router_id is None:
                continue
            valid_router_ids.append(main_router_id)
            r_hd_binding_db = self._get_router_binding_info(context.elevated(),
                                                            main_router_id)
            is_ha = (ha_supported and r_hd_binding_db.router_type_id !=
                     self.get_namespace_router_type_id(context))
            if is_ha:
                # find redundancy routers for this ha-enabled router
                router_id_list = self._redundancy_routers_for_floatingip(
                    e_context, main_router_id)
                if router_id_list:
                    valid_router_ids.extend(router_id_list)
        self.notify_routers_updated(e_context, valid_router_ids, operation)

    def get_router_type_id(self, context, router_id):
        r_hd_b = self._get_router_binding_info(context, router_id,
                                               load_hd_info=False)
        return r_hd_b['router_type_id']

    def _is_master_process(self):
        ppid = os.getppid()
        parent_name = subprocess.check_output(
            ["ps", "-p", str(ppid), "-o", "comm="])
        is_master = parent_name != "python"
        LOG.debug('Executable for parent process(%d) is %s so this is %s '
                  'process (%d)' % (ppid, parent_name,
                                    'the MASTER' if is_master else 'a WORKER',
                                    os.getpid()))
        return is_master

    def get_namespace_router_type_id(self, context):
        if self._namespace_router_type_id is None:
            if self._is_master_process() is True:
                # This should normally only happen once so we register
                # router types defined in config file here in the master
                # process.
                self._create_router_types_from_config()
            # activate processing of backlogged (i.e., non-scheduled) routers
            self._setup_backlog_handling()
            try:
                self._namespace_router_type_id = (
                    self.get_routertype_db_by_id_name(
                        context,
                        cfg.CONF.routing.namespace_router_type_name)['id'])
            except n_exc.NeutronException:
                self._namespace_router_type_id = ''
        return self._namespace_router_type_id

    @lockutils.synchronized('routerbacklog', 'neutron-')
    def backlog_router(self, context, binding_info_db):
        LOG.debug('Trying to backlog router %s' % binding_info_db.router_id)
        # Ensure we get latest state from DB in case it was updated while
        # thread was waiting for lock to enter this function
        context.session.expire(binding_info_db)
        # call unsynchronized version to actually add to backlog
        self._backlog_router(context, binding_info_db)

    def _backlog_router(self, context, binding_info_db):
        # Namespace-based routers are scheduled by the l3agent scheduler so we
        # don't backlog those
        if (binding_info_db.router_type_id ==
                self.get_namespace_router_type_id(context) or
            binding_info_db.hosting_device_id is not None or
                binding_info_db.router_id in self._backlogged_routers):
            LOG.debug('Aborting backlogging of router %s' %
                      binding_info_db.router_id)
            return
        LOG.info(_LI('Backlogging router %s for renewed scheduling attempt '
                     'later'), binding_info_db.router_id)
        self._backlogged_routers.add(binding_info_db.router_id)

    @lockutils.synchronized('routerbacklog', 'neutron-')
    def remove_router_from_backlog(self, router_id):
        # call unsynchronized version to actually remove from backlog
        self._remove_router_from_backlog(router_id)

    def _remove_router_from_backlog(self, router_id):
        if router_id in self._backlogged_routers:
            self._backlogged_routers.discard(router_id)
            LOG.info(_LI('Router %s removed from backlog'), router_id)

    @lockutils.synchronized('routerbacklog', 'neutron-')
    def _process_backlogged_routers(self):
        if self._refresh_router_backlog:
            self._sync_router_backlog()
        if not self._backlogged_routers:
            LOG.debug('No routers in backlog %s' % self._backlogged_routers)
            return
        e_context = n_context.get_admin_context()
        scheduled_routers = []
        LOG.info(_LI('Processing router (scheduling) backlog'))
        # try to reschedule
        for r_id in copy.deepcopy(self._backlogged_routers):
            r_hd_binding = self._get_router_binding_info(e_context, r_id)
            if r_hd_binding.hosting_device_id is not None:
                # this router was scheduled by some other process so it
                # requires no further processing
                self._backlogged_routers.remove(r_id)
                continue
            # since this function is already synchronized on the
            # router backlog, any backlog operations during scheduling
            # can be done unsynchronized
            self.schedule_router_on_hosting_device(e_context, r_hd_binding,
                                                   synchronized=False)
            e_context.session.expire(r_hd_binding)
            if r_hd_binding.hosting_device is not None:
                router = self.get_router(e_context, r_id)
                self.add_type_and_hosting_device_info(
                    e_context, router, r_hd_binding, schedule=False)
                # scheduling attempt succeeded
                scheduled_routers.append(router)
        # notify cfg agents so the scheduled routers are instantiated
        if scheduled_routers:
            for ni in self.get_notifiers(e_context, scheduled_routers):
                if ni['notifier']:
                    ni['notifier'].routers_updated(e_context, ni['routers'])

    def _setup_backlog_handling(self):
        LOG.debug('Activating periodic backlog processor')
        self._heartbeat = loopingcall.FixedIntervalLoopingCall(
            self._process_backlogged_routers)
        self._heartbeat.start(
            interval=cfg.CONF.routing.backlog_processing_interval)

    def _sync_router_backlog(self):
        LOG.info(_LI('Synchronizing router (scheduling) backlog'))
        context = n_context.get_admin_context()
        type_to_exclude = self.get_namespace_router_type_id(context)
        query = context.session.query(l3_models.RouterHostingDeviceBinding)
        query = query.options(joinedload('router'))
        query = query.filter(
            l3_models.RouterHostingDeviceBinding.router_type_id !=
            type_to_exclude,
            l3_models.RouterHostingDeviceBinding.hosting_device_id ==
            expr.null(),
            l3_models.RouterHostingDeviceBinding.auto_schedule == expr.true())
        self._backlogged_routers = set(binding.router_id for binding in query)
        self._refresh_router_backlog = False

    def _get_relevant_router_ids(self, context, router_ids=None,
                                 namespace_routers=False):
        query = context.session.query(
            l3_models.RouterHostingDeviceBinding.router_id)
        if namespace_routers:
            query = query.filter_by(
                router_type_id=self.get_namespace_router_type_id(context))
        else:
            query = query.filter(
                l3_models.RouterHostingDeviceBinding.router_type_id !=
                self.get_namespace_router_type_id(context))
        if router_ids:
            query = query.filter(
                l3_models.RouterHostingDeviceBinding.router_id.in_(router_ids))
        return [r_id[0] for r_id in query]

    def get_notifiers(self, context, routers):
        """Determines notifier to use for routers.

        @params: context - context
        @params: routers - list of router dict that includes router type id

        @returns: list of dicts - [{'notifier': notifier_object_1,
                                    'routers': list_1 of router dicts or
                                               router uuids},
                                   {'notifier': notifier_object_2,
                                    'routers': list_2 of router dicts or
                                               router uuids},
                                   ...]
        """
        res = {
            AGENT_TYPE_L3: {
                'notifier': self.agent_notifiers.get(AGENT_TYPE_L3),
                'routers': []},
            AGENT_TYPE_L3_CFG: {
                'notifier': self.agent_notifiers.get(AGENT_TYPE_L3_CFG),
                'routers': []}}
        for router in routers:
            if (router[routertype.TYPE_ATTR] ==
                    self.get_namespace_router_type_id(context)):
                res[AGENT_TYPE_L3]['routers'].append(router['id'])
            else:
                res[AGENT_TYPE_L3_CFG]['routers'].append(router)
        return [v for k, v in res.items() if v['routers']]

    def _ensure_router_role_compliant(self, router):
        router_role = router.pop(routerrole.ROUTER_ROLE_ATTR, None)
        if (router_role is not None and router_role not in
                cisco_constants.ALLOWED_ROUTER_ROLES):
            LOG.error(_LE('Unknown router role %s'), router_role or 'None')
            raise RouterCreateInternalError()
        return router_role

    def _ensure_create_routertype_compliant(self, context, router):
        router_type_name = router.pop(routertype.TYPE_ATTR,
                                      attributes.ATTR_NOT_SPECIFIED)
        if router_type_name is attributes.ATTR_NOT_SPECIFIED:
            router_type_name = cfg.CONF.routing.default_router_type
        namespace_router_type_id = self.get_namespace_router_type_id(context)
        router_type_db = self.get_routertype_db_by_id_name(context,
                                                           router_type_name)
        if (router_type_db.id != namespace_router_type_id and
            router_type_db.template.host_category == VM_CATEGORY and
                self._dev_mgr.mgmt_nw_id() is None):
            LOG.error(_LE('No OSN management network found which is required'
                          'for routertype with VM based hosting device'))
            raise RouterCreateInternalError()
        return self._make_routertype_dict(router_type_db)

    def _get_effective_and_normal_routertypes(self, context, hosting_info):
        if hosting_info:
            hosting_device = hosting_info.hosting_device
            normal = self._make_routertype_dict(hosting_info.router_type)
            if hosting_device:
                rt_info = self.get_routertypes(
                    context,
                    filters={'template_id': [hosting_device.template_id]})
                if (not rt_info or rt_info[0]['id'] ==
                        hosting_info.router_type_id):
                    effective = normal
                else:
                    # Neutron router relocated to hosting device of different
                    # type so effective router type is not its normal one
                    effective = rt_info[0]
            else:
                effective = normal
        else:
            # should not happen but just in case...
            LOG.debug('Could not determine effective router type since '
                      'router db record had no binding information')
            normal = None
            effective = None
        return effective, normal

    def _get_effective_slot_need(self, context, hosting_info):
        (eff_rt, norm_rt) = self._get_effective_and_normal_routertypes(
            context, hosting_info)
        return eff_rt['slot_need'] if eff_rt else 0

    def _update_routertype(self, context, r, binding_info_db):
        if routertype.TYPE_ATTR not in r:
            return
        router_type_name = r[routertype.TYPE_ATTR]
        if router_type_name is attributes.ATTR_NOT_SPECIFIED:
            router_type_name = cfg.CONF.routing.default_router_type
        router_type_id = self.get_routertype_by_id_name(context,
                                                        router_type_name)['id']
        if router_type_id == binding_info_db.router_type_id:
            return
        LOG.debug("Unscheduling router %s", binding_info_db.router_id)
        self.unschedule_router_from_hosting_device(context, binding_info_db)
        with context.session.begin(subtransactions=True):
            binding_info_db.hosting_device_id = None
            context.session.add(binding_info_db)
        # put in backlog for rescheduling

    def _extend_router_dict_routertype(self, router_res, router_db):
        adm_context = n_context.get_admin_context()
        (eff_rt, norm_rt) = self._get_effective_and_normal_routertypes(
            adm_context, router_db.hosting_info)
        # Show both current (temporary) and normal types if Neutron router is
        # relocated to a device of different type
        if eff_rt and norm_rt:
            router_type = (eff_rt['id'] + " (normal: " + norm_rt['id'] + ")"
                           if eff_rt['id'] != norm_rt['id'] else eff_rt['id'])
        else:
            router_type = None
        router_res[routertype.TYPE_ATTR] = router_type

    def _extend_router_dict_routerhostingdevice(self, router_res, router_db):
        router_res[routerhostingdevice.HOSTING_DEVICE_ATTR] = (
            (router_db.hosting_info or {}).get('hosting_device_id'))

    def _extend_router_dict_routerrole(self, router_res, router_db):
        router_res[routerrole.ROUTER_ROLE_ATTR] = (
            (router_db.hosting_info or {}).get('role'))

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    @property
    def _dev_mgr(self):
        return manager.NeutronManager.get_service_plugins().get(
            cisco_constants.DEVICE_MANAGER)

    def _get_router_binding_info(self, context, id, load_hd_info=True):
        query = context.session.query(l3_models.RouterHostingDeviceBinding)
        if load_hd_info:
            query = query.options(joinedload('hosting_device'))
        query = query.filter(l3_models.RouterHostingDeviceBinding.router_id ==
                             id)
        try:
            return query.one()
        except exc.NoResultFound:
            # This should not happen
            LOG.error(_LE('DB inconsistency: No type and hosting info '
                          'associated with router %s'), id)
            raise RouterBindingInfoError(router_id=id)
        except exc.MultipleResultsFound:
            # This should not happen either
            LOG.error(_LE('DB inconsistency: Multiple type and hosting info '
                          'associated with router %s'), id)
            raise RouterBindingInfoError(router_id=id)

    def _get_hosting_device_bindings(self, context, id, load_routers=False,
                                     load_hosting_device=False):
        query = context.session.query(l3_models.RouterHostingDeviceBinding)
        if load_routers:
            query = query.options(joinedload('router'))
        if load_hosting_device:
            query = query.options(joinedload('hosting_device'))
        query = query.filter(
            l3_models.RouterHostingDeviceBinding.hosting_device_id == id)
        return query.all()

    def add_type_and_hosting_device_info(self, context, router,
                                         binding_info_db=None, schedule=True):
        """Adds type and hosting device information to a router."""
        try:
            if binding_info_db is None:
                binding_info_db = self._get_router_binding_info(context,
                                                                router['id'])
        except RouterBindingInfoError:
            LOG.error(_LE('DB inconsistency: No hosting info associated with '
                          'router %s'), router['id'])
            router['hosting_device'] = None
            return
        router['router_type'] = {
            'id': binding_info_db.router_type.id,
            'name': binding_info_db.router_type.name,
            'cfg_agent_service_helper':
                binding_info_db.router_type.cfg_agent_service_helper,
            'cfg_agent_driver': binding_info_db.router_type.cfg_agent_driver}
        router[routerrole.ROUTER_ROLE_ATTR] = binding_info_db.role
        router['share_host'] = binding_info_db.share_hosting_device
        if binding_info_db.router_type_id == self.get_namespace_router_type_id(
                context):
            router['hosting_device'] = None
            return
        if binding_info_db.hosting_device is None:
            router['hosting_device'] = None
            if schedule is True and binding_info_db.auto_schedule is True:
                self.backlog_router(context, binding_info_db)
        else:
            router['hosting_device'] = self._dev_mgr.get_device_info_for_agent(
                context, binding_info_db.hosting_device)

    def _add_hosting_port_info(self, context, router, plugging_driver):
        """Adds hosting port information to router ports.

        We only populate hosting port info, i.e., reach here, if the
        router has been scheduled to a hosting device. Hence this
        a good place to allocate hosting ports to the router ports.
        """
        # cache of hosting port information: {mac_addr: {'name': port_name}}
        if router['external_gateway_info'] is not None:
            self._populate_hosting_info_for_port(
                context, router['id'], router['gw_port'],
                router['hosting_device'], plugging_driver)
        for itfc in router.get(l3_constants.INTERFACE_KEY, []):
            self._populate_hosting_info_for_port(
                context, router['id'], itfc, router['hosting_device'],
                plugging_driver)

    def _populate_hosting_info_for_port(self, context, router_id, port,
                                        hosting_device, plugging_driver):
        port_db = self._core_plugin._get_port(context, port['id'])
        h_info = port_db.hosting_info
        new_allocation = False
        if h_info is None:
            # The port does not yet have a hosting port so allocate one now
            h_info = self._allocate_hosting_port(
                context, router_id, port_db, hosting_device['id'],
                plugging_driver)
            if h_info is None:
                # This should not happen but just in case ...
                port['hosting_info'] = None
                return None, new_allocation
            else:
                new_allocation = True
        # Including MAC address of hosting port so L3CfgAgent can easily
        # determine which VM VIF to configure VLAN sub-interface on.
        port['hosting_info'] = {'hosting_port_id': h_info.hosting_port_id,
                                'hosting_mac': h_info.hosting_port.mac_address,
                                'hosting_port_name': h_info.hosting_port.name}
        # Finally add any driver specific information
        plugging_driver.extend_hosting_port_info(
            context, port_db, hosting_device, port['hosting_info'])
        return h_info, new_allocation

    def _allocate_hosting_port(self, context, router_id, port_db,
                               hosting_device_id, plugging_driver):
        net_data = self._core_plugin.get_network(
            context, port_db.network_id, [pr_net.NETWORK_TYPE])
        network_type = net_data.get(pr_net.NETWORK_TYPE)
        alloc = plugging_driver.allocate_hosting_port(
            context, router_id, port_db, network_type, hosting_device_id)
        if alloc is None:
            LOG.error(_LE('Failed to allocate hosting port for port %s'),
                      port_db['id'])
            return
        with context.session.begin(subtransactions=True):
            h_info_db = hd_models.HostedHostingPortBinding(
                logical_resource_id=router_id,
                logical_port_id=port_db['id'],
                network_type=network_type,
                hosting_port_id=alloc['allocated_port_id'],
                segmentation_id=alloc['allocated_vlan'])
            context.session.add(h_info_db)
            context.session.expire(port_db)
        # allocation succeeded so establish connectivity for logical port
        context.session.expire(h_info_db)
        plugging_driver.setup_logical_port_connectivity(context, port_db,
                                                        hosting_device_id)
        return h_info_db

    def _get_router_port_db_on_subnet(self, router_db, subnet):
        for router_port in router_db.attached_ports:
            if router_port.port['fixed_ips'][0]['subnet_id'] == subnet['id']:
                return router_port.port
        return None

    def _get_router_type_scheduler(self, context, routertype):
        """Returns the scheduler (instance) for a router type."""
        if routertype is None:
            return
        try:
            return self._router_schedulers[routertype]
        except KeyError:
            try:
                router_type = self.get_routertype_by_id_name(context,
                                                             routertype)
                self._router_schedulers[routertype] = (
                    importutils.import_object(router_type['scheduler']))
            except (ImportError, TypeError, n_exc.NeutronException):
                LOG.exception(_LE("Error loading scheduler for router type "
                                  "%s"), routertype)
            return self._router_schedulers.get(routertype)

    def _get_router_type_driver(self, context, routertype):
        """Returns the driver (instance) for a router type."""
        if routertype is None:
            return
        try:
            return self._router_drivers[routertype]
        except KeyError:
            try:
                router_type = self.get_routertype_by_id_name(context,
                                                             routertype)
                if (router_type['driver'] == "" or
                        router_type['driver'] is None):
                    self._router_drivers[routertype] = None
                else:
                    self._router_drivers[routertype] = (
                        importutils.import_object(router_type['driver']))
            except (ImportError, TypeError, n_exc.NeutronException):
                LOG.exception(_LE("Error loading drivers for router type "
                                  "%s"), routertype)
            return self._router_drivers.get(routertype)

    def _create_router_types_from_config(self):
        """To be called late during plugin initialization so that any router
        type defined in the config file is properly inserted in the DB.
           """
        # TODO(bobmel): Call this function from a better place inside the
        # device manager so that is independent of other service plugins.
        self._dev_mgr._setup_device_manager()
        rt_dict = config.get_specific_config('cisco_router_type')
        attr_info = routertype.RESOURCE_ATTRIBUTE_MAP[routertype.ROUTER_TYPES]
        adm_context = n_context.get_admin_context()

        for rt_uuid, kv_dict in rt_dict.items():
            try:
                # ensure hd_uuid is properly formatted
                rt_uuid = config.uuidify(rt_uuid)
                self.get_routertype(adm_context, rt_uuid)
                is_create = False
            except routertype.RouterTypeNotFound:
                is_create = True
            kv_dict['id'] = rt_uuid
            kv_dict['tenant_id'] = self._dev_mgr.l3_tenant_id()
            config.verify_resource_dict(kv_dict, True, attr_info)
            hd = {'routertype': kv_dict}
            try:
                if is_create:
                    self.create_routertype(adm_context, hd)
                else:
                    self.update_routertype(adm_context, kv_dict['id'], hd)
            except n_exc.NeutronException:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Invalid router type definition in '
                                  'configuration file for device = %s'),
                              rt_uuid)


# Need to override function in l3_db as implementation there does
# not take into account our HA implementation requirements
def _notify_routers_callback(resource, event, trigger, **kwargs):
    context = kwargs['context']
    router_ids = kwargs['router_ids']
    l3plugin = manager.NeutronManager.get_service_plugins().get(
        svc_constants.L3_ROUTER_NAT)
    if l3plugin and router_ids:
        l3plugin._notify_affected_routers(context, list(router_ids),
                                          'disassociate_floatingips')


def modify_subscribe():
    # unregister the function in l3_db as it does not do what we need
    registry.unsubscribe(l3_db._notify_routers_callback, resources.PORT,
                         events.AFTER_DELETE)
    # register our own version
    registry.subscribe(
        _notify_routers_callback, resources.PORT, events.AFTER_DELETE)


modify_subscribe()
