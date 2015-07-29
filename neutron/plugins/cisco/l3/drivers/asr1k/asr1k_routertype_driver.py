# Copyright 2015 Cisco Systems, Inc.  All rights reserved.
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

from oslo_log import log as logging

from neutron.common import constants as common_constants
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.db.l3 import ha_db
from neutron.plugins.cisco.db.l3 import l3_models
from neutron.plugins.cisco.extensions import routerhostingdevice
from neutron.plugins.cisco.extensions import routertype
from neutron.plugins.cisco.l3 import drivers
from neutron.plugins.common import constants

LOG = logging.getLogger(__name__)

import pprint


class ASR1kL3RouterDriver(drivers.L3RouterBaseDriver):

    def create_router_precommit(self, context, router_context):
        pass

    def create_router_postcommit(self, context, router_context):
        """
        After a router has been successfully created, we confirm that
        a global router exists.  The global router serves as a placeholder
        for the global vrf that handles external network connectivity.

        If the created router has an external gateway configured, we perform
        a conditional port-add to the global router.
        """
        self._ensure_logical_global_router_exists(context)
        current = router_context.current
        LOG.debug("XXXXXXXXXX current: %s" % current)
        if current['gw_port_id']:
            ext_nw_id = current['external_gateway_info']['network_id']
            self._conditionally_add_logical_global_ext_nw_port(context,
                                                               ext_nw_id)
        return

    def update_router_precommit(self, context, router_context):
        pass

    def update_router_postcommit(self, context, router_context,
                                 old_ext_nw_id=None, new_ext_nw_id=None):
        # Whenever a gateway is added to, or removed from, a router hosted on
        # a hosting device, we must ensure that a global router is running
        # (for add operation) or not running (for remove operation) on that
        # hosting device.
        # rpdb.set_trace()
        LOG.debug("++++ update_router_postcommit, context = %s",
                  pprint.pformat(context))
        LOG.debug("++++ update_router_postcommit, router_context = %s",
                  pprint.pformat(router_context))
        LOG.debug("++++ update_router_postcommit, old_ext_nw_id = %s",
                  pprint.pformat(old_ext_nw_id))
        LOG.debug("++++ update_router_postcommit, new_ext_nw_id = %s",
                  pprint.pformat(new_ext_nw_id))

        self._ensure_logical_global_router_exists(context)
        logical_global_router = self._get_logical_global_router(context)
        current = router_context.current

        if old_ext_nw_id != new_ext_nw_id:
            if old_ext_nw_id is not None:
                self._conditionally_remove_logical_global_ext_nw_port(context,
                                                                old_ext_nw_id)
            if new_ext_nw_id is not None:
                self._conditionally_add_logical_global_ext_nw_port(context,
                                                                new_ext_nw_id)

        hd_id = current[routerhostingdevice.HOSTING_DEVICE_ATTR]
        if hd_id is None:
            return

        if old_ext_nw_id != new_ext_nw_id:
            if old_ext_nw_id is not None:
                self._conditionally_remove_global_router_ext_nw(context,
                                                                hd_id,
                                                                old_ext_nw_id)
            if new_ext_nw_id is not None:
                self._conditionally_add_global_router(context,
                                                      hd_id,
                                                      current,
                                                      logical_global_router.id)

        # if current['gw_port_id']:
        #     self._conditionally_add_global_router(context, hd_id, current,
        #                                           logical_global_router.id)
        # else:
            # self._conditionally_remove_global_router(context, hd_id, True)

            # if router is hosted and router has gateway port:
            #    if global router does not exist for hosting device of router:
            #        create global router on that hosting device
            #    if global router doesn't have port on router's external
            #    network:
            #        create port on external network for global router

    def delete_router_precommit(self, context, router_context):
        pass

    def delete_router_postcommit(self, context, router_context,
                                 old_ext_nw_id=None):
        self._ensure_logical_global_router_exists(context)
        self._conditionally_remove_logical_global_ext_nw_port(context,
                                                              old_ext_nw_id)
        self._conditionally_remove_global_router_ext_nw(context,
                                                        None,
                                                        old_ext_nw_id)
        return

    def schedule_router_precommit(self, context, router_context):
        pass

    def _global_router_name(self, hosting_device_id):
        return '%s-%s' % (
            cisco_constants.ROLE_PREFIX,
            hosting_device_id[-cisco_constants.ROLE_ID_LEN:])

    def _global_router_index_from_hosting_device_id(self, hosting_device_id):
        return int(hosting_device_id[-cisco_constants.HA_PRIORITY_ID_LEN:])

    def _get_logical_router_with_ext_nw_count(self, context, ext_nw_id):
        qry = context.session.query(l3_db.Router,
                                    models_v2.Port,
                                    l3_models.RouterHostingDeviceBinding)
        qry = qry.filter(models_v2.Port.network_id == ext_nw_id)
        qry = qry.filter(l3_db.Router.gw_port_id == models_v2.Port.id)
        qry = qry.filter(l3_models.RouterHostingDeviceBinding.role ==
                         cisco_constants.ROUTER_ROLE_LOGICAL)
        qry = qry.filter(l3_models.RouterHostingDeviceBinding.router_id ==
                         l3_db.Router.id)
        return qry.count()

    def _get_logical_global_router(self, context):
        qry = context.session.query(l3_models.RouterHostingDeviceBinding,
                                    l3_db.Router)
        qry = qry.filter(l3_models.RouterHostingDeviceBinding.role ==
                         cisco_constants.ROUTER_ROLE_LOGICAL_GLOBAL)
        qry = qry.filter(l3_models.RouterHostingDeviceBinding.router_id ==
                         l3_db.Router.id)
        rhdb_db, router_db = qry.first()
        # LOG.debug("ZZZZZZZZZZ rhdb_db: %s, router_db: %s, qry.count(): %s" %
        #          (pprint.pformat(rhdb_db),
        #          pprint.pformat(router_db),
        #          qry.count()))
        return router_db

    def _get_global_routers(self, context):
        qry = context.session.query(l3_models.RouterHostingDeviceBinding,
                                    l3_db.Router)
        qry = qry.filter(l3_models.RouterHostingDeviceBinding.role ==
                         cisco_constants.ROUTER_ROLE_LOGICAL_GLOBAL)
        qry = qry.filter(l3_models.RouterHostingDeviceBinding.router_id ==
                         l3_db.Router.id)
        rhdb_db, router_db = qry.first()
        # LOG.debug("ZZZZZZZZZZ rhdb_db: %s, router_db: %s, qry.count(): %s" %
        #          (pprint.pformat(rhdb_db),
        #          pprint.pformat(router_db),
        #          qry.count()))
        return router_db

    def _get_global_router_ext_nw_intf(self,
                                       context,
                                       ext_nw_id,
                                       router_id):

        qry = context.session.query(models_v2.Port)
        qry = qry.filter(models_v2.Port.device_id == router_id)
        qry = qry.filter(models_v2.Port.network_id == ext_nw_id)
        return qry.first()

    def _ensure_logical_global_router_exists(self, context):
        qry = context.session.query(l3_models.RouterHostingDeviceBinding)
        qry = qry.filter(l3_models.RouterHostingDeviceBinding.role ==
                         cisco_constants.ROUTER_ROLE_LOGICAL_GLOBAL)
        if qry.count() < 1:
            r_spec = {'router': {
                # global routers are not tied to any tenant
                'tenant_id': '',
                'name': 'LOGICAL_GLOBAL_ROUTER_XX',
                'admin_state_up': True, }}

            r = self._l3_plugin.do_create_router(context,
                      r_spec,
                      self._l3_plugin.get_hardware_router_type_id(context),
                      False,
                      True,
                      None,
                      cisco_constants.ROUTER_ROLE_LOGICAL_GLOBAL)

            self._l3_plugin.add_type_and_hosting_device_info(
                context.elevated(), r)

            r_ha_s = ha_db.RouterHASetting(router_id=r['id'],
                                       ha_type='HSRP',
                                       redundancy_level=2,
                                       priority=ha_db.DEFAULT_MASTER_PRIORITY,
                                       probe_connectivity=False,
                                       probe_target=None,
                                       probe_interval=5)

            context.session.add(r_ha_s)

    def _add_global_router_ext_nw_intf(self, context, ext_nw_id, router_id):
        global_port = self._l3_plugin._create_hidden_port(context,
                                                          ext_nw_id,
                                                          router_id)
        router_port = \
            l3_db.RouterPort(router_id=router_id,
                           port_id=global_port['id'],
                           port_type=common_constants.DEVICE_OWNER_ROUTER_INTF)
        context.session.add(router_port)
        return global_port

    def _conditionally_add_logical_global_ext_nw_port(self,
                                                      context,
                                                      ext_nw_id):
        router = self._get_logical_global_router(context)
        ext_port = self._get_global_router_ext_nw_intf(context,
                                                       ext_nw_id,
                                                       router.id)

        LOG.debug("QQQQQQ condition add logical global ext nw port:"
                  " router_id: %s,"
                  " ext_port: %s" % (router.id, ext_port))

        if ext_port is None:
            new_ext_port = self._add_global_router_ext_nw_intf(context,
                                                               ext_nw_id,
                                                               router.id)
            ha_settings = \
                self._l3_plugin._get_ha_settings_by_router_id(context,
                                                              router.id)
            self._l3_plugin._create_ha_group(context,
                                             router.id,
                                             new_ext_port,
                                             ha_settings)

    def _conditionally_remove_logical_global_ext_nw_port(self,
                                                         context,
                                                         ext_nw_id):
        if self._get_logical_router_with_ext_nw_count(context, ext_nw_id) < 1:
            router = self._get_logical_global_router(context)
            ext_port = self._get_global_router_ext_nw_intf(context,
                                                           ext_nw_id,
                                                           router.id)
            LOG.debug("QQQQQQ condition remove logical global ext nw port:"
                      "router_id: %s, ext_port: %s" % (router.id, ext_port))

            if (ext_port is not None):
                self._l3_plugin._delete_ha_group(context, ext_port.id)
                self._l3_plugin._core_plugin.delete_port(context,
                                                         ext_port.id,
                                                         l3_port_check=False)
            else:
                LOG.debug("QQQQQQ ext_port was None, "
                          "skipping delete_ha_group and delete_port")

    def _conditionally_add_global_router(self, context, hosting_device_id,
                                         router, logical_global_router_id):
        # Ensure that a global router exists on hosting_device_id
        filters = {
            routerhostingdevice.HOSTING_DEVICE_ATTR: [hosting_device_id],
            'role': [cisco_constants.ROUTER_ROLE_GLOBAL]}
        global_routers = self._l3_plugin.get_routers(context,
                                                     filters=filters)
        ext_nw = router[l3.EXTERNAL_GW_INFO]['network_id']
        if not global_routers:
            # must create global router on hosting device
            r_spec = {'router': {
                # global routers are not tied to any tenant
                'tenant_id': '',
                'name': self._global_router_name(hosting_device_id),
                'admin_state_up': True}}
            # l3.EXTERNAL_GW_INFO: {'network_id': ext_nw}}}
            r = self._l3_plugin.do_create_router(
                context, r_spec, router[routertype.TYPE_ATTR], False, True,
                hosting_device_id, cisco_constants.ROUTER_ROLE_GLOBAL)
            self._l3_plugin.add_type_and_hosting_device_info(
                context.elevated(), r)
            global_router = r

            priority = ha_db.DEFAULT_MASTER_PRIORITY
            global_router_idx = \
                self._global_router_index_from_hosting_device_id(
                                                            hosting_device_id)
            priority += global_router_idx * ha_db.PRIORITY_INCREASE_STEP
            rrb_db = \
                ha_db.RouterRedundancyBinding(
                            redundancy_router_id=global_router['id'],
                            priority=priority,
                            user_router_id=logical_global_router_id)

            context.session.add(rrb_db)
        else:
            global_router = global_routers[0]
            self._l3_plugin.add_type_and_hosting_device_info(
                context.elevated(), global_router)

        # Add an ext_nw interface to global_router if none exist
        ext_port = self._get_global_router_ext_nw_intf(context,
                                                       ext_nw,
                                                       global_router['id'])
        tenant_ext_nw_count = \
            self._get_logical_router_with_ext_nw_count(context,
                                                       ext_nw)
        LOG.debug("ext_port: %(ext_port)s,"
                  " tenant_enc: %(tenant_ext_nw_count)s" %
                  {'ext_port': ext_port,
                   'tenant_ext_nw_count': tenant_ext_nw_count})

        if ext_port is None and tenant_ext_nw_count > 0:
            LOG.debug("TRACE global_router: %s" %
                      global_router)

            self._add_global_router_ext_nw_intf(context,
                                                ext_nw,
                                                global_router['id'])

            for ni in self._l3_plugin.get_notifiers(context, [global_router]):
                if ni['notifier']:
                    ni['notifier'].routers_updated(context, ni['routers'])

    def schedule_router_postcommit(self, context, router_context):
        # When the hosting device hosts a Neutron router with external
        # connectivity, a "global" router (modeled as a Neutron router) must
        # also run on the hosting device (outside of any VRF) to enable the
        # connectivity.
        current = router_context.current
        LOG.debug("schedule_router_post_commit: %s" % current)
        hd_id = current[routerhostingdevice.HOSTING_DEVICE_ATTR]
        if current['gw_port_id'] and hd_id is not None:
            self._ensure_logical_global_router_exists(context)
            logical_global_router = self._get_logical_global_router(context)

            self._conditionally_add_global_router(context, hd_id, current,
                                                  logical_global_router.id)

    def unschedule_router_precommit(self, context, router_context):
        pass

    def _conditionally_remove_global_router(self, context, hosting_device_id,
                                            update_operation=False):
        filters = {
            routerhostingdevice.HOSTING_DEVICE_ATTR: [hosting_device_id]}
        invert_filters = {'gw_port_id': [None]}
        num_rtrs = self._l3_plugin.get_routers_count_extended(
            context, filters=filters, invert_filters=invert_filters)
        if ((num_rtrs <= 2 and update_operation is False) or
                (num_rtrs <= 1 and update_operation is True)):
            # there are one or two routers left and one of them may be a
            # global router, which can then be deleted
            filters['role'] = [cisco_constants.ROUTER_ROLE_GLOBAL]
            global_routers = self._l3_plugin.get_routers(
                context, filters=filters)
            if global_routers:
                # can remove the global router as it will no longer be used
                self._l3_plugin.delete_router(
                    context, global_routers[0]['id'], unschedule=False)

    def _conditionally_remove_global_router_ext_nw(self,
                                                   context,
                                                   hosting_device_id,
                                                   ext_nw_id):
        if hosting_device_id:
            filters = {
                routerhostingdevice.HOSTING_DEVICE_ATTR: [hosting_device_id],
                'role': [cisco_constants.ROUTER_ROLE_GLOBAL]}
        else:
            filters = {'role': [cisco_constants.ROUTER_ROLE_GLOBAL]}

        global_routers = self._l3_plugin.get_routers(context,
                                                     filters=filters)

        ext_nw_intf_count = \
            self._get_logical_router_with_ext_nw_count(context,
                                                       ext_nw_id)
        LOG.debug("ext_nw_intf_count: %s" % ext_nw_intf_count)
        if ext_nw_intf_count < 1:
            LOG.debug("global routers: %s" % global_routers)
            for global_router in global_routers:
                # global_router = global_routers[0]

                global_ext_nw_intf = \
                    self._get_global_router_ext_nw_intf(context,
                                                        ext_nw_id,
                                                        global_router['id'])
                LOG.debug("g_ext_nw_intf: %s" % global_ext_nw_intf)
                if global_ext_nw_intf:
                    self._l3_plugin._core_plugin.delete_port(context,
                                                        global_ext_nw_intf.id,
                                                        l3_port_check=False)
                    self._l3_plugin.add_type_and_hosting_device_info(
                        context.elevated(), global_router)
                    for ni in self._l3_plugin.get_notifiers(context,
                                                            [global_router]):
                        if ni['notifier']:
                            ni['notifier'].routers_updated(context,
                                                           ni['routers'])

    def unschedule_router_postcommit(self, context, router_context):
        # When there is no longer any router with external gateway hosted on
        # a hosting device, the global router on that hosting device can also
        # be removed.
        current = router_context.current
        hd_id = current[routerhostingdevice.HOSTING_DEVICE_ATTR]
        if current['gw_port_id'] and hd_id is not None:
            pass
            # self._conditionally_remove_global_router(context, hd_id)

    def add_router_interface_precommit(self, context, r_port_context):
        pass

    def add_router_interface_postcommit(self, context, r_port_context):
        pass

    def remove_router_interface_precommit(self, context, r_port_context):
        pass

    def remove_router_interface_postcommit(self, context, r_port_context):
        pass

    def update_floatingip_precommit(self, context, fip_context):
        pass

    def update_floatingip_postcommit(self, context, fip_context):
        pass

    def delete_floatingip_precommit(self, context, fip_context):
        pass

    def delete_floatingip_postcommit(self, context, fip_context):
        pass

    @property
    def _l3_plugin(self):
        return manager.NeutronManager.get_service_plugins().get(
            constants.L3_ROUTER_NAT)
