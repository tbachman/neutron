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

from oslo.config import cfg
from sqlalchemy.orm import exc
from sqlalchemy import sql

from neutron.common import topics
from neutron.db import agents_db
from neutron.db import l3_agentschedulers_db
from neutron.db import models_v2
from neutron.db import portbindings_db as p_binding
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.common import cisco_constants as c_consts
from neutron.plugins.cisco.db.device_manager import hd_models
from neutron.plugins.cisco.db.l3 import l3_models
from neutron.plugins.cisco.extensions import routertypeawarescheduler

LOG = logging.getLogger(__name__)


ROUTER_TYPE_AWARE_SCHEDULER_OPTS = [
    cfg.StrOpt('router_type_aware_scheduler_driver',
               default='neutron.plugins.cisco.l3.scheduler.'
                       'l3_routertype_aware_agent_scheduler.'
                       'L3RouterTypeAwareScheduler',
               help=_('Driver to use for router type-aware scheduling of '
                      'router to a default L3 agent')),
]

cfg.CONF.register_opts(ROUTER_TYPE_AWARE_SCHEDULER_OPTS, "routing")


class L3RouterTypeAwareSchedulerDbMixin(
        l3_agentschedulers_db.L3AgentSchedulerDbMixin):
    """Mixin class to add L3 router type-aware scheduler capability.

    This class can schedule Neutron routers to hosting devices
    and to L3 agents on network nodes.
    """
    def validate_hosting_device_router_combination(self, context, binding_info,
                                                   hosting_device_id):
        #TODO(bobmel): Perform proper hosting device validation
        if False:
            raise routertypeawarescheduler.RouterHostingDeviceMismatch(
                hosting_device_id=hosting_device_id)

    def add_router_to_hosting_device(self, context, hosting_device_id,
                                     router_id):
        """Add a (non-hosted) router to a hosting device."""
        e_context = context.elevated()
        r_hd_binding = self._get_router_binding_info(e_context, router_id)
        if r_hd_binding.hosting_device_id:
            raise routertypeawarescheduler.RouterHostedByHostingDevice(
                router_id=router_id, hosting_device_id=hosting_device_id)
        self.validate_hosting_device_router_combination(context, r_hd_binding,
                                                        hosting_device_id)
        result = self.schedule_router_on_hosting_device(
            e_context, r_hd_binding, hosting_device_id)
        if result:
            self._ensure_routertype(context, r_hd_binding)
            router = self.get_router(context, router_id)
            self._add_type_and_hosting_device_info(
                e_context, router, binding_info=r_hd_binding, schedule=False)
            l3_cfg_notifier = self.agent_notifiers.get(
                c_consts.AGENT_TYPE_L3_CFG)
            if l3_cfg_notifier:
                l3_cfg_notifier.router_added_to_hosting_device(context, router)
        else:
            raise routertypeawarescheduler.RouterSchedulingFailed(
                router_id=router_id, hosting_device_id=hosting_device_id)

    def _ensure_routertype(self, context, binding_info):
        """Ensures that the routertype of a router corresponds to the
        hosting device hosting the router.
        """
        template_id = binding_info.hosting_device.template_id
        rt_ids = self.get_routertypes(context, fields=['id'],
                                      filters={'template_id': [template_id]})
        if rt_ids:
            with context.session.begin(subtransactions=True):
                binding_info.router_type_id = rt_ids[0]['id']
                context.session.update(binding_info)

    def remove_router_from_hosting_device(self, context, hosting_device_id,
                                          router_id):
        """Remove the router from hosting device.

        After removal, the router will be non-hosted until there is update
        which leads to re-schedule or be added to another hosting device
        manually.
        """
        e_context = context.elevated()
        r_hd_binding = self._get_router_binding_info(e_context, router_id)
        if r_hd_binding.hosting_device_id != hosting_device_id:
            raise routertypeawarescheduler.RouterNotHostedByHostingDevice(
                router_id=router_id, hosting_device_id=hosting_device_id)
        router = self.get_router(context, router_id)
        self._add_type_and_hosting_device_info(
            e_context, router, binding_info=r_hd_binding, schedule=False)
        # conditionally remove router from backlog ensure it does not get
        # scheduled automatically
        self.remove_router_from_backlog(id)
        l3_cfg_notifier = self.agent_notifiers.get(c_consts.AGENT_TYPE_L3_CFG)
        if l3_cfg_notifier:
            l3_cfg_notifier.router_removed_from_hosting_device(context, router)
        LOG.debug("Unscheduling router %s", r_hd_binding.router_id)
        self.unschedule_router_from_hosting_device(context, r_hd_binding)
        # now unbind the router from the hosting device
        with context.session.begin(subtransactions=True):
            r_hd_binding.hosting_device = None

    def list_routers_on_hosting_device(self, context, hosting_device_id):
        query = context.session.query(
            l3_models.RouterHostingDeviceBinding.router_id)
        query = query.filter(
            l3_models.RouterHostingDeviceBinding.hosting_device_id ==
            hosting_device_id)
        router_ids = [item[0] for item in query]
        return {'routers': self.get_sync_data_ext(context,
                                                  router_ids=router_ids)}

    def list_hosting_devices_hosting_router(self, context, router_id):
        query = context.session.query(
            l3_models.RouterHostingDeviceBinding.hosting_device_id)
        query = query.filter(l3_models.RouterHostingDeviceBinding.router_id ==
                             router_id)
        hd_ids = [item[0] for item in query]
        if hd_ids:
            return {'hosting_devices':
                    self._dev_mgr.get_hosting_devices(context,
                                                      filters={'id': hd_ids})}
        else:
            return {'hosting_devices': []}

    def list_active_sync_routers_on_hosting_devices(self, context, host,
                                                    router_ids=None,
                                                    hosting_device_ids=None):
        agent = self._get_agent_by_type_and_host(context,
                                                 c_consts.AGENT_TYPE_CFG, host)
        if not agent.admin_state_up:
            return []
        query = context.session.query(
            l3_models.RouterHostingDeviceBinding.router_id)
        query = query.join(hd_models.HostingDevice)
        query = query.filter(hd_models.HostingDevice.cfg_agent_id == agent.id)
        if router_ids:
            query = query.filter(
                l3_models.RouterHostingDeviceBinding.router_id.in_(router_ids))
        if hosting_device_ids:
            query = query.filter(
                l3_models.RouterHostingDeviceBinding.hosting_device_id.in_(
                    hosting_device_ids))
        router_ids = [item[0] for item in query]
        return self.get_sync_data_ext(context, router_ids=router_ids,
                                      active=True)

    def get_active_routers_for_host(self, context, host):
        query = context.session.query(
            l3_models.RouterHostingDeviceBinding.router_id)
        query = query.join(
            models_v2.Port,
            l3_models.RouterHostingDeviceBinding.hosting_device_id ==
            models_v2.Port.device_id)
        query = query.join(p_binding.PortBindingPort)
        query = query.filter(p_binding.PortBindingPort.host == host)
        query = query.filter(models_v2.Port.name == 'mgmt')
        router_ids = [item[0] for item in query]
        return self.get_sync_data_ext(context, router_ids=router_ids,
                                      active=True)

    def _agent_state_filter(self, check_active, last_heartbeat):
        """Filters only active agents, if requested."""
        if not check_active:
            return True
        return not agents_db.AgentDbMixin.is_agent_down(last_heartbeat)

    def get_hosts_for_routers(self, context, routers, admin_state_up=None,
                              check_active=False):
        query = context.session.query(p_binding.PortBindingPort.host,
                                      agents_db.Agent)
        query = query.join(
            models_v2.Port,
            models_v2.Port.id == p_binding.PortBindingPort.port_id)
        query = query.join(
            l3_models.RouterHostingDeviceBinding,
            l3_models.RouterHostingDeviceBinding.hosting_device_id ==
            models_v2.Port.device_id)
        query = query.join(
            agents_db.Agent,
            agents_db.Agent.host == p_binding.PortBindingPort.host)
        query = query.filter(sql.and_(
            agents_db.Agent.topic == topics.L3_AGENT,
            l3_models.RouterHostingDeviceBinding.router_id.in_(routers)))
        if admin_state_up is not None:
            query = query.filter(
                agents_db.Agent.admin_state_up == admin_state_up)
        hosts = [row.host for row in query if
                 self._agent_state_filter(check_active,
                                          row.heartbeat_timestamp)]
        return hosts
