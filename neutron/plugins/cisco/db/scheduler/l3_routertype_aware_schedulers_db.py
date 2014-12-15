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
import sqlalchemy as sql

from neutron.common import topics
from neutron.db import agents_db
from neutron.db import l3_agentschedulers_db as l3agentsched_db
from neutron.db import models_v2
from neutron.db import portbindings_db as p_binding
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.common import cisco_constants as c_constants
from neutron.plugins.cisco.db.device_manager import hd_models
from neutron.plugins.cisco.db.l3 import l3_models

LOG = logging.getLogger(__name__)


ROUTER_TYPE_AWARE_SCHEDULER_OPTS = [
    cfg.StrOpt('router_type_aware_scheduler_driver',
               default='neutron.plugins.cisco.l3.scheduler.'
                       'l3_routertype_aware_agent_scheduler.'
                       'L3RouterTypeAwareScheduler',
               help=_('Driver to use for router type-aware scheduling of '
                      'router to a default L3 agent')),
]

cfg.CONF.register_opts(ROUTER_TYPE_AWARE_SCHEDULER_OPTS)


class L3RouterTypeAwareSchedulerDbMixin(
        l3agentsched_db.L3AgentSchedulerDbMixin):
    """Mixin class to add L3 router type-aware scheduler capability.

    This class can schedule Neutron routers to hosting devices
    and to L3 agents on network nodes.
    """

    def list_active_sync_routers_on_hosting_devices(self, context, host,
                                                    router_ids=None,
                                                    hosting_device_ids=None):
        agent = self._get_agent_by_type_and_host(
            context, c_constants.AGENT_TYPE_CFG, host)
        if not agent.admin_state_up:
            return []
        query = context.session.query(
            l3_models.RouterHostingDeviceBinding.router_id)
        query = query.join(hd_models.HostingDevice)
        query = query.filter(hd_models.HostingDevice.cfg_agent_id == agent.id)
        if router_ids:
            if len(router_ids) == 1:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.router_id ==
                    router_ids[0])
            else:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.router_id.in_(
                        router_ids))
        if hosting_device_ids:
            if len(hosting_device_ids) == 1:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.hosting_device_id ==
                    hosting_device_ids[0])
            elif len(hosting_device_ids) > 1:
                query = query.filter(
                    l3_models.RouterHostingDeviceBinding.hosting_device_id.in_(
                        hosting_device_ids))
        router_ids = [item[0] for item in query]
        if router_ids:
            return self.get_sync_data_ext(context, router_ids=router_ids,
                                          active=True)
        else:
            return []

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
        # TODO(pcm) Don't think we need if clause, as it'll work w/empty list
        if router_ids:
            return self.get_sync_data_ext(context, router_ids=router_ids,
                                          active=True)
        else:
            return []

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
