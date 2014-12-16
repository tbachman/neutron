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

from sqlalchemy import sql

from neutron.common import constants
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.db.l3 import l3_models
from neutron.scheduler import l3_agent_scheduler

LOG = logging.getLogger(__name__)


AGENT_TYPE_L3 = constants.AGENT_TYPE_L3


class L3RouterTypeAwareScheduler(l3_agent_scheduler.L3Scheduler):
    """A router type aware l3 agent scheduler for Cisco router service plugin.

    It schedules Neutron routers with router type representing network
    namespace based routers to l3 agents.
    """

    def get_unscheduled_routers(self, context, plugin):
        """Get routers with no agent binding."""
        # TODO(gongysh) consider the disabled agent's router
        no_agent_binding = ~sql.exists().where(
            l3_db.Router.id ==
            l3_agentschedulers_db.RouterL3AgentBinding.router_id)
        # Modified to only include routers of network namespace type
        ns_routertype_id = plugin.get_namespace_router_type_id(context)
        query = context.session.query(l3_db.Router.id)
        query = query.join(l3_models.RouterHostingDeviceBinding)
        query = query.filter(
            l3_models.RouterHostingDeviceBinding.router_type_id ==
            ns_routertype_id, no_agent_binding)
        unscheduled_router_ids = [router_id_[0] for router_id_ in query]
        if unscheduled_router_ids:
            return plugin.get_routers(
                context, filters={'id': unscheduled_router_ids})
        return []

    def schedule(self, plugin, context, router, candidates=None):
        # Only network namespace based routers should be scheduled here
        ns_routertype_id = plugin.get_namespace_router_type_id(context)
        if router['router_type']['id'] == ns_routertype_id:
            # Do the traditional Neutron router scheduling
            return plugin.l3agent_scheduler.schedule(plugin, context,
                                                     router['id'], candidates)
        else:
            return

    def _choose_router_agent(self, plugin, context, candidates):
        return plugin.l3agent_scheduler._choose_router_agent(plugin, context,
                                                             candidates)

    def _choose_router_agents_for_ha(self, plugin, context, candidates):
        return plugin.l3agent_scheduler._choose_router_agents_for_ha(
            plugin, context, candidates)
