# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
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

import random

from sqlalchemy.orm import exc
from sqlalchemy.sql import exists

from quantum.common import constants
from quantum.db import models_v2
from quantum.db import agents_db
from quantum.db import agentschedulers_db
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class ChanceScheduler(object):
    """Allocate a DHCP agent for a network in a random way.
    More sophisticated scheduler (similar to filter scheduler in nova?)
    can be introduced later."""

    def __init__(self):
        self.agents = []

    def choose_agent(self, plugin, context, active_agents):
        """Choose agent using a round-robin scheme.""" 
        rebuild_agt_list = False
        # Check if the list of active agents has changed
        if len(self.agents) == len(active_agents):
            for agt in active_agents:
                if agt['id'] not in self.agents:
                    rebuild_agt_list = True
                    break;
        else:
            rebuild_agt_list = True
        # Rebuild the agent list if needed
        if rebuild_agt_list:
            self.agents = []
            for agt in active_agents:
                self.agents.append(agt['id'])
            LOG.debug(_('Agent list %s'), self.agents)
        # Choose the first agent id and
        # move it to the end of the list
        chosen_agt_id = self.agents[0]
        new_list = self.agents[1:]
        new_list.append(chosen_agt_id)
        self.agents = new_list
        # Return the agent instance corr to the chosen id
        chosen_agent = [agt for agt in active_agents 
                        if agt['id'] == chosen_agt_id][0]
        LOG.debug(_('Chose agt on node %s'), chosen_agent['host'])
        return chosen_agent    

    def schedule(self, plugin, context, network):
        """Schedule the network to an active DHCP agent if there
        is no active DHCP agent hosting it.
        """
        #TODO(gongysh) don't schedule the networks with only
        # subnets whose enable_dhcp is false
        with context.session.begin(subtransactions=True):
            dhcp_agents = plugin.get_dhcp_agents_hosting_networks(
                context, [network['id']], active=True)
            if dhcp_agents:
                LOG.debug(_('Network %s is hosted already'),
                          network['id'])
                return
            enabled_dhcp_agents = plugin.get_agents_db(
                context, filters={
                    'agent_type': [constants.AGENT_TYPE_DHCP],
                    'admin_state_up': [True]})
            if not enabled_dhcp_agents:
                LOG.warn(_('No enabled DHCP agents'))
                return
            active_dhcp_agents = [enabled_dhcp_agent for enabled_dhcp_agent in
                                  enabled_dhcp_agents if not
                                  agents_db.AgentDbMixin.is_agent_down(
                                  enabled_dhcp_agent['heartbeat_timestamp'])]
            if not active_dhcp_agents:
                LOG.warn(_('No active DHCP agents'))
                return
            chosen_agent = self.choose_agent(plugin, context,
                                             active_dhcp_agents)
            binding = agentschedulers_db.NetworkDhcpAgentBinding()
            binding.dhcp_agent = chosen_agent
            binding.network_id = network['id']
            context.session.add(binding)
            LOG.debug(_('Network %(network_id)s is scheduled to be hosted by '
                        'DHCP agent %(agent_id)s'),
                      {'network_id': network['id'],
                       'agent_id': chosen_agent['id']})
        return chosen_agent

    def auto_schedule_networks(self, plugin, context, host):
        """Schedule non-hosted networks to the DHCP agent on
        the specified host."""
        with context.session.begin(subtransactions=True):
            query = context.session.query(agents_db.Agent)
            query = query.filter(agents_db.Agent.agent_type ==
                                 constants.AGENT_TYPE_DHCP,
                                 agents_db.Agent.host == host,
                                 agents_db.Agent.admin_state_up == True)
            try:
                dhcp_agent = query.one()
            except (exc.MultipleResultsFound, exc.NoResultFound):
                LOG.warn(_('No enabled DHCP agent on host %s'),
                         host)
                return False
            if agents_db.AgentDbMixin.is_agent_down(
                dhcp_agent.heartbeat_timestamp):
                LOG.warn(_('DHCP agent %s is not active'), dhcp_agent.id)
            #TODO(gongysh) consider the disabled agent's network
            net_stmt = ~exists().where(
                models_v2.Network.id ==
                agentschedulers_db.NetworkDhcpAgentBinding.network_id)
            net_ids = context.session.query(
                models_v2.Network.id).filter(net_stmt).all()
            if not net_ids:
                LOG.debug(_('No non-hosted networks'))
                return False
            for net_id in net_ids:
                binding = agentschedulers_db.NetworkDhcpAgentBinding()
                binding.dhcp_agent = dhcp_agent
                binding.network_id = net_id[0]
                context.session.add(binding)
        return True
