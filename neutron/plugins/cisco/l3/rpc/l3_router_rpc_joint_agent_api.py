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
#

import random

from oslo import messaging

from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.common import cisco_constants as c_constants
from neutron.plugins.cisco.extensions import ciscocfgagentscheduler
from neutron.plugins.common import constants as svc_constants

LOG = logging.getLogger(__name__)


L3AGENT_SCHED = constants.L3_AGENT_SCHEDULER_EXT_ALIAS
CFGAGENT_SCHED = ciscocfgagentscheduler.CFG_AGENT_SCHEDULER_ALIAS


class L3RouterJointAgentNotifyAPI(object):
    """API for plugin to notify Cisco cfg agent and L3 agent."""

    def __init__(self, l3plugin, topic=topics.L3_AGENT):
        target = messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)
        self._l3plugin = l3plugin

    def _host_notification(self, context, method, payload, host,
                           topic=topics.L3_AGENT):
        """Notify the agent that is hosting the router."""
        LOG.debug('Notify agent at %(host)s the message %(method)s',
                  {'host': host, 'method': method})
        cctxt = self.client.prepare(topic=topic, server=host)
        cctxt.cast(context, method, payload=payload)

    def _agent_notification(self, context, method, routers, operation,
                            shuffle_agents):
        """Notify individual L3 agents and Cisco cfg agents."""
        admin_context = context.is_admin and context or context.elevated()
        dmplugin = manager.NeutronManager.get_service_plugins().get(
            svc_constants.DEVICE_MANAGER)
        ns_routertype_id = self._l3plugin.get_namespace_router_type_id(context)
        for router in routers:
            if (router['router_type']['id'] == ns_routertype_id and
                    utils.is_extension_supported(self._l3plugin, L3AGENT_SCHED)):
                agents = self._l3plugin.get_l3_agents_hosting_routers(
                    admin_context, [router['id']],
                    admin_state_up=True,
                    active=True)
                if shuffle_agents:
                    random.shuffle(agents)
            elif (router['hosting_device'] is not None and
                  utils.is_extension_supported(dmplugin, CFGAGENT_SCHED)):
                agents = dmplugin.get_cfg_agents_for_hosting_devices(
                    admin_context, [router['hosting_device']['id']],
                    admin_state_up=True, active=True, schedule=True)
            else:
                continue
            for agent in agents:
                # Only use agent topic for l3 agent, otherwise topic for
                # router service helper in cfg agent.
                if router['hosting_device'] is None:
                    topic = agent.topic
                    version = '1.1'
                else:
                    topic = c_constants.CFG_AGENT_L3_ROUTING
                    version = '1.0'
                LOG.debug('Notify %(agent_type)s at %(topic)s.%(host)s the '
                          'message %(method)s',
                          {'agent_type': agent.agent_type,
                           'topic': topic,
                           'host': agent.host,
                           'method': method})
                cctxt = self.client.prepare(topic=topic,
                                            server=agent.host,
                                            version=version)
                cctxt.cast(context, method, routers=[router['id']])

    def _notification(self, context, method, routers, operation,
                      shuffle_agents):
        """Notify all or individual L3 agents and Cisco cfg agents."""
        if utils.is_extension_supported(self._l3plugin, L3AGENT_SCHED):
            adm_context = (context.is_admin and context or context.elevated())
            # This is where a hosting device gets scheduled to a
            # Cisco cfg agent and where network namespace-based
            # routers get scheduled to a l3 agent.
            self._l3plugin.schedule_routers(adm_context, routers)
            self._agent_notification(
                context, method, routers, operation, shuffle_agents)
        else:
            cctxt = self.client.prepare(topics=topics.L3_AGENT, fanout=True)
            cctxt.cast(context, method, routers=[r['id'] for r in routers])

    def _notification_fanout(self, context, method, router_id):
        """Fanout the deleted router to all L3 agents."""
        LOG.debug('Fanout notify agent at %(topic)s the message %(method)s on '
                  'router %(router_id)s',
                  {'topic': topics.DHCP_AGENT,
                   'method': method,
                   'router_id': router_id})
        cctxt = self.client.prepare(topics=topics.L3_AGENT, fanout=True)
        cctxt.cast(context, method, router_id=router_id)

    def agent_updated(self, context, admin_state_up, host):
        """Updates agent on host to enable or disable it."""
        #TODO(bobmel): Ensure only used for l3agent
        self._host_notification(context, 'agent_updated',
                                {'admin_state_up': admin_state_up}, host)

    def router_deleted(self, context, router):
        """Notifies agents about a deleted router."""
        namespace_routertype_id = self._l3plugin.get_namespace_router_type_id(
            context)
        if router['router_type']['id'] == namespace_routertype_id:
            self._notification_fanout(context, 'router_deleted', router['id'])
        else:
            self._agent_notification(context, 'router_deleted', [router], None,
                                     False)

    def routers_updated(self, context, routers, operation=None, data=None,
                        shuffle_agents=False):
        """Notifies agents about configuration changes to routers.

        This includes operations performed on the router like when a
        router interface is added or removed.

        L3 agent or Cisco configuration agent are receiver of the
        notification.
        """
        if routers:
            self._notification(context, 'routers_updated', routers, operation,
                               shuffle_agents)

    def router_removed_from_agent(self, context, router_id, host):
        """Notifies L3 agent on host that router has been removed from it."""
        self._host_notification(context, 'router_removed_from_agent',
                                {'router_id': router_id}, host,
                                topic=topics.L3_AGENT)

    def router_added_to_agent(self, context, routers, host):
        """Notifies L3 agent on host that router has been added to it."""
        self._host_notification(context, 'router_added_to_agent',
                                routers, host,
                                topic=topics.L3_AGENT)

    def router_removed_from_hosting_device(self, context, router_id, host):
        """Notification that router has been removed from hosting device.

        A Cisco configuration agent is the receiver of these notifications.
        """
        self._host_notification(context, 'router_removed_from_hosting_device',
                                {'router_id': router_id}, host,
                                topic=c_constants.CFG_AGENT)

    def router_added_to_hosting_device(self, context, routers, host):
        """Notification that router has been added to hosting device.

        A Cisco configuration agent is the receiver of these notifications.
        """
        self._host_notification(context, 'router_added_to_hosting_device',
                                routers, host,
                                topic=c_constants.CFG_AGENT)
