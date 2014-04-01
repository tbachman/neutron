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
# Based on Neutron L3 Agent scheduler.

import random

from sqlalchemy.orm import exc
from sqlalchemy.sql import exists

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.l3.common import constants as cl3_constants
from neutron.plugins.cisco.l3.db import hosting_device_manager_db as dev_mgr_db
from neutron.plugins.cisco.l3.db import l3_models

LOG = logging.getLogger(__name__)


class HostingDeviceCfgAgentScheduler(object):
    """A scheduler for Cisco (hosting) device manager service plugin.

    It schedules hosting devices to Cisco cfg agents. The scheduling is a
    simple random selection among qualified candidates.
    """

    def auto_schedule_hosting_devices_on_cfg_agent(self, context, agent_host):
        """Schedules unassociated hosting devices to Cisco cfg agent.

        Schedules hosting device to agent running on <agent_host>.
        """
        with context.session.begin(subtransactions=True):
            #TODO(bobmel): Consider change implementation so that ALL active
            # agents are considered during auto-scheduling.
            # Check if there is a valid Cisco cfg agent on the host
            query = context.session.query(agents_db.Agent)
            query = query.filter_by(agent_type=cl3_constants.AGENT_TYPE_CFG,
                                    host=agent_host, admin_state_up=True)
            try:
                cfg_agent = query.one()
            except (exc.MultipleResultsFound, exc.NoResultFound):
                LOG.debug(_('No enabled Cisco cfg agent on host %s'),
                          agent_host)
                return False
            if agents_db.AgentDbMixin.is_agent_down(
                    cfg_agent.heartbeat_timestamp):
                LOG.warn(_('Cisco cfg agent %s is not alive'), cfg_agent.id)
            query = context.session.query(HostingDevice)
            query = query.filter_by(cfg_agent_id=None)
            for hd in query:
                hd.cfg_agent = cfg_agent
                context.session.add(hd)
            return True

    def schedule_hosting_devices_on_cfg_agent(self, plugin, context, id):
        """Selects Cisco cfg agent that will configure hosting device."""
        with context.session.begin(subtransactions=True):
            hd_db = self._dev_mgr.get_hosting_devices_db(context, [id])
            if not hd_db:
                LOG.debug(_('DB inconsistency: Hosting device %s could '
                            'not be found'), id)
                return
            if hd_db[0].cfg_agent:
                LOG.debug(_('Hosting device %(hd_id)s has already been '
                            'assigned to Cisco cfg agent %(agent_id)s'),
                          {'hd_id': id,
                           'agent_id': hd_db[0].cfg_agent['id']})
                return
            active_cfg_agents = plugin.get_cfg_agents(context, active=True)
            if not active_cfg_agents:
                LOG.warn(_('There are no active Cisco cfg agents'))
                # No worries, once a Cisco cfg agent is started and
                # announces itself any "dangling" hosting devices
                # will be scheduled to it.
                return
            chosen_agent = random.choice(active_cfg_agents)
            hd_db[0].cfg_agent = chosen_agent
            context.session.add(hd_db[0])
            return chosen_agent

    @property
    def _dev_mgr(self):
        return dev_mgr_db.HostingDeviceManagerMixin.get_instance()
