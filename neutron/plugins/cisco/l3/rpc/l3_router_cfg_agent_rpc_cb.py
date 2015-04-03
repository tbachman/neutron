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

from oslo import messaging
from oslo_serialization import jsonutils
from oslo_log import log as logging

from neutron.common import constants
from neutron.common import exceptions
from neutron.common import utils
from neutron import context as neutron_context
from neutron.extensions import portbindings
from neutron import manager

LOG = logging.getLogger(__name__)


class L3RouterCfgRpcCallback(object):
    """Cisco cfg agent rpc support in L3 routing service plugin."""

    target = messaging.Target(version='1.0')

    def __init__(self, l3plugin):
        self._l3plugin = l3plugin

    @property
    def _core_plugin(self):
        try:
            return self._plugin
        except AttributeError:
            self._plugin = manager.NeutronManager.get_plugin()
            return self._plugin

    def cfg_sync_routers(self, context, host, router_ids=None,
                         hosting_device_ids=None):
        """Sync routers according to filters to a specific Cisco cfg agent.

        @param context: contains user information
        @param host - originator of callback
        @param router_ids - list of router ids to return information about
        @param hosting_device_ids - list of hosting device ids to get
        routers for.
        @return: a list of routers
                 with their hosting devices, interfaces and floating_ips
        """
        adm_context = neutron_context.get_admin_context()
        try:
            routers = (
                self._l3plugin.list_active_sync_routers_on_hosting_devices(
                    adm_context, host, router_ids, hosting_device_ids))
        except AttributeError:
            routers = []
        if routers and utils.is_extension_supported(
                self._core_plugin, constants.PORT_BINDING_EXT_ALIAS):
            self._ensure_host_set_on_ports(context, host, routers)
        LOG.debug('Routers returned to Cisco cfg agent@%(agt)s:\n %(routers)s',
                  {'agt': host, 'routers': jsonutils.dumps(routers, indent=5)})
        return routers

    def report_status(self, context, host, status_list):
        """Report status of a particular Neutron router by Cisco cfg agent.

        This is called by Cisco cfg agent when it has performed an operation
        on a Neutron router. Note that the agent may include status updates
        for multiple routers in one message.

        @param context: contains user information
        @param host - originator of callback
        @param status_list: list of status dicts for routers
                            Each list item is
                            {'router_id': <router_id>,
                             'operation': <attempted operation>
                             'status': <'SUCCESS'|'FAILURE'>,
                             'details': <optional explaining details>}
        """
        #TODO(bobmel): Update router status
        # State machine: CREATE: SCHEDULING -> PENDING_CREATE -> ACTIVE/ERROR
        #                UPDATE: PENDING_UPDATE -> ACTIVE/ERROR
        #                DELETE: PENDING_DELETE -> DELETED/ERROR
        # While in SCHEDULING|PENDING_* states, no operations on the router
        # are allowed. Need to handle lost ACKs by either periodic refreshes
        # or by maintaining timers on routers in SCHEDULING|PENDING_* states.
        LOG.debug("Config agent %(host)s reported status for Neutron"
                  "routers: %(routers)s", {'host': host, 'routers': []})

    def _ensure_host_set_on_ports(self, context, host, routers):
        for router in routers:
            LOG.debug("Checking router: %(id)s for host: %(host)s",
                      {'id': router['id'], 'host': host})
            self._ensure_host_set_on_port(context, host, router.get('gw_port'),
                                          router['id'])
            for interface in router.get(constants.INTERFACE_KEY, []):
                self._ensure_host_set_on_port(context, host,
                                              interface, router['id'])

    def _ensure_host_set_on_port(self, context, host, port, router_id=None):
        if (port and
            (port.get('device_owner') !=
             constants.DEVICE_OWNER_DVR_INTERFACE and
             port.get(portbindings.HOST_ID) != host or
             port.get(portbindings.VIF_TYPE) ==
             portbindings.VIF_TYPE_BINDING_FAILED)):
            try:
                self._core_plugin.update_port(
                    context, port['id'],
                    {'port': {portbindings.HOST_ID: host}})
            except exceptions.PortNotFound:
                LOG.debug("Port %(port)s not found while updating "
                          "agent binding for router %(router)s."
                          % {"port": port['id'], "router": router_id})
