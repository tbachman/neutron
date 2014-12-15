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

from neutron.common import constants
from neutron.common import utils
from neutron import context as neutron_context
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class L3RouterCfgRpcCallbackMixin(object):
    """Mixin for Cisco cfg agent rpc support in L3 routing service plugin."""

    target = messaging.Target(version='1.0')

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
        context = neutron_context.get_admin_context()
        try:
            routers = (
                self._l3plugin.list_active_sync_routers_on_hosting_devices(
                    context, host, router_ids, hosting_device_ids))
        except AttributeError:
            routers = []
        if routers and utils.is_extension_supported(
                self._core_plugin, constants.PORT_BINDING_EXT_ALIAS):
            self._ensure_host_set_on_ports(context, self._core_plugin, host,
                                           routers)
        LOG.debug('Routers returned to Cisco cfg agent@%(agt)s:\n %(routers)s',
                  {'agt': host, 'routers': jsonutils.dumps(routers, indent=5)})
        return routers
