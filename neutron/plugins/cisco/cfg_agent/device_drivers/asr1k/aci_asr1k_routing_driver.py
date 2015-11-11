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

import logging
import netaddr

from neutron.i18n import _LE, _LI
from neutron.common import constants
from neutron.plugins.cisco.cfg_agent import cfg_exceptions as cfg_exc
from neutron.plugins.cisco.cfg_agent.device_drivers.asr1k \
    import asr1k_cfg_syncer
from neutron.plugins.cisco.cfg_agent.device_drivers.asr1k import asr1k_snippets
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    cisco_csr1kv_snippets as snippets)
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    iosxe_routing_driver as iosxe_driver)
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.extensions import ha
from neutron.plugins.cisco.extensions import routerrole
from neutron.plugins.cisco.cfg_agent.device_drivers.asr1k import (
    asr1k_routing_driver as asr1k)


LOG = logging.getLogger(__name__)


DEVICE_OWNER_ROUTER_GW = constants.DEVICE_OWNER_ROUTER_GW
HA_INFO = 'ha_info'
ROUTER_ROLE_ATTR = routerrole.ROUTER_ROLE_ATTR


class AciASR1kRoutingDriver(asr1k.ASR1kRoutingDriver):

    def __init__(self, **device_params):
        super(AciASR1kRoutingDriver, self).__init__(**device_params)
        self._fullsync = False
        self._deployment_id = "zxy"
        self.hosting_device = {'id': device_params.get('id'),
                               'name': device_params.get('device_id')}

    # ============== Public functions ==============

    def internal_network_added(self, ri, port):
        if not self._is_port_v6(port):
            if self._is_global_router(ri):
                # The global router is modeled as the default vrf
                # in the ASR.  When an external gateway is configured,
                # a normal "internal" interface is created in the default
                # vrf that is in the same subnet as the ext-net.
                LOG.debug("++++ global router handling")
                self.external_gateway_added(ri, port)

    def internal_network_removed(self, ri, port):
        pass

    def floating_ip_added(self, ri, ext_gw_port, floating_ip, fixed_ip):
        self._add_floating_ip(ri, ext_gw_port, floating_ip, fixed_ip)

    def floating_ip_removed(self, ri, ext_gw_port, floating_ip, fixed_ip):
        self._remove_floating_ip(ri, ext_gw_port, floating_ip, fixed_ip)

    # ============== Internal "preparation" functions  ==============

    def _get_vrf_name(self, ri):
        """
        For ACI, a tenant is mapped to a VRF.
        """
        return ri.router['tenant_id']

    def _add_floating_ip(self, ri, ex_gw_port, floating_ip, fixed_ip):
        vrf_name = self._get_vrf_name(ri)
        self._asr_do_add_floating_ip(floating_ip, fixed_ip,
                                     vrf_name, ex_gw_port)

    def _asr_do_add_floating_ip(self, floating_ip, fixed_ip, vrf, ex_gw_port):
        """
        To implement a floating ip, an ip static nat is configured in the
        underlying router ex_gw_port contains data to derive the vlan
        associated with related subnet for the fixed ip.  The vlan in turn
        is applied to the redundancy parameter for setting the IP NAT.
        """
        vlan = ex_gw_port['hosting_info']['segmentation_id']
        hsrp_grp = ex_gw_port['ha_info']['group']

        LOG.debug("add floating_ip: %(fip)s, fixed_ip: %(fixed_ip)s, "
                  "vrf: %(vrf)s, ex_gw_port: %(port)s",
                  {'fip': floating_ip, 'fixed_ip': fixed_ip, 'vrf': vrf,
                   'port': ex_gw_port})

        confstr = asr1k_snippets.SET_STATIC_SRC_TRL_NO_VRF_MATCH % \
            (fixed_ip, floating_ip, vrf, hsrp_grp, vlan)
        self._edit_running_config(confstr, 'SET_STATIC_SRC_TRL_NO_VRF_MATCH')

    def _remove_floating_ip(self, ri, ext_gw_port, floating_ip, fixed_ip):
        vrf_name = self._get_vrf_name(ri)
        self._asr_do_remove_floating_ip(floating_ip,
                                        fixed_ip,
                                        vrf_name,
                                        ext_gw_port)

    def _asr_do_remove_floating_ip(self, floating_ip,
                                   fixed_ip, vrf, ex_gw_port):
        vlan = ex_gw_port['hosting_info']['segmentation_id']
        hsrp_grp = ex_gw_port['ha_info']['group']

        confstr = asr1k_snippets.REMOVE_STATIC_SRC_TRL_NO_VRF_MATCH % \
            (fixed_ip, floating_ip, vrf, hsrp_grp, vlan)
        self._edit_running_config(confstr,
                                  'REMOVE_STATIC_SRC_TRL_NO_VRF_MATCH')
