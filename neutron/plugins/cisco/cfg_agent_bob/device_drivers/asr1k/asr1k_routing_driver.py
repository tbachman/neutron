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
from neutron.plugins.cisco.cfg_agent.device_drivers.asr1k import asr1k_snippets
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    cisco_csr1kv_snippets as snippets)
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    iosxe_routing_driver as csr1kv_driver)
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.extensions import ha

LOG = logging.getLogger(__name__)


DEVICE_OWNER_ROUTER_GW = constants.DEVICE_OWNER_ROUTER_GW


class ASR1kRoutingDriver(csr1kv_driver.CSR1kvRoutingDriver):

    def __init__(self, **device_params):
        super(ASR1kRoutingDriver, self).__init__(**device_params)

    # ============== Public functions ==============

    def internal_network_added(self, ri, port):
        gw_ip = port['subnet']['gateway_ip']
        if self._is_port_v6(port):
            LOG.debug("Adding IPv6 internal network port: %s for router %s" % (
                      port, ri['id']))
            self._create_sub_interface_v6(ri, port, False, gw_ip)
        else:
            LOG.debug("Adding IPv4 internal network port: %s for router %s" % (
                      port, ri['id']))
            self._create_sub_interface(ri, port, False, gw_ip)

    def external_gateway_added(self, ri, ext_gw_port):
        # global router handles IP assignment, HSRP setup
        # tenant router handles interface creation and default route
        # within VRFs
        if self._is_global_router(ri):
            self._handle_external_gateway_added_global_router(ri, ext_gw_port)
        else:
            self._handle_external_gateway_added_normal_router(ri, ext_gw_port)

    def external_gateway_removed(self, ri, ext_gw_port):
        if self._is_global_router(ri):
            self._remove_sub_interface(ext_gw_port)
        else:
            ex_gw_ip = ext_gw_port['subnet']['gateway_ip']
            if (ex_gw_ip and
                    ext_gw_port['device_owner'] == DEVICE_OWNER_ROUTER_GW):
                # LOG.debug("REMOVE ROUTE PORT %s" % ex_gw_port)
                # Remove default route via this network's gateway ip
                if self._is_port_v6(ext_gw_port):
                    self._remove_default_route_v6(ri, ex_gw_ip, ext_gw_port)
                else:
                    self._set_nat_pool(ri, ext_gw_port, True)
                    self._remove_default_route(ri, ext_gw_port)

    def floating_ip_added(self, ri, ext_gw_port, floating_ip, fixed_ip):
        self._add_floating_ip(ri, ext_gw_port, floating_ip, fixed_ip)

    def disable_internal_network_NAT(self, ri, port, ext_gw_port,
                                     itfc_delete=False):
        self._remove_internal_nw_nat_rules(ri, [port], ext_gw_port,
                                           itfc_delete)

    # ============== Internal "preparation" functions  ==============

    def _get_interface_name_from_hosting_port(self, port):
        try:
            vlan = port['hosting_info']['segmentation_id']
            int_prefix = port['hosting_info']['physical_interface']
            return '%s.%s' % (int_prefix, vlan)
        except KeyError as e:
            params = {'key': e}
            raise cfg_exc.DriverExpectedKeyNotSetException(**params)

    def _get_interface_name_from_hosting_port_1C_VERSION(self, port):
        asr_ent = self.target_asr
        vlan = self._get_interface_vlan_from_hosting_port(port)
        subinterface = asr_ent['target_intf']
        intfc_name = "%s.%s" % (subinterface, vlan)
        return intfc_name

    def _enable_itfcs(self, conn):
        """For ASR we don't need to do anything"""
        return True

    def _get_virtual_gw_port_for_ext_net(self, ri, ex_gw_port):
        subnet_id = ex_gw_port['subnet']['id']
        gw_ports = ri.router.get(constants.HA_GW_KEY, [])
        for gw_port in gw_ports:
            if gw_port['subnet']['id'] == subnet_id:
                if gw_port['device_owner'] == constants.DEVICE_OWNER_ROUTER_GW:
                    return gw_port
        return None

    def _handle_external_gateway_added_global_router(self, ri, ext_gw_port):
        # TODO(bobmel): Get the HA virtual IP correctly
        virtual_gw_port = self._get_virtual_gw_port_for_ext_net(
            ri, ext_gw_port)
        sub_itfc_ip = virtual_gw_port['fixed_ips'][0]['ip_address']
        if self._is_port_v6(ext_gw_port):
            LOG.debug("Adding IPv6 external network port: %s for global "
                      "router %s" % (ext_gw_port['id'], ri['id']))
            self._create_sub_interface_v6(ri, ext_gw_port, True, sub_itfc_ip)
        else:
            LOG.debug("Adding IPv4 external network port: %s for global "
                      "router %s" % (ext_gw_port['id'], ri['id']))
            self._create_sub_interface(ri, ext_gw_port, True, sub_itfc_ip)

    def _handle_external_gateway_added_normal_router(self, ri, ext_gw_port):
        # Default routes are mapped to VRFs tenant routers). Global Router
        # is not aware of tenant routers with ext network assigned. Thus,
        # default route must be handled per tenant router.
        ex_gw_ip = ext_gw_port['subnet']['gateway_ip']
        sub_interface = self._get_interface_name_from_hosting_port(ext_gw_port)
        vlan_id = self._get_interface_vlan_from_hosting_port(ext_gw_port)
        if (self._fullsync and
                int(vlan_id) in self._existing_cfg_dict['interfaces']):
            LOG.debug("Sub-interface already exists, don't create "
                      "interface")
        else:
            LOG.debug("Adding IPv4 external network port: %s for tenant "
                      "router %s" % (ext_gw_port['id'], ri['id']))
            self._create_ext_sub_interface_enable_only(sub_interface)
        if ex_gw_ip:
            # Set default route via this network's gateway ip
            if self._is_port_v6(ext_gw_port):
                self._add_default_route_v6(ri, ex_gw_ip, ext_gw_port)
            else:
                self._set_nat_pool(ri, ext_gw_port, False)
                self._add_default_route(ri, ext_gw_port)

    def _create_sub_interface(self, ri, port, is_external=False, gw_ip=""):
        if not self._port_needs_config(port):
            return
        vlan = self._get_interface_vlan_from_hosting_port(port)
        if (self._fullsync and
                int(vlan) in self._existing_cfg_dict['interfaces']):
            LOG.info(_LI("Sub-interface already exists, skipping"))
            return
        vrf_name = self._get_vrf_name(ri)
        net_mask = netaddr.IPNetwork(port['ip_cidr']).netmask
        hsrp_ip = port['fixed_ips'][0]['ip_address']
        sub_interface = self._get_interface_name_from_hosting_port(port)
        self._do_create_sub_interface(sub_interface, vlan, vrf_name, hsrp_ip,
                                      net_mask, is_external)
        # Always do HSRP
        self._add_ha_hsrp(ri, port, gw_ip, is_external)

    def _do_create_sub_interface(self, sub_interface, vlan_id, vrf_name, ip,
                                 mask, is_external=False):
        if is_external is True:
            conf_str = asr1k_snippets.CREATE_SUBINTERFACE_EXTERNAL_WITH_ID % (
                sub_interface, self._asr_config.deployment_id, vlan_id, ip,
                mask)
        else:
            conf_str = asr1k_snippets.CREATE_SUBINTERFACE_WITH_ID % (
                sub_interface, self._asr_config.deployment_id, vlan_id,
                vrf_name, ip, mask)
        self._edit_running_config(conf_str, '%s CREATE_sub_interface' %
                                  self.target_asr['name'])

    def _create_ext_sub_interface_enable_only(self, sub_interface):
        LOG.debug("Enabling external network sub interface: %s" %
                  sub_interface)
        conf_str = snippets.ENABLE_INTF % sub_interface
        self._edit_running_config(conf_str, '%s ENABLE_INTF' %
                                  self.target_asr['name'])

    def _set_nat_pool(self, ri, gw_port, is_delete):
        vrf_name = self._get_vrf_name(ri)
        pool_ip = gw_port['fixed_ips'][0]['ip_address']
        pool_name = "%s_nat_pool" % (vrf_name)
        pool_net = netaddr.IPNetwork(gw_port['ip_cidr'])

        if self._fullsync and pool_ip in self._existing_cfg_dict['pools']:
            LOG.info(_LI("Pool already exists, skipping"))
            return

        #LOG.debug("SET_NAT_POOL pool netmask: %s, gw_port %s" % (
        # pool_net.netmask, gw_port))
        try:
            if is_delete:
                conf_str = asr1k_snippets.DELETE_NAT_POOL % (
                    pool_name, pool_ip, pool_ip, pool_net.netmask)
                self._edit_running_config(conf_str, '%s DELETE_NAT_POOL' %
                                          self.target_asr['name'])
            else:
                conf_str = asr1k_snippets.CREATE_NAT_POOL % (
                    pool_name, pool_ip, pool_ip, pool_net.netmask)
                self._edit_running_config(conf_str, '%s CREATE_NAT_POOL' %
                                          self.target_asr['name'])
        except cfg_exc.CSR1kvConfigException as cse:
            LOG.error(_LE("Temporary disable NAT_POOL exception handling: "
                          "%s"), cse)

    def _add_default_route(self, ri, ext_gw_port):
        router_id = self._get_short_router_id_from_port(ext_gw_port)
        if self._fullsync and router_id in self._existing_cfg_dict['routes']:
            LOG.debug("Default route already exists, skipping")
            return
        ext_gw_ip = ext_gw_port['subnet']['gateway_ip']
        if ext_gw_ip:
            conn = self._get_connection()
            vrf_name = self._get_vrf_name(ri)
            out_itfc = self._get_interface_name_from_hosting_port(ext_gw_port)
            conf_str = asr1k_snippets.SET_DEFAULT_ROUTE_WITH_INTF % (
                vrf_name, out_itfc, ext_gw_ip)
            rpc_obj = conn.edit_config(target='running', config=conf_str)
            self._check_response(rpc_obj, '%s SET_DEFAULT_ROUTE_WITH_INTF' %
                                 self.target_asr['name'])

    def _remove_default_route(self, ri, ext_gw_port):
        ext_gw_ip = ext_gw_port['subnet']['gateway_ip']
        if ext_gw_ip:
            conn = self._get_connection()
            vrf_name = self._get_vrf_name(ri)
            out_itfc = self._get_interface_name_from_hosting_port(ext_gw_port)
            conf_str = asr1k_snippets.REMOVE_DEFAULT_ROUTE_WITH_INTF % (
                vrf_name, out_itfc, ext_gw_ip)
            rpc_obj = conn.edit_config(target='running', config=conf_str)
            self._check_response(rpc_obj, '%s REMOVE_DEFAULT_ROUTE_WITH_INTF' %
                                 self.target_asr['name'])

    def _add_ha_hsrp(self, ri, port):
        priority = ri[ha.DETAILS][ha.PRIORITY]
        port_ha_info = port[ha.HA_INFO]
        group = port_ha_info['group']
        ip = port_ha_info['ha_port']['fixed_ips'][0]['ip_address']
        if ip and group and priority:
            vrf_name = self._get_vrf_name(ri)
            sub_interface = self._get_interface_name_from_hosting_port(port)
            self._do_set_ha_hsrp(sub_interface, vrf_name, priority, group, ip)

    def _add_ha_hsrp_1C_VERSION(self, ri, port, ip, is_external=False):
        if not self._port_needs_config(port):
            return
        vlan = self._get_interface_vlan_from_hosting_port(port)
        # group = vlan
        if is_external:
            group = self._get_hsrp_grp_num_from_net_id(port['network_id'])
        else:
            group = self._get_hsrp_grp_num_from_ri(ri)
        vrf_name = self._get_vrf_name(ri)
        asr_ent = self.target_asr
        priority = asr_ent['order']
        sub_interface = self._get_interface_name_from_hosting_port(port)
        self._do_set_ha_hsrp(sub_interface, vrf_name, priority, group, vlan,
                             ip, is_external)

    def _do_set_ha_hsrp(self, sub_interface, vrf_name, priority, group, ip):
        if vrf_name not in self._get_vrfs():
            LOG.error(_LE("VRF %s not present"), vrf_name)
        conf_str = snippets.SET_INTC_HSRP % (sub_interface, vrf_name, group,
                                             priority, group, ip)
        action = "SET_INTC_HSRP (Group: %s, Priority: % s)" % (group, priority)
        self._edit_running_config(conf_str, action)

    def _do_set_ha_hsrp_1C_VERSION(self, subinterface, vrf_name, priority,
                                   group, vlan, ip, is_external=False):
        try:
            confstr = asr1k_snippets.REMOVE_INTC_ASR_HSRP_PREEMPT % (
                subinterface, group)
            self._edit_running_config(confstr, "REMOVE_HSRP_PREEMPT")
        except Exception:
            pass
        if is_external is True:
            conf_str = asr1k_snippets.SET_INTC_ASR_HSRP_EXTERNAL % (
                subinterface, group, priority, group, ip, group, group, group,
                vlan)
        else:
            conf_str = asr1k_snippets.SET_INTC_ASR_HSRP % (
                subinterface, vrf_name, group, priority, group, ip, group)
        action = "%s SET_INTC_HSRP (Group: %s, Priority: % s)" % (
            self.target_asr['name'], group, priority)
        self._edit_running_config(conf_str, action)

    def _create_sub_interface_v6(self, ri, port, is_external=False, gw_ip=""):
        if self._v6_port_needs_config(port) is not True:
            return
        vrf_name = self._get_vrf_name(ri)
        ip_cidr = port['ip_cidr']
        vlan = self._get_interface_vlan_from_hosting_port(port)
        sub_interface = self._get_interface_name_from_hosting_port(port)
        self._do_create_sub_interface_v6(sub_interface, vlan, vrf_name,
                                         ip_cidr, is_external)
        # Always do HSRP
        self._add_ha_HSRP_v6(ri, port, ip_cidr, is_external)

    def _do_create_sub_interface_v6(self, sub_interface, vlan_id, vrf_name,
                                   ip_cidr, is_external=False):
        if is_external is True:
            conf_str = asr1k_snippets.CREATE_SUBINTERFACE_V6_NO_VRF_WITH_ID % (
                sub_interface, self._asr_config.deployment_id, vlan_id,
                ip_cidr)
        else:
            conf_str = asr1k_snippets.CREATE_SUBINTERFACE_V6_WITH_ID % (
                sub_interface, self._asr_config.deployment_id, vlan_id,
                vrf_name, ip_cidr)
        self._edit_running_config(conf_str, '%s CREATE_SUBINTERFACE_V6' %
                                  self.target_asr['name'])

    def _add_default_route_v6(self, ri, gw_ip, gw_port):
        vrf_name = self._get_vrf_name(ri)
        #sub_interface = self._get_interface_name_from_hosting_port(gw_port)
        conn = self._get_connection()
        # confstr = asr1k_snippets.SET_DEFAULT_ROUTE_V6_WITH_INTF % (vrf,
        # out_intf, gw_ip)
        conf_str = asr1k_snippets.SET_DEFAULT_ROUTE_V6_WITH_INTF % (
            vrf_name, gw_ip)
        rpc_obj = conn.edit_config(target='running', config=conf_str)
        self._check_response(rpc_obj, '%s SET_DEFAULT_ROUTE_V6_WITH_INTF' %
                             self.target_asr['name'])

    def _remove_default_route_v6(self, ri, gw_ip, gw_port):
        vrf_name = self._get_vrf_name(ri)
        sub_interface = self._get_interface_name_from_hosting_port(gw_port)
        self._remove_default_static_route_v6(gw_ip, vrf_name, sub_interface)

    def _remove_default_static_route_v6(self, gw_ip, vrf, out_intf):
        conn = self._get_connection()
        # confstr = asr_snippets.REMOVE_DEFAULT_ROUTE_V6_WITH_INTF % (vrf,
        # out_intf, gw_ip)
        conf_str = asr1k_snippets.REMOVE_DEFAULT_ROUTE_V6_WITH_INTF % (
            vrf, gw_ip)
        rpc_obj = conn.edit_config(target='running', config=conf_str)
        self._check_response(rpc_obj, '%s REMOVE_DEFAULT_ROUTE_V6_WITH_INTF' %
                             self.target_asr['name'])

    def _add_ha_HSRP_v6(self, ri, port, ip, is_external=False):
        if self._v6_port_needs_config(port) is not True:
            return
        vlan = self._get_interface_vlan_from_hosting_port(port)
        group = vlan
        asr_ent = self.target_asr
        priority = asr_ent['order']
        sub_interface = self._get_interface_name_from_hosting_port(port)
        self._set_ha_HSRP_v6(sub_interface, priority, group, is_external)

    def _port_needs_config(self, port):
        if not self._port_is_hsrp(port):
            LOG.debug("Ignoring non-HSRP interface")
            return False
        asr_ent = self._get_asr_ent_from_port(port)
        if asr_ent['name'] != self.target_asr['name']:
            LOG.debug("Ignoring interface for non-target ASR1k")
            return False
        return True

    def _port_is_hsrp(self, port):
        hsrp_types = [constants.DEVICE_OWNER_ROUTER_HA_GW,
                      constants.DEVICE_OWNER_ROUTER_HA_INTF]
        return port['device_owner'] in hsrp_types

    def _is_global_router(self, ri):
        return ri.get('role') == cisco_constants.ROUTER_ROLE_GLOBAL

    def _is_port_v6(self, port):
        return netaddr.IPNetwork(port['subnet']['cidr']).version == 6
