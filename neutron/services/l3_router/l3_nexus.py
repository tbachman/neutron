# Copyright (c) 2014 OpenStack Foundation.
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
#
# @author: Arvind Somya, Cisco Systems, Inc. <asomya@cisco.com>

from oslo.config import cfg

from neutron.common import constants as q_const
from neutron.common import topics
from neutron.db import common_db_mixin
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_dvrscheduler_db
from neutron.db import l3_gwmode_db
from neutron.extensions import portbindings
from neutron.openstack.common import importutils
from neutron.plugins.common import constants
from neutron.plugins.ml2.drivers.cisco.nexus import config as conf
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_db_v2 as nxdb
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_network_driver


class NexusL3ServicePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                           extraroute_db.ExtraRoute_db_mixin,
                           l3_gwmode_db.L3_NAT_db_mixin):

    supported_extension_aliases = ["router", "ext-gw-mode",
                                   "extraroute"]

    def __init__(self):
        conf.ML2MechCiscoConfig()
        super(NexusL3ServicePlugin, self).__init__()
        self.driver = nexus_network_driver.CiscoNexusDriver()
        self._nexus_switches = conf.ML2MechCiscoConfig.nexus_dict

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def _get_switch_info(self, host_id):
        host_connections = []
        for switch_ip, attr in self._nexus_switches:
            if str(attr) == str(host_id):
                for port_id in (
                    self._nexus_switches[switch_ip, attr].split(',')):
                    if ':' in port_id:
                        intf_type, port = port_id.split(':')
                    else:
                        intf_type, port = 'ethernet', port_id
                    host_connections.append((switch_ip, intf_type, port))

        if host_connections:
            return host_connections

    def create_router(self, context, router):
        db_router = super(NexusL3ServicePlugin, self).create_router(
            context, router)
        # Allocate VRF for router
        nx_db_vrf = nxdb.add_nexus_vrf(context.session, db_router.get('id'))
        return db_router

    def update_router(self, context, id, router):
        return super(NexusL3ServicePlugin, self).update_router(context,
                                                               id, router)

    def delete_router(self, context, id):
        # Get VRF associated
        nx_db_vrf = nxdb.get_nexus_vrf(context.session, id)
        # Delete on switches
        
        nxdb.delete_nexus_vrf(context.session, nx_db_vrf['vrf_id'])
        return super(NexusL3ServicePlugin, self).delete_router(context, id)

    def add_router_interface(self, context, router_id, interface_info):
        result = super(NexusL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)

        # Get interface subnet, network and ports
        subnet = self._core_plugin.get_subnet(context,
                                              interface_info['subnet_id'])
        port_filters = {'network_id': [subnet['network_id']]}
        ports = self._core_plugin.get_ports(context, port_filters)
        for port in ports:
            self._create_vrf(context, router_id, port)

        return result

    def _create_vrf(self, context, router_id, port):
        db_router = nxdb.get_nexus_vrf(context.session, router_id)
        vrf_id = db_router.vrf_id
        host_id = port.get(portbindings.HOST_ID)
        owner = port.get('device_owner')
        if host_id and owner=='compute:None':
            # Get switch connections for this host
            connections = self._get_switch_info(host_id)
            for connection in connections:
                # Check for a VRF binding
                if not nxdb.get_nexus_vrf_binding(context.session, vrf_id,
                                                  connection[0]):
                    self.driver.create_vrf(connection[0], vrf_id)
                    nxdb.add_nexus_vrf_binding(context.session, vrf_id,
                                               connection[0])

    def remove_router_interface(self, context, router_id, interface_info):
        # Get vrf_id for this router
        db_router = nxdb.get_nexus_vrf(context.session, router_id)
        # Get all bindings for this vrf
        bindings = nxdb.get_nexus_vrf_bindings(context.session,
                                               db_router['vrf_id'])
        for binding in bindings:
            self.driver.delete_vrf(binding['vrf_id'], binding['switch_ip'])
            nxdb.delete_nexus_vrf_binding(binding['vrf_id'],
                                          binding['switch_ip'])

        return super(NexusL3ServicePlugin, self).remove_router_interface(
            context, router_id, interface_info)

    def create_floatingip(self, context, floatingip):
        return super(NexusL3ServicePlugin, self).create_floatingip(
            context, floatingip)

    def update_floatingip(self, context, id, floatingip):
        return super(NexusL3ServicePlugin, self).update_floatingip(
            context, id, floatingip)

    def update_floatingip_status(self, context, floatingip_id, status):
        return super(NexusL3ServicePlugin, self).update_floatingip_status(
            context, floatingip_id, status)

    def delete_floatingip(self, context, id):
        return super(NexusL3ServicePlugin, self).delete_floatingip(
            context, id)

    def dissassociate_floatingips(self, context, port_id):
        return super(NexusL3ServicePlugin, self).disassociate_floatingips(
            context, port_id)
