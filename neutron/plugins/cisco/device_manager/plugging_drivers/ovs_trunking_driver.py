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

from oslo_log import log as logging

from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.i18n import _LE
from neutron.plugins.cisco.device_manager.plugging_drivers import (
    n1kv_plugging_constants as n1kv_const)
from neutron.plugins.cisco.device_manager.plugging_drivers import (
    n1kv_trunking_driver)

LOG = logging.getLogger(__name__)


TRUNKED_NETWORKS = 'trunkport:trunked_networks'


class OvsTrunkingPlugDriver(n1kv_trunking_driver.N1kvTrunkingPlugDriver):
    """This is a driver class for service VMs.

    It is used together with a patched version of the Openvswitch plugin that
    supports VLAN trunking.
    """
    def create_hosting_device_resources(self, context, complementary_id,
                                        tenant_id, mgmt_context, max_hosted):
        mgmt_port = None
        t1_n, t1_sn, t2_n, t2_sn, t_p = [], [], [], [], []
        if (mgmt_context and mgmt_context.get('mgmt_nw_id') and
                mgmt_context.get('mgmt_sec_grp_id') and tenant_id):
            # Create port for mgmt interface
            p_spec = {'port': {
                'tenant_id': tenant_id,
                'admin_state_up': True,
                'name': 'mgmt',
                'network_id': mgmt_context['mgmt_nw_id'],
                'mac_address': attributes.ATTR_NOT_SPECIFIED,
                'fixed_ips': self._mgmt_subnet_spec(context, mgmt_context),
                'security_groups': [mgmt_context['mgmt_sec_grp_id']],
                'device_id': "",
                # Use device_owner attribute to ensure we can query for these
                # ports even before Nova has set device_id attribute.
                'device_owner': complementary_id}}
            try:
                mgmt_port = self._core_plugin.create_port(context,
                                                          p_spec)
                # No security groups on the trunk ports since
                # they have no IP address
                p_spec['port']['security_groups'] = []
                # The trunk networks
                n_spec = {'network': {'tenant_id': tenant_id,
                                      'admin_state_up': True,
                                      'name': n1kv_const.T1_NETWORK_NAME,
                                      'shared': False,
                                      TRUNKED_NETWORKS: {}}}
                # Until Nova allows spinning up VMs with VIFs on
                # networks without subnet(s) we create "dummy" subnets
                # for the trunk networks
                s_spec = {'subnet': {
                    'tenant_id': tenant_id,
                    'admin_state_up': True,
                    'cidr': n1kv_const.SUBNET_PREFIX,
                    'enable_dhcp': False,
                    'gateway_ip': attributes.ATTR_NOT_SPECIFIED,
                    'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                    'ip_version': 4,
                    'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                    'host_routes': attributes.ATTR_NOT_SPECIFIED}}
                for i in xrange(max_hosted):
                    # Create T1 trunk network for this router
                    self._create_resources(
                        context, "T1", i, n_spec, n1kv_const.T1_NETWORK_NAME,
                        t1_n, s_spec, n1kv_const.T1_SUBNET_NAME, t1_sn,
                        p_spec, n1kv_const.T1_PORT_NAME, t_p)
                    # Create T2 trunk network for this router
                    self._create_resources(
                        context, "T2", i, n_spec, n1kv_const.T2_NETWORK_NAME,
                        t2_n, s_spec, n1kv_const.T2_SUBNET_NAME, t2_sn,
                        p_spec, n1kv_const.T2_PORT_NAME, t_p)
            except n_exc.NeutronException as e:
                LOG.error(_LE('Error %s when creating service VM resources. '
                            'Cleaning up.'), e)
                resources = {'ports': t_p, 'networks': t1_n + t2_n,
                             'subnets': t1_sn + t2_sn}
                self.delete_hosting_device_resources(
                    context, tenant_id, mgmt_port, **resources)
                mgmt_port = None
                t1_n, t1_sn, t2_n, t2_sn, t_p = [], [], [], [], []
        return {'mgmt_port': mgmt_port,
                'ports': t_p,
                'networks': t1_n + t2_n,
                'subnets': t1_sn + t2_sn}

    def _create_resources(self, context, type_name, resource_index,
                          n_spec, net_namebase, t_n,
                          s_spec, subnet_namebase, t_sn,
                          p_spec, port_namebase, t_p):
        index = str(resource_index + 1)
        # Create trunk network
        n_spec['network'].update({'name': net_namebase + index})
        t_n.append(self._core_plugin.create_network(context, n_spec))
        LOG.debug('Created %(t_n)s network with name %(name)s and id %(id)s',
                  {'t_n': type_name, 'name': n_spec['network']['name'],
                   'id': t_n[resource_index]['id']})
        # Create dummy subnet for the trunk network
        s_spec['subnet'].update({'name': subnet_namebase + index,
                                'network_id': t_n[resource_index]['id']})
        t_sn.append(self._core_plugin.create_subnet(context, s_spec))
        # Create port for on trunk network
        p_spec['port'].update({'name': port_namebase + index,
                               'network_id': t_n[resource_index]['id']})
        t_p.append(self._core_plugin.create_port(context, p_spec))
        LOG.debug('Created %(t_n)s port with name %(name)s, id %(id)s on '
                  'subnet %(subnet)s',
                  {'t_n': type_name, 'name': t_n[resource_index]['name'],
                   'id': t_n[resource_index]['id'],
                   'subnet': t_sn[resource_index]['id']})

    def setup_logical_port_connectivity(self, context, port_db,
                                        hosting_device_id):
        # Remove the VLAN from the VLANs that the hosting port trunks.
        if (port_db is None or port_db.hosting_info is None or
                port_db.hosting_info.hosting_port is None):
            return
        mappings = self._get_trunk_mappings(
            context, port_db.hosting_info.hosting_port['id'])
        mappings[port_db['network_id']] = port_db.hosting_info.segmentation_tag
        network_dict = {'network': {TRUNKED_NETWORKS: mappings}}
        self._core_plugin.update_network(
            context.elevated(),
            port_db.hosting_info.hosting_port['network_id'],
            network_dict)

    def teardown_logical_port_connectivity(self, context, port_db,
                                        hosting_device_id):
        # Remove the VLAN from the VLANs that the hosting port trunks.
        if (port_db is None or port_db.hosting_info is None or
                port_db.hosting_info.hosting_port is None):
            return
        mappings = self._get_trunk_mappings(
            context, port_db.hosting_info.hosting_port['id'])
        mappings.pop(port_db['network_id'])
        network_dict = {'network': {TRUNKED_NETWORKS: mappings}}
        self._core_plugin.update_network(
            context.elevated(),
            port_db.hosting_info.hosting_port['network_id'],
            network_dict)
