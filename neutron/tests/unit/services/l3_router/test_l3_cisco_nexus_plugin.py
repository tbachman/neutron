# Copyright (c) 2014 Cisco Systems
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

import mock
from collections import namedtuple

from neutron import context
from neutron.extensions import portbindings
from neutron.plugins.ml2.drivers.cisco.nexus import config as cisco_config
from neutron.plugins.ml2.drivers.cisco.nexus import exceptions as cexc
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_db_v2 as nxdb
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_network_driver
from neutron.services.l3_router import l3_cisco_nexus
from neutron.tests import base
from neutron.tests.unit import test_db_plugin


ROUTER = 'router1'
SUBNET = 'subnet1'
NETWORK = 'network1'
NETWORK_NAME = 'one_network'
EXTERNAL_NETWORK = 'extnet'
SUBNET_GATEWAY = '10.3.2.1'
SUBNET_CIDR = '10.3.1.0/24'
ROUTER_EXTERNAL_GATEWAYS = ('192.168.1.1',)
FLOATING_IP_ADDRESS = '172.0.0.1'
VLAN = 100


class TestCiscoNexusL3Plugin(test_db_plugin.NeutronDbPluginV2TestCase,
                             base.BaseTestCase):

    def setUp(self):
        super(TestCiscoNexusL3Plugin, self).setUp()
        self.context = context.get_admin_context()

        self.interface_info = {'subnet_id': SUBNET,
                               'network_id': NETWORK,
                               'name': NETWORK_NAME,
                               'gateway_ip': SUBNET_GATEWAY,
                               'cidr': SUBNET_CIDR}
        self.router = {'router': {'name': ROUTER,
                                  'admin_state_up': True,
                                 }
                      }
        self.floatingip = {'floatingip': 
                            {'id':'abcdef',
                             'floating_ip_address': FLOATING_IP_ADDRESS,
                             'port_id': 'port1'}
                          }
        self.ports = [
                        {'id': 'port1',
                         'device_owner': 'compute:None',
                         portbindings.HOST_ID: 'host1',
                         'fixed_ips': [{
                            'ip_address': '10.0.0.1'
                         }]},
                        {'id': 'port2',
                         'device_owner': 'compute:None',
                         portbindings.HOST_ID: 'host2'}
                     ]

        # Mock the nexus switch dictionary and initialization method.
        # Don't need all switch values, just IP addresses for these tests.
        mock.patch.object(cisco_config.ML2MechCiscoConfig,
                          '__init__',
                          return_value=None).start()

        self.nexus_config = {('1.1.1.1', 'username'): 'admin',
                             ('1.1.1.1', 'host1'): '1/1',
                             ('2.2.2.2', 'username'): 'admin',
                             ('2.2.2.2', 'host2'): '1/2'}
        self.nexus_patch = mock.patch.dict(
            cisco_config.ML2MechCiscoConfig.nexus_dict,
            self.nexus_config)
        self.nexus_patch.start()
        self.addCleanup(self.nexus_patch.stop)

        # Mock nexus switch driver method called right before netconf calls.
        self.mock_edit_config = mock.Mock()
        mock.patch.object(nexus_network_driver.CiscoNexusDriver,
                          '_edit_config',
                          return_value=self.mock_edit_config).start()

        self.plugin = l3_cisco_nexus.CiscoNexusL3ServicePlugin()
        self.plugin.get_subnet = mock.Mock(return_value=self.interface_info)
        self.plugin.get_ports = mock.Mock(return_value=self.ports)
        self.plugin._get_vlanid = mock.Mock(return_value=VLAN)
        self.plugin.get_port = mock.Mock(return_value=self.ports[0])
        self.plugin.get_floatingip = mock.Mock(
            return_value=self.floatingip.get('floatingip'))
        self.plugin._get_router_gateways = mock.Mock(
            return_value=ROUTER_EXTERNAL_GATEWAYS)

        testclass = namedtuple('testclass', 'switch_ip gateway_ip')
        testobj = testclass(switch_ip=ROUTER_EXTERNAL_GATEWAYS[0], 
                            gateway_ip='1.1.1.1')

        mock.patch.object(nxdb,
                          'get_nexus_vrf_bindings',
                          return_value = (testobj,)).start()

        mock.patch('neutron.db.l3_gwmode_db.L3_NAT_db_mixin.'
                   'add_router_interface').start()
        mock.patch('neutron.db.l3_gwmode_db.L3_NAT_db_mixin.'
                   'remove_router_interface').start()
        mock.patch('neutron.db.l3_gwmode_db.L3_NAT_db_mixin.'
                   'update_floatingip').start()
        mock.patch('neutron.db.l3_gwmode_db.L3_NAT_db_mixin.'
                   'update_router').start()
        mock.patch('neutron.openstack.common.excutils.'
                   'save_and_reraise_exception').start()

    def _check_xml_keywords(self, expected_words, xml_words):
        if all(word in xml_words for word in expected_words):
            return True

    def test_create_router(self):
        with mock.patch('neutron.plugins.ml2.drivers.cisco.nexus.'
                        'nexus_db_v2.add_nexus_vrf'):
            db_router = self.plugin.create_router(self.context, self.router)
            router_id = db_router.get('id')
            nxdb.add_nexus_vrf.assert_called_once_with(
                self.context.session, router_id)

    def test_delete_router(self):
        with mock.patch('neutron.plugins.ml2.drivers.cisco.nexus.'
                        'nexus_db_v2.delete_nexus_vrf'):
            db_router = self.plugin.create_router(self.context, self.router)
            router_id = db_router.get('id')
            vrf_id = nxdb.get_nexus_vrf(self.context.session,
                                        router_id).get('vrf_id')
            self.plugin.delete_router(self.context, router_id)
            nxdb.delete_nexus_vrf.assert_called_once_with(
                self.context.session, vrf_id)

    def test_add_router_interface(self):
        driver = self.plugin.driver

        db_router = self.plugin.create_router(self.context, self.router)
        router_id = db_router.get('id')
        vrf_id = nxdb.get_nexus_vrf(self.context.session,
                                        router_id).get('vrf_id')
        self.plugin.add_router_interface(self.context, router_id,
                                         self.interface_info)
        self.assertTrue(self._check_xml_keywords([vrf_id],
            driver._edit_config.mock_calls[0][2]['config']))

    def test_remove_router_interface(self):
        driver = self.plugin.driver

        db_router = self.plugin.create_router(self.context, self.router)
        router_id = db_router.get('id')
        vrf_id = nxdb.get_nexus_vrf(self.context.session,
                                    router_id).get('vrf_id')
        self.plugin.add_router_interface(self.context, router_id,
                                         self.interface_info)
        self.plugin.remove_router_interface(self.context, router_id,
                                            self.interface_info)
        self.assertTrue(self._check_xml_keywords([vrf_id],
            driver._edit_config.mock_calls[0][2]['config']))

    def test_update_floatingip_with_port_assoc(self):
        driver = self.plugin.driver

        with mock.patch('neutron.plugins.ml2.drivers.cisco.nexus.'
                        'nexus_db_v2.delete_nexus_vrf'):
            fip_id = self.floatingip['floatingip']['id']
            pid = self.ports[0].get('fixed_ips')[0].get('ip_address')
            self.plugin.update_floatingip(self.context,
                                          fip_id,
                                          self.floatingip)
            self.assertTrue(
                self._check_xml_keywords(
                    [FLOATING_IP_ADDRESS, pid],
                    driver._edit_config.mock_calls[0][2]['config']))

    def test_update_floatingip_without_port_assoc(self):
        driver = self.plugin.driver

        with mock.patch('neutron.plugins.ml2.drivers.cisco.nexus.'
                        'nexus_db_v2.delete_nexus_vrf'):
            del self.floatingip['floatingip']['port_id']
            fip_id = self.floatingip['floatingip']['id']
            self.plugin.update_floatingip(self.context,
                                          fip_id,
                                          self.floatingip)
            self.assertTrue(
                self._check_xml_keywords(
                    [FLOATING_IP_ADDRESS],
                    driver._edit_config.mock_calls[0][2]['config']))

    def test_update_router_with_external_gateway(self):
        driver = self.plugin.driver

        db_router = self.plugin.create_router(self.context, self.router)
        router_id = db_router.get('id')
        vrf_id = nxdb.get_nexus_vrf(self.context.session,
                                    router_id).get('vrf_id')
        self.router['router']['external_gateway_info'] = {
            'network_id': EXTERNAL_NETWORK
        }
        self.plugin.update_router(self.context, router_id, self.router)
        self.assertTrue(
                self._check_xml_keywords(
                    [vrf_id, ROUTER_EXTERNAL_GATEWAYS[0]],
                    driver._edit_config.mock_calls[0][2]['config']))

    def test_update_router_without_external_gateway(self):
        driver = self.plugin.driver

        db_router = self.plugin.create_router(self.context, self.router)
        router_id = db_router.get('id')
        vrf_id = nxdb.get_nexus_vrf(self.context.session,
                                    router_id).get('vrf_id')
        self.plugin.update_router(self.context, router_id, self.router)
        self.assertTrue(
                self._check_xml_keywords(
                    [vrf_id, ROUTER_EXTERNAL_GATEWAYS[0]],
                    driver._edit_config.mock_calls[0][2]['config']))
