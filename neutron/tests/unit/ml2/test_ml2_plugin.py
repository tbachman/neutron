# Copyright (c) 2013 OpenStack Foundation
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

from oslo.config import cfg

from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import providernet as pnet
from neutron.plugins.ml2 import config as config
from neutron.plugins.ml2.drivers import type_vlan
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extension_ext_gw_mode


PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class Ml2PluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = PLUGIN_NAME

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'test'],
                                     group='ml2')
        self.physnet = 'physnet1'
        self.vlan_range = '1:100'
        phys_vrange = ':'.join([self.physnet, self.vlan_range])
        cfg.CONF.set_override('network_vlan_ranges', [phys_vrange],
                                     group='ml2_type_vlan')
        self.addCleanup(cfg.CONF.reset)
        super(Ml2PluginV2TestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'


class TestMl2BasicGet(test_plugin.TestBasicGet,
                      Ml2PluginV2TestCase):
    pass


class TestMl2V2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            Ml2PluginV2TestCase):
    pass


class TestMl2NetworksV2(test_plugin.TestNetworksV2,
                        Ml2PluginV2TestCase):
    pass


class TestMl2PortsV2(test_plugin.TestPortsV2, Ml2PluginV2TestCase):

    def test_update_port_status_build(self):
        with self.port() as port:
            self.assertEqual(port['port']['status'], 'DOWN')
            self.assertEqual(self.port_create_status, 'DOWN')


# TODO(rkukura) add TestMl2PortBinding


# TODO(rkukura) add TestMl2PortBindingNoSG


class TestMl2PortBindingHost(Ml2PluginV2TestCase,
                             test_bindings.PortBindingsHostTestCaseMixin):
    pass


class TestMl2ExtGwModeSupport(Ml2PluginV2TestCase,
                              test_extension_ext_gw_mode.ExtGwModeTestCase):
    pass


class TestMultiSegmentNetworks(Ml2PluginV2TestCase):

    def setUp(self, plugin=None):
        super(TestMultiSegmentNetworks, self).setUp()

    def test_create_network_provider(self):
        data = {'network': {'name': 'net1',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        self.assertEqual(network['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(network['network'][pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(network['network'][pnet.SEGMENTATION_ID], 1)
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

    def test_create_network_single_multiple_provider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        net_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        for provider_field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                               pnet.SEGMENTATION_ID]:
            self.assertTrue(provider_field not in network['network'])
        tz = network['network'][mpnet.SEGMENTS][0]
        self.assertEqual(tz[pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(tz[pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(tz[pnet.SEGMENTATION_ID], 1)

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS][0]
        self.assertEqual(tz[pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(tz[pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(tz[pnet.SEGMENTATION_ID], 1)

    def test_create_network_multprovider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                            {pnet.NETWORK_TYPE: 'gre',
                             pnet.PHYSICAL_NETWORK: 'physnet1'}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS]
        for tz in data['network'][mpnet.SEGMENTS]:
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(tz.get(field), tz.get(field))

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS]
        for tz in data['network'][mpnet.SEGMENTS]:
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(tz.get(field), tz.get(field))

    def test_create_network_with_provider_and_multiprovider_fail(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}

        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(res.status_int, 400)

    def test_create_network_duplicate_segments(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                            {pnet.NETWORK_TYPE: 'vlan',
                             pnet.PHYSICAL_NETWORK: 'physnet1',
                             pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(res.status_int, 400)
