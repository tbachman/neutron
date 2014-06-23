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
# @author: Hareesh Puthalath, Cisco Systems, Inc.

import copy
import mock
from mock import call
from mock import patch
from oslo.config import cfg
import sys

from neutron.agent.common import config
from neutron.common import config as base_config
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.cfg_agent.cfg_agent import CiscoCfgAgent
from neutron.plugins.cisco.cfg_agent.cfg_exceptions import (
    CSR1kvConfigException)
# from neutron.plugins.cisco.cfg_agent.service_helpers.routing_svc_helper import(
#     CiscoRoutingPluginApi)
from neutron.plugins.cisco.cfg_agent.service_helpers.routing_svc_helper import(
    RouterInfo)
from neutron.plugins.cisco.cfg_agent.service_helpers.routing_svc_helper import(
    RoutingServiceHelper)


from neutron.tests import base


_uuid = uuidutils.generate_uuid
HOST = 'myhost'
FAKE_ID = _uuid()

LOG = logging.getLogger(__name__)


def prepare_router_data(enable_snat=None, num_internal_ports=1):
    router_id = _uuid()
    ex_gw_port = {'id': _uuid(),
                  'network_id': _uuid(),
                  'fixed_ips': [{'ip_address': '19.4.4.4',
                                 'subnet_id': _uuid()}],
                  'subnet': {'cidr': '19.4.4.0/24',
                             'gateway_ip': '19.4.4.1'}}
    int_ports = []
    for i in range(num_internal_ports):
        int_ports.append({'id': _uuid(),
                          'network_id': _uuid(),
                          'admin_state_up': True,
                          'fixed_ips': [{'ip_address': '35.4.%s.4' % i,
                                         'subnet_id': _uuid()}],
                          'mac_address': 'ca:fe:de:ad:be:ef',
                          'subnet': {'cidr': '35.4.%s.0/24' % i,
                                     'gateway_ip': '35.4.%s.1' % i}})
    hosting_device = {'id': _uuid(),
                      "name": "CSR1kv_template",
                      "booting_time": 300,
                      "host_category": "VM",
                      'management_ip_address': '20.0.0.5',
                      'protocol_port': 22,
                      "credentials": {
                          "username": "user",
                          "password": "4getme"},
                      }
    router = {
        'id': router_id,
        l3_constants.INTERFACE_KEY: int_ports,
        'routes': [],
        'gw_port': ex_gw_port,
        'hosting_device': hosting_device}
    if enable_snat is not None:
        router['enable_snat'] = enable_snat
    return router, int_ports


class TestRouterInfo(base.BaseTestCase):

    def setUp(self):
        super(TestRouterInfo, self).setUp()
        self.ex_gw_port = {'id': _uuid(),
                           'network_id': _uuid(),
                           'fixed_ips': [{'ip_address': '19.4.4.4',
                                          'subnet_id': _uuid()}],
                           'subnet': {'cidr': '19.4.4.0/24',
                                      'gateway_ip': '19.4.4.1'}}
        self.router = {'id': _uuid(),
                       'enable_snat': True,
                       'routes': [],
                       'gw_port': self.ex_gw_port}


    def test_router_info_create(self):
        id = _uuid()
        fake_router = {}
        ri = RouterInfo(id, fake_router)

        self.assertTrue(ri.router_name().endswith(id))

    def test_router_info_create_with_router(self):
        id = _uuid()
        ri = RouterInfo(id, self.router)
        self.assertTrue(ri.router_name().endswith(id))
        self.assertEqual(ri.router, self.router)
        self.assertEqual(ri._router, self.router)
        self.assertEqual(ri.snat_enabled, True)
        self.assertEqual(ri.ex_gw_port, None)

    def test_router_info_create_snat_disabled(self):
        id = _uuid()
        self.router['enable_snat'] = False
        ri = RouterInfo(id, self.router)
        self.assertEqual(ri.snat_enabled, False)


class TestBasicRoutingOperations(base.BaseTestCase):

    def setUp(self):
        super(TestBasicRoutingOperations, self).setUp()
        self.conf = cfg.ConfigOpts()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(CiscoCfgAgent.OPTS)
        self.ex_gw_port = {'id': _uuid(),
                           'network_id': _uuid(),
                           'fixed_ips': [{'ip_address': '19.4.4.4',
                                         'subnet_id': _uuid()}],
                           'subnet': {'cidr': '19.4.4.0/24',
                                      'gateway_ip': '19.4.4.1'}}
        self.hosting_device = {'id': "100",
                               'name': "CSR1kv_template",
                               'booting_time': 300,
                               'host_category': "VM",
                               'management_ip_address': '20.0.0.5',
                               'protocol_port': 22,
                               'credentials': {'username': 'user',
                                               "password": '4getme'},
                               }
        self.router = {
            'id': _uuid(),
            'enable_snat': True,
            'routes': [],
            'gw_port': self.ex_gw_port,
            'hosting_device': self.hosting_device}

        self.agent = mock.Mock()

        #Patches & Mocks

        self.l3pluginApi_cls_p = mock.patch(
            'neutron.plugins.cisco.cfg_agent.service_helpers.'
            'routing_svc_helper.CiscoRoutingPluginApi')
        l3pluginApi_cls = self.l3pluginApi_cls_p.start()
        self.plugin_api = mock.Mock()
        l3pluginApi_cls.return_value = self.plugin_api
        self.looping_call_p = mock.patch(
            'neutron.openstack.common.loopingcall.FixedIntervalLoopingCall')
        self.looping_call_p.start()
        mock.patch('neutron.openstack.common.rpc.create_connection').start()

        self.addCleanup(mock.patch.stopall)

    def _mock_driver_and_hosting_device(self, svc_helper):
        svc_helper._dev_status.is_hosting_device_reachable = mock.MagicMock(
            return_value=True)
        svc_helper._drivermgr.get_driver = mock.MagicMock()
        svc_helper._drivermgr.set_driver = mock.MagicMock()

    def test_process_router_throw_config_error(self):
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        self._mock_driver_and_hosting_device(routing_svc_helper)
        routing_svc_helper._internal_network_added = mock.Mock()
        snip_name = 'CREATE_SUBINTERFACE'
        e_type = 'Fake error'
        e_tag = 'Fake error tag'
        params = {'snippet': snip_name, 'type': e_type, 'tag': e_tag}
        routing_svc_helper._internal_network_added.side_effect = (
            CSR1kvConfigException(**params))
        router, ports = prepare_router_data()
        ri = RouterInfo(router['id'], router)
        self.assertRaises(CSR1kvConfigException,
                          routing_svc_helper._process_router, ri)
        routing_svc_helper._internal_network_added.reset_mock()

    def test_process_router(self):
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper._process_router_floating_ips = mock.Mock()
        routing_svc_helper._internal_network_added = mock.Mock()
        routing_svc_helper._external_gateway_added = mock.Mock()
        routing_svc_helper._internal_network_removed = mock.Mock()
        routing_svc_helper._external_gateway_removed = mock.Mock()
        self._mock_driver_and_hosting_device(routing_svc_helper)
        router, ports = prepare_router_data()
        fake_floatingips1 = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '8.8.8.8',
             'fixed_ip_address': '7.7.7.7',
             'port_id': _uuid()}]}
        ri = RouterInfo(router['id'], router=router)
        # Process with initial values
        routing_svc_helper._process_router(ri)
        ex_gw_port = ri.router.get('gw_port')
        # Assert that process_floating_ips, internal_network & external network
        # added were all called with the right params
        routing_svc_helper._process_router_floating_ips.assert_called_with(
            ri, ex_gw_port)
        routing_svc_helper._process_router_floating_ips.reset_mock()
        routing_svc_helper._internal_network_added.assert_called_with(
            ri, ports[0], ex_gw_port)
        routing_svc_helper._external_gateway_added.assert_called_with(
            ri, ex_gw_port)
        routing_svc_helper._internal_network_added.reset_mock()
        routing_svc_helper._external_gateway_added.reset_mock()
        # remap floating IP to a new fixed ip
        fake_floatingips2 = copy.deepcopy(fake_floatingips1)
        fake_floatingips2['floatingips'][0]['fixed_ip_address'] = '7.7.7.8'
        router[l3_constants.FLOATINGIP_KEY] = fake_floatingips2['floatingips']

        # Process again and check that this time only the process_floating_ips
        # was only called.
        routing_svc_helper._process_router(ri)
        ex_gw_port = ri.router.get('gw_port')
        routing_svc_helper._process_router_floating_ips.assert_called_with(
            ri, ex_gw_port)
        self.assertFalse(routing_svc_helper._internal_network_added.called)
        self.assertFalse(routing_svc_helper._external_gateway_added.called)
        routing_svc_helper._process_router_floating_ips.reset_mock()

        # remove just the floating ips
        del router[l3_constants.FLOATINGIP_KEY]
        # Process again and check that this time also only the
        # process_floating_ips and external_network remove was called
        routing_svc_helper._process_router(ri)
        ex_gw_port = ri.router.get('gw_port')
        routing_svc_helper._process_router_floating_ips.assert_called_with(
            ri, ex_gw_port)
        self.assertFalse(routing_svc_helper._internal_network_added.called)
        self.assertFalse(routing_svc_helper._external_gateway_added.called)
        routing_svc_helper._process_router_floating_ips.reset_mock()

        # now no ports so state is torn down
        del router[l3_constants.INTERFACE_KEY]
        del router['gw_port']
        # Update router_info object
        ri.router = router
        # Keep a copy of the ex_gw_port before its gone after processing.
        ex_gw_port = ri.ex_gw_port
        # Process router and verify that internal and external network removed
        # were called and floating_ips_process was called
        routing_svc_helper._process_router(ri)
        self.assertFalse(routing_svc_helper.
                         _process_router_floating_ips.called)
        self.assertFalse(routing_svc_helper._external_gateway_added.called)
        self.assertTrue(routing_svc_helper._internal_network_removed.called)
        self.assertTrue(routing_svc_helper._external_gateway_removed.called)
        routing_svc_helper._internal_network_removed.assert_called_with(
            ri, ports[0], ex_gw_port)
        routing_svc_helper._external_gateway_removed.assert_called_with(
            ri, ex_gw_port)

    def test_routing_table_update(self):
        router = self.router
        driver = mock.Mock()
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper._drivermgr.get_driver = mock.Mock(
            return_value=driver)
        fake_route1 = {'destination': '135.207.0.0/16',
                       'nexthop': '1.2.3.4'}
        fake_route2 = {'destination': '135.207.111.111/32',
                       'nexthop': '1.2.3.4'}

        # First we set the routes to fake_route1 and see if the
        # driver.routes_updated was called with 'replace'(==add or replace)
        # and fake_route1
        router['routes'] = [fake_route1]
        ri = RouterInfo(router['id'], router)
        routing_svc_helper._process_router(ri)

        driver.routes_updated.assert_called_with(ri, 'replace', fake_route1)

        # Now we replace fake_route1 with fake_route2. This should cause driver
        # to be invoked to delete fake_route1 and 'replace'(==add or replace)
        driver.reset_mock()
        router['routes'] = [fake_route2]
        ri.router = router
        routing_svc_helper._process_router(ri)

        driver.routes_updated.assert_called_with(ri, 'delete', fake_route1)
        driver.routes_updated.assert_any_call(ri, 'replace', fake_route2)

        # Now we add back fake_route1 as a new route, this should cause driver
        # to be invoked to 'replace'(==add or replace) fake_route1
        driver.reset_mock()
        router['routes'] = [fake_route2, fake_route1]
        ri.router = router
        routing_svc_helper._process_router(ri)

        driver.routes_updated.assert_any_call(ri, 'replace', fake_route1)

        # Now we delete all routes. This should cause driver
        # to be invoked to delete fake_route1 and fake-route2
        driver.reset_mock()
        router['routes'] = []
        ri.router = router
        routing_svc_helper._process_router(ri)

        driver.routes_updated.assert_any_call(ri, 'delete', fake_route2)
        driver.routes_updated.assert_any_call(ri, 'delete', fake_route1)

    def test_process_router_internal_network_added_unexpected_error(self):
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        self._mock_driver_and_hosting_device(routing_svc_helper)
        router, ports = prepare_router_data()
        ri = RouterInfo(router['id'], router=router)
        with mock.patch.object(
                RoutingServiceHelper,
                '_internal_network_added') as internal_network_added:
            # raise RuntimeError to simulate that an unexpected exception
            # occurrs
            internal_network_added.side_effect = RuntimeError
            self.assertRaises(RuntimeError,
                              routing_svc_helper._process_router,
                              ri)
            self.assertNotIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

            # The unexpected exception has been fixed manually
            internal_network_added.side_effect = None

            # Failure will cause a retry next time,
            # We were able to add the port to ri.internal_ports
            routing_svc_helper._process_router(ri)
            self.assertIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_process_router_internal_network_removed_unexpected_error(self):
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        self._mock_driver_and_hosting_device(routing_svc_helper)
        router, ports = prepare_router_data()
        ri = RouterInfo(router['id'], router=router)
        # add an internal port
        routing_svc_helper._process_router(ri)

        with mock.patch.object(
                RoutingServiceHelper,
                '_internal_network_removed') as internal_net_removed:
            # raise RuntimeError to simulate that an unexpected exception
            # occurrs
            internal_net_removed.side_effect = RuntimeError
            ri.internal_ports[0]['admin_state_up'] = False
            # The above port is set to down state, remove it.
            self.assertRaises(RuntimeError,
                              routing_svc_helper._process_router,
                              ri)
            self.assertIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

            # The unexpected exception has been fixed manually
            internal_net_removed.side_effect = None

            # Failure will cause a retry next time,
            # We were able to add the port to ri.internal_ports
            routing_svc_helper._process_router(ri)
            # We were able to remove the port from ri.internal_ports
            self.assertNotIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_routers_with_admin_state_down(self):
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        self.plugin_api.get_external_network_id.return_value = None

        routers = [
            {'id': _uuid(),
             'admin_state_up': False,
             'external_gateway_info': {}}]
        routing_svc_helper._process_routers(routers, None)
        self.assertNotIn(routers[0]['id'], routing_svc_helper.router_info)

    def test_router_deleted(self):
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper.router_deleted(None, FAKE_ID)
        self.assertIn(FAKE_ID, routing_svc_helper.removed_routers)

    def test_routers_updated(self):
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper.routers_updated(None, [FAKE_ID])
        self.assertIn(FAKE_ID, routing_svc_helper.updated_routers)

    def test_removed_from_agent(self):
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper.router_removed_from_agent(None, {'router_id': FAKE_ID})
        self.assertIn(FAKE_ID, routing_svc_helper.removed_routers)

    def test_added_to_agent(self):
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper.router_added_to_agent(None, [FAKE_ID])
        self.assertIn(FAKE_ID, routing_svc_helper.updated_routers)

    def test_process_router_delete(self):
        router = self.router
        router['gw_port'] = self.ex_gw_port
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        self._mock_driver_and_hosting_device(routing_svc_helper)
        routing_svc_helper._router_added(router['id'], router)
        self.assertIn(router['id'], routing_svc_helper.router_info)
        # Now we remove the router
        routing_svc_helper._router_removed(router['id'], deconfigure=True)
        self.assertNotIn(router['id'], routing_svc_helper.router_info)

    def test_collect_state(self):
        router, ports = prepare_router_data(enable_snat=True,
                                            num_internal_ports=2)
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        self._mock_driver_and_hosting_device(routing_svc_helper)
        routing_svc_helper._router_added(router['id'], router)

        configurations = {}
        configurations = routing_svc_helper.collect_state(configurations)
        hd_exp_result = {
            router['hosting_device']['id']: {'routers': 1}}
        self.assertEquals(1, configurations['total routers'])
        self.assertEquals(1, configurations['total ex_gw_ports'])
        self.assertEquals(2, configurations['total interfaces'])
        self.assertEquals(0, configurations['total floating_ips'])
        self.assertEquals(hd_exp_result, configurations['hosting_devices'])
        self.assertEquals([], configurations['non_responding_hosting_devices'])

    def test_sort_resources_per_hosting_device(self):
        router1, port = prepare_router_data()
        router2, port = prepare_router_data()
        router3, port = prepare_router_data()
        router4, port = prepare_router_data()

        hd1_id = router1['hosting_device']['id']
        hd2_id = router4['hosting_device']['id']
        #Setting router2 and router3 device id same as router1's device id
        router2['hosting_device']['id'] = hd1_id
        router3['hosting_device']['id'] = hd1_id

        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        resources = {'routers': [router1, router2, router4],
                     'removed_routers': [router3]}
        devices = (routing_svc_helper
                  ._sort_resources_per_hosting_device(resources))

        self.assertEquals(2, len(devices.keys()))  # Two devices
        hd1_routers = [router1, router2]
        self.assertEquals(hd1_routers, devices[hd1_id]['routers'])
        self.assertEquals([router3], devices[hd1_id]['removed_routers'])
        self.assertEquals([router4], devices[hd2_id]['routers'])

    def test_get_router_ids_from_removed_devices_info(self):
        removed_devices_info = {
            'hosting_data': {'device_1': {'routers': ['id1', 'id2']},
                             'device_2': {'routers': ['id3', 'id4'],
                                          'other_key': ['value1', 'value2']}}
        }
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        resp = routing_svc_helper._get_router_ids_from_removed_devices_info(
            removed_devices_info)
        self.assertItemsEqual(['id1', 'id2', 'id3', 'id4'], resp)

    @patch("eventlet.GreenPool.spawn_n")
    def test_process_services_full_sync_different_devices(self, mock_spawn):
        router1, port = prepare_router_data()
        router2, port = prepare_router_data()
        self.plugin_api.get_routers = mock.Mock(
            return_value=[router1, router2])
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper.process_service()
        self.assertEquals(2, mock_spawn.call_count)
        call1 = mock.call(routing_svc_helper._process_routers, [router1],
                          None, router1['hosting_device']['id'],
                          all_routers=True)
        call2 = mock.call(routing_svc_helper._process_routers, [router2],
                          None, router2['hosting_device']['id'],
                          all_routers=True)
        mock_spawn.assert_has_calls([call1, call2], any_order=True)

    @patch("eventlet.GreenPool.spawn_n")
    def test_process_services_full_sync_same_device(self, mock_spawn):
        router1, port = prepare_router_data()
        router2, port = prepare_router_data()
        router2['hosting_device']['id'] = router1['hosting_device']['id']
        self.plugin_api.get_routers = mock.Mock(return_value=[router1,
                                                              router2])
        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper.process_service()
        self.assertEquals(1, mock_spawn.call_count)
        mock_spawn.assert_called_with(routing_svc_helper._process_routers,
                                      [router1, router2],
                                      None,
                                      router1['hosting_device']['id'],
                                      all_routers=True)

    @patch("eventlet.GreenPool.spawn_n")
    def test_process_services_with_updated_routers(self, mock_spawn):

        router1, port = prepare_router_data()
        def routers_data(context, router_ids=None, hd_ids=[]):
            if router_ids:
                return [router1]
        self.plugin_api.get_routers.side_effect = routers_data

        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper.fullsync = False
        routing_svc_helper.updated_routers.add(router1['id'])
        routing_svc_helper.process_service()
        self.assertEquals(1, self.plugin_api.get_routers.call_count)
        self.plugin_api.get_routers.assert_called_with(
            routing_svc_helper.context,
            router_ids=[router1['id']])
        self.assertEquals(1, mock_spawn.call_count)
        mock_spawn.assert_called_with(routing_svc_helper._process_routers,
                                      [router1],
                                      None,
                                      router1['hosting_device']['id'],
                                      all_routers=False)

    @patch("eventlet.GreenPool.spawn_n")
    def test_process_services_with_deviceid(self, mock_spawn):

        router1, port = prepare_router_data()
        device_id = router1['hosting_device']['id']

        def routers_data(context, router_ids=None, hd_ids=[]):
            if hd_ids:
                self.assertEqual([device_id], hd_ids)
                return [router1]

        self.plugin_api.get_routers.side_effect = routers_data

        routing_svc_helper = RoutingServiceHelper(HOST, self.conf, self.agent)
        routing_svc_helper.fullsync = False
        # routing_svc_helper.updated_routers.add(router1['id'])
        routing_svc_helper.process_service(device_ids=[device_id])
        self.assertEquals(1, self.plugin_api.get_routers.call_count)
        self.plugin_api.get_routers.assert_called_with(
            routing_svc_helper.context,
            hd_ids=[device_id])
        self.assertEquals(1, mock_spawn.call_count)
        mock_spawn.assert_called_with(routing_svc_helper._process_routers,
                                      [router1],
                                      None,
                                      router1['hosting_device']['id'],
                                      all_routers=False)