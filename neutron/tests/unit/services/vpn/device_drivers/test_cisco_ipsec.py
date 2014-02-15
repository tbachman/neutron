# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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
import httplib
import mock

from neutron import context
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.vpn.device_drivers import cisco_ipsec as ipsec_driver
from neutron.tests import base

_uuid = uuidutils.generate_uuid
FAKE_HOST = 'fake_host'
FAKE_ROUTER_ID = _uuid()
FAKE_VPN_SERVICE = {
    'id': _uuid(),
    'router_id': FAKE_ROUTER_ID,
    'admin_state_up': True,
    'status': constants.PENDING_CREATE,
    'subnet': {'cidr': '10.0.0.0/24'},
    'ipsec_site_connections': [
        {'peer_cidrs': ['20.0.0.0/24',
                        '30.0.0.0/24']},
        {'peer_cidrs': ['40.0.0.0/24',
                        '50.0.0.0/24']}]
}

CSR_REST_CLIENT = ('neutron.services.vpn.device_drivers.'
                   'cisco_csr_rest_client.CsrRestClient')


class TestIPsecDeviceDriver(base.BaseTestCase):
    def setUp(self, driver=ipsec_driver.CiscoCsrIPsecDriver):
        super(TestIPsecDeviceDriver, self).setUp()
        self.addCleanup(mock.patch.stopall)
        for klass in ['neutron.openstack.common.rpc.create_connection',
                      'neutron.context.get_admin_context_without_session',
                      'neutron.openstack.common.'
                      'loopingcall.FixedIntervalLoopingCall']:
            mock.patch(klass).start()
        mock.patch(CSR_REST_CLIENT, autospec=True).start()
        self.agent = mock.Mock()
        self.driver = ipsec_driver.CiscoCsrIPsecDriver(self.agent, FAKE_HOST)
        self.driver.agent_rpc = mock.Mock()
        self.driver.csr.status = 201  # All calls succeed
        self.conn_info = {
            'id': '123',
            'psk': 'secret',
            'peer_address': '192.168.1.2',
            'peer_cidrs': ['10.1.0.0/24', '10.2.0.0/24'],
            'mtu': 1500,
            'ike_policy': {'auth_algorithm': 'sha1',
                           'encryption_algorithm': 'aes-128',
                           'pfs': 'Group5',
                           'ike_version': 'v1',
                           'lifetime_units': 'seconds',
                           'lifetime_value': 3600},
            'ipsec_policy': {'transform_protocol': 'ah',
                             'encryption_algorithm': 'aes-128',
                             'auth_algorithm': 'sha1',
                             'pfs': 'group5',
                             'lifetime_units': 'seconds',
                             'lifetime_value': 3600},
            'cisco': {'site_conn_id': 'Tunnel0',
                      'ike_policy_id': 222,
                      'ipsec_policy_id': 333,
                      # TODO(pcm) get from vpnservice['external_ip']
                      'router_public_ip': '172.24.4.23'}
        }

    def test_create_ipsec_site_connection(self):
        """Ensure all steps are done to create an IPSec site connection.

        Verify that each of the driver calls occur (in order), and
        the right information is stored for later deletion.
        """
        expected = ['make_route_id',
                    'make_route_id',
                    'create_pre_shared_key',
                    'create_ike_policy',
                    'create_ipsec_policy',
                    'create_ipsec_connection',
                    'create_static_route',
                    'create_static_route']
        expected_rollback_steps = [
            ipsec_driver.RollbackStep(action='pre_shared_key',
                                      resource_id='123',
                                      title='Pre-Shared Key'),
            ipsec_driver.RollbackStep(action='ike_policy',
                                      resource_id=222,
                                      title='IKE Policy'),
            ipsec_driver.RollbackStep(action='ipsec_policy',
                                      resource_id=333,
                                      title='IPSec Policy'),
            ipsec_driver.RollbackStep(action='ipsec_connection',
                                      resource_id='Tunnel0',
                                      title='IPSec Connection'),
            ipsec_driver.RollbackStep(action='static_route',
                                      resource_id='10.1.0.0_24_Tunnel0',
                                      title='Static Route'),
            ipsec_driver.RollbackStep(action='static_route',
                                      resource_id='10.2.0.0_24_Tunnel0',
                                      title='Static Route')]
        self.driver.csr.make_route_id.side_effect = ['10.1.0.0_24_Tunnel0',
                                                     '10.2.0.0_24_Tunnel0']
        self.driver.create_ipsec_site_connection(mock.Mock(), self.conn_info)
        client_calls = [c[0] for c in self.driver.csr.method_calls]
        self.assertEqual(expected, client_calls)
        self.assertEqual(
            expected_rollback_steps,
            self.driver.connections[self.conn_info['id']])

    def test_create_ipsec_site_connection_with_rollback(self):
        """Failure test of IPSec site conn creation that fails and rolls back.

        Simulate a failure in the last create step (making routes for the
        peer networks), and ensure that the create steps are called in
        order (except for create_static_route), and that the delete
        steps are called in reverse order. At the end, there should be no
        rollback infromation for the connection.
        """
        def fake_route_check_fails(*args, **kwargs):
            if args[0] == 'Static Route':
                # So that subsequent calls to CSR rest client (for rollback)
                # will fake as passing.
                self.driver.csr.status = httplib.NO_CONTENT
                raise ipsec_driver.CsrResourceCreateFailure(resource=args[0],
                                                            which=args[1])

        with mock.patch.object(ipsec_driver.CiscoCsrIPsecDriver,
                               '_check_create',
                               side_effect=fake_route_check_fails):

            expected = ['make_route_id',
                        'make_route_id',
                        'create_pre_shared_key',
                        'create_ike_policy',
                        'create_ipsec_policy',
                        'create_ipsec_connection',
                        'create_static_route',
                        'delete_ipsec_connection',
                        'delete_ipsec_policy',
                        'delete_ike_policy',
                        'delete_pre_shared_key']
            self.driver.create_ipsec_site_connection(mock.Mock(),
                                                     self.conn_info)
            client_calls = [c[0] for c in self.driver.csr.method_calls]
            self.assertEqual(expected, client_calls)
            self.assertNotIn('123', self.driver.connections)

    def test_create_verification_with_error(self):
        """Negative test of create check step had failed."""
        self.driver.csr.status = httplib.NOT_FOUND
        self.assertRaises(ipsec_driver.CsrResourceCreateFailure,
                          self.driver._check_create, 'name', 'id')

    def test_failure_with_invalid_create_step(self):
        """Negative test of invalid create step (programming error)."""
        self.driver.steps = []
        try:
            self.driver.do_create_action('bogus', None, '123', 'Bogus Step')
        except ipsec_driver.CsrResourceCreateFailure:
            pass
        else:
            self.fail('Expected exception with invalid create step')

    def test_failure_with_invalid_delete_step(self):
        """Negative test of invalid delete step (programming error)."""
        self.driver.steps = [ipsec_driver.RollbackStep(action='bogus',
                                                       resource_id='123',
                                                       title='Bogus Step')]
        try:
            self.driver.do_rollback()
        except ipsec_driver.CsrResourceCreateFailure:
            pass
        else:
            self.fail('Expected exception with invalid delete step')

    def test_delete_ipsec_connection(self):
        # TODO(pcm) implement
        pass


class TestCsrIPsecDeviceDriverCreateTransforms(base.BaseTestCase):

    """Verifies that config info is prepared/transformed correctly."""

    def setUp(self):
        super(TestCsrIPsecDeviceDriverCreateTransforms, self).setUp()
        self.addCleanup(mock.patch.stopall)
        for klass in ['neutron.openstack.common.rpc.create_connection',
                      'neutron.context.get_admin_context_without_session',
                      'neutron.openstack.common.'
                      'loopingcall.FixedIntervalLoopingCall']:
            mock.patch(klass).start()
        mock.patch(CSR_REST_CLIENT, autospec=True).start()
        self.agent = mock.Mock()
        self.driver = ipsec_driver.CiscoCsrIPsecDriver(self.agent, FAKE_HOST)
        self.driver.agent_rpc = mock.Mock()
        self.conn_info = {
            'id': '123',
            'psk': 'secret',
            'peer_address': '192.168.1.2',
            'peer_cidrs': ['10.1.0.0/24', '10.2.0.0/24'],
            'mtu': 1500,
            'ike_policy': {'auth_algorithm': 'sha1',
                           'encryption_algorithm': 'aes-128',
                           'pfs': 'Group5',
                           'ike_version': 'v1',
                           'lifetime_units': 'seconds',
                           'lifetime_value': 3600},
            'ipsec_policy': {'transform_protocol': 'ah',
                             'encryption_algorithm': 'aes-128',
                             'auth_algorithm': 'sha1',
                             'pfs': 'group5',
                             'lifetime_units': 'seconds',
                             'lifetime_value': 3600},
            'cisco': {'site_conn_id': 'Tunnel0',
                      'ike_policy_id': 222,
                      'ipsec_policy_id': 333,
                      # TODO(pcm) get from vpnservice['external_ip']
                      'router_public_ip': '172.24.4.23'}
        }

    def test_invalid_attribute(self):
        """Negative test of unknown attribute - programming error."""
        self.assertRaises(ipsec_driver.CsrDriverMismatchError,
                          self.driver.translate_dialect,
                          'ike_policy', 'unknown_attr', self.conn_info)

    def test_driver_unknown_mapping(self):
        """Negative test of service driver providing unknown value to map."""
        self.conn_info['ike_policy']['pfs'] = "unknown_value"
        self.assertRaises(ipsec_driver.CsrUnknownMappingError,
                          self.driver.translate_dialect,
                          'ike_policy', 'pfs', self.conn_info['ike_policy'])

    def test_psk_create_info(self):
        """Ensure that pre-shared key info is created correctly."""
        expected = {u'keyring-name': '123',
                    u'pre-shared-key-list': [
                        {u'key': 'secret',
                         u'encrypted': False,
                         u'peer-address': '192.168.1.2'}]}
        psk_id = self.conn_info['id']
        psk_info = self.driver.create_psk_info(psk_id, self.conn_info)
        self.assertEqual(expected, psk_info)

    def test_create_ike_policy_info(self):
        """Ensure that IKE policy info is mapped/created correctly."""
        expected = {u'priority-id': 222,
                    u'encryption': u'aes',
                    u'hash': u'sha',
                    u'dhGroup': 5,
                    u'version': u'v1',
                    u'lifetime': 3600}
        policy_id = self.conn_info['cisco']['ike_policy_id']
        policy_info = self.driver.create_ike_policy_info(policy_id,
                                                         self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_create_ike_policy_info_non_defaults(self):
        """Ensure that IKE policy info with different values."""
        self.conn_info['ike_policy'] = {
            'auth_algorithm': 'sha1',
            'encryption_algorithm': 'aes-256',
            'pfs': 'Group14',
            'ike_version': 'v1',
            'lifetime_units': 'seconds',
            'lifetime_value': 60
        }
        expected = {u'priority-id': 222,
                    u'encryption': u'aes',  # TODO(pcm): fix
                    u'hash': u'sha',
                    u'dhGroup': 14,
                    u'version': u'v1',
                    u'lifetime': 60}
        policy_id = self.conn_info['cisco']['ike_policy_id']
        policy_info = self.driver.create_ike_policy_info(policy_id,
                                                         self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_ipsec_policy_info(self):
        """Ensure that IPSec policy info is mapped/created correctly."""
        expected = {u'policy-id': 333,
                    u'protection-suite': {
                        u'esp-encryption': u'esp-aes',
                        u'esp-authentication': u'esp-sha-hmac',
                        u'ah': u'ah-sha-hmac'
                    },
                    u'lifetime-sec': 3600,
                    u'pfs': u'group5',
                    u'anti-replay-window-size': u'64'}
        ipsec_policy_id = self.conn_info['cisco']['ipsec_policy_id']
        policy_info = self.driver.create_ipsec_policy_info(ipsec_policy_id,
                                                           self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_ipsec_policy_info_non_defaults(self):
        """Create/map IPSec policy info with different values."""
        self.conn_info['ipsec_policy'] = {'transform_protocol': 'esp',
                                          'encryption_algorithm': '3des',
                                          'auth_algorithm': 'sha1',
                                          'pfs': 'group14',
                                          'lifetime_units': 'seconds',
                                          'lifetime_value': 120}
        expected = {u'policy-id': 333,
                    u'protection-suite': {
                        u'esp-encryption': u'esp-3des',
                        u'esp-authentication': u'esp-sha-hmac'
                    },
                    u'lifetime-sec': 120,
                    u'pfs': u'group14',
                    u'anti-replay-window-size': u'64'}
        ipsec_policy_id = self.conn_info['cisco']['ipsec_policy_id']
        policy_info = self.driver.create_ipsec_policy_info(ipsec_policy_id,
                                                           self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_site_connection_info(self):
        """Ensure site-to-site connection info is created/mapped correctly."""
        expected = {u'vpn-interface-name': 'Tunnel0',
                    u'ipsec-policy-id': 333,
                    u'local-device': {
                        u'ip-address': u'GigabitEthernet3',
                        u'tunnel-ip-address': u'172.24.4.23'
                    },
                    u'remote-device': {
                        u'tunnel-ip-address': '192.168.1.2'
                    },
                    u'mtu': 1500}
        ipsec_policy_id = self.conn_info['cisco']['ipsec_policy_id']
        site_conn_id = self.conn_info['cisco']['site_conn_id']
        conn_info = self.driver.create_site_connection_info(site_conn_id,
                                                            ipsec_policy_id,
                                                            self.conn_info)
        self.assertEqual(expected, conn_info)

    def test_static_route_info(self):
        """Create static route info for peer CIDRs."""
        expected = [('10.1.0.0_24_Tunnel0',
                     {u'destination-network': '10.1.0.0/24',
                      u'outgoing-interface': 'Tunnel0'}),
                    ('10.2.0.0_24_Tunnel0',
                     {u'destination-network': '10.2.0.0/24',
                      u'outgoing-interface': 'Tunnel0'})]
        self.driver.csr.make_route_id.side_effect = ['10.1.0.0_24_Tunnel0',
                                                     '10.2.0.0_24_Tunnel0']
        site_conn_id = self.conn_info['cisco']['site_conn_id']
        routes_info = self.driver.create_routes_info(site_conn_id,
                                                     self.conn_info)
        self.assertEqual(2, len(routes_info))
        self.assertEqual(expected, routes_info)


class TestCsrIPsecDeviceDriverSyncStatuses(base.BaseTestCase):

    """Test status/state of services and connections, after sync."""

    def setUp(self):
        super(TestCsrIPsecDeviceDriverSyncStatuses, self).setUp()
        self.addCleanup(mock.patch.stopall)
        for klass in ['neutron.openstack.common.rpc.create_connection',
                      'neutron.context.get_admin_context_without_session',
                      'neutron.openstack.common.'
                      'loopingcall.FixedIntervalLoopingCall']:
            mock.patch(klass).start()
        mock.patch(CSR_REST_CLIENT, autospec=True).start()
        self.context = context.Context('some_user', 'some_tenant')
        self.agent = mock.Mock()
        self.driver = ipsec_driver.CiscoCsrIPsecDriver(self.agent, FAKE_HOST)
        self.driver.agent_rpc = mock.Mock()
        self.driver.create_ipsec_site_connection = mock.Mock()
        self.driver.delete_ipsec_site_connection = mock.Mock()

    def _get_service_status(self, service_id):
        return self.driver.service_state[service_id].last_status

    def _get_conn_status(self, service_id, conn_id):
        service_state = self.driver.service_state[service_id]
        return service_state.conn_state[conn_id]['last_status']

    def test_sync_for_first_connection_create(self):
        """Sync creating first IPSec connection for a VPN service."""
        conn1 = {'id': '1', 'status': constants.PENDING_CREATE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [{
            'id': '123',
            'status': constants.PENDING_CREATE,
            'ipsec_conns': [conn1, ]
        }]
        self.driver.perform_pending_operations(self.context)
        self.assertEqual(1,
                         self.driver.create_ipsec_site_connection.call_count)
        self.assertEqual(constants.PENDING_CREATE,
                         self._get_service_status('123'))
        self.assertEqual(constants.PENDING_CREATE,
                         self._get_conn_status('123', '1'))

    def test_report_first_connection_create(self):
        """Report generation for first connection create on service."""
        # Simulate connection is requesting create on new service
        conn1 = {'id': '1', 'status': constants.PENDING_CREATE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        service = {'id': '123', 'status': constants.PENDING_CREATE}
        self.driver.snapshot_service_state(service)
        self.driver.service_state['123'].snapshot_conn_state(conn1)
        # Simulate CSR status of new connection active
        self.driver.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-ACTIVE'), ]

        self.driver.report_status(self.context)
        self.assertEqual(constants.ACTIVE, self._get_conn_status('123', '1'))
        self.assertEqual(constants.ACTIVE, self._get_service_status('123'))
        expected_report = [{
            'id': '123',
            'updated_pending_status': True,
            'status': constants.ACTIVE,
            'ipsec_site_connections': {
                '1': {'status': constants.ACTIVE,
                      'updated_pending_status': True}
            }
        }]
        self.driver.agent_rpc.update_status.assert_called_once_with(
            self.context, expected_report)

    def test_report_first_connection_create_failed(self):
        """Failure test of first connection create failing for service."""
        # Simulate connection is requesting create on new service
        conn1 = {'id': '1', 'status': constants.PENDING_CREATE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        service = {'id': '123', 'status': constants.PENDING_CREATE}
        self.driver.snapshot_service_state(service)
        self.driver.service_state['123'].snapshot_conn_state(conn1)
        # Simulate CSR status showing no connections
        self.driver.csr.read_tunnel_statuses.return_value = []

        self.driver.report_status(self.context)
        self.assertEqual(constants.ERROR, self._get_conn_status('123', '1'))
        self.assertEqual(constants.DOWN, self._get_service_status('123'))
        expected_report = [{
            'id': '123',
            'updated_pending_status': True,
            'status': constants.DOWN,
            'ipsec_site_connections': {
                '1': {'status': constants.ERROR,
                      'updated_pending_status': True}
            }
        }]
        self.driver.agent_rpc.update_status.assert_called_once_with(
            self.context, expected_report)

    def test_sync_second_connection_create_for_service(self):
        """Second connection create on existing service."""
        conn1 = {'id': '1', 'status': constants.ACTIVE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        conn2 = {'id': '2', 'status': constants.PENDING_CREATE,
                 'cisco': {'site_conn_id': u'Tunnel1'}}
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [{
            'id': '123',
            'status': constants.ACTIVE,
            'ipsec_conns': [conn1, conn2]
        }]
        self.driver.perform_pending_operations(self.context)
        self.assertEqual(1,
                         self.driver.create_ipsec_site_connection.call_count)
        self.assertEqual(constants.ACTIVE, self._get_conn_status('123', '1'))
        self.assertEqual(constants.PENDING_CREATE,
                         self._get_conn_status('123', '2'))
        self.assertEqual(constants.ACTIVE, self._get_service_status('123'))

    def test_report_second_connection_create(self):
        """Report generation for second connection create on service.

        On an existing VPN service, a second connection is created and has
        become active. The first connection, has gone from active to down,
        showing a state change too.
        """
        # Simulate first connection active, second requesting create
        conn1 = {'id': '1', 'status': constants.ACTIVE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        conn2 = {'id': '2', 'status': constants.PENDING_CREATE,
                 'cisco': {'site_conn_id': u'Tunnel1'}}
        service = {'id': '123', 'status': constants.ACTIVE}
        self.driver.snapshot_service_state(service)
        self.driver.service_state['123'].snapshot_conn_state(conn1)
        self.driver.service_state['123'].snapshot_conn_state(conn2)
        # Simulate CSR status shows conn1 went down and conn2 is active
        self.driver.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'DOWN'), (u'Tunnel1', u'UP-IDLE')]

        self.driver.report_status(self.context)
        self.assertEqual(constants.DOWN, self._get_conn_status('123', '1'))
        self.assertEqual(constants.ACTIVE, self._get_conn_status('123', '2'))
        self.assertEqual(constants.ACTIVE, self._get_service_status('123'))
        expected_report = [{
            'id': '123',
            'updated_pending_status': False,
            'status': constants.ACTIVE,
            'ipsec_site_connections': {
                '1': {'status': constants.DOWN,
                      'updated_pending_status': False},
                '2': {'status': constants.ACTIVE,
                      'updated_pending_status': True}
            }
        }]
        self.driver.agent_rpc.update_status.assert_called_once_with(
            self.context, expected_report)

    def test_sync_second_failed_connection_create(self):
        """Failure test of second sync's connection create failed.

        First connection on service was previously created. Second create
        failed.
        """
        conn1 = {'id': '1', 'status': constants.ACTIVE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        conn2 = {'id': '2', 'status': constants.PENDING_CREATE,
                 'cisco': {'site_conn_id': u'Tunnel1'}}
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [{
            'id': '123',
            'status': constants.ACTIVE,
            'ipsec_conns': [conn1, conn2]
        }]
        self.driver.perform_pending_operations(self.context)
        self.assertEqual(1,
                         self.driver.create_ipsec_site_connection.call_count)
        self.assertEqual(constants.ACTIVE, self._get_conn_status('123', '1'))
        self.assertEqual(constants.PENDING_CREATE,
                         self._get_conn_status('123', '2'))
        self.assertEqual(constants.ACTIVE, self._get_service_status('123'))

    def test_report_second_connection_create_failed(self):
        """Failure test report of second create failed on existing service."""
        # Simulate first connection active, second requesting create
        conn1 = {'id': '1', 'status': constants.ACTIVE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        conn2 = {'id': '2', 'status': constants.PENDING_CREATE,
                 'cisco': {'site_conn_id': u'Tunnel1'}}
        service = {'id': '123', 'status': constants.ACTIVE}
        self.driver.snapshot_service_state(service)
        self.driver.service_state['123'].snapshot_conn_state(conn1)
        self.driver.service_state['123'].snapshot_conn_state(conn2)
        # Simulate CSR status shows conn1 unchanged and conn2 is failed
        self.driver.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-NO-IKE'), ]

        self.driver.report_status(self.context)
        self.assertEqual(constants.ACTIVE, self._get_conn_status('123', '1'))
        self.assertEqual(constants.ERROR, self._get_conn_status('123', '2'))
        self.assertEqual(constants.ACTIVE, self._get_service_status('123'))
        expected_report = [{
            'id': '123',
            'updated_pending_status': False,
            'status': constants.ACTIVE,
            'ipsec_site_connections': {
                '2': {'status': constants.ERROR,
                      'updated_pending_status': True}
            }
        }]
        self.driver.agent_rpc.update_status.assert_called_once_with(
            self.context, expected_report)

    def test_report_one_of_two_connect_creates_failed(self):
        """Failure test of reporting when one of two connection creates."""
        # Simulate first connection active, second requesting create
        conn1 = {'id': '1', 'status': constants.PENDING_CREATE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        conn2 = {'id': '2', 'status': constants.PENDING_CREATE,
                 'cisco': {'site_conn_id': u'Tunnel1'}}
        service = {'id': '123', 'status': constants.PENDING_CREATE}
        self.driver.snapshot_service_state(service)
        self.driver.service_state['123'].snapshot_conn_state(conn1)
        self.driver.service_state['123'].snapshot_conn_state(conn2)
        # Simulate CSR status shows conn1 went up and conn2 errored
        self.driver.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-ACTIVE')]

        self.driver.report_status(self.context)
        self.assertEqual(constants.ACTIVE, self._get_conn_status('123', '1'))
        self.assertEqual(constants.ERROR, self._get_conn_status('123', '2'))
        self.assertEqual(constants.ACTIVE, self._get_service_status('123'))
        expected_report = [{
            'id': '123',
            'updated_pending_status': True,
            'status': constants.ACTIVE,
            'ipsec_site_connections': {
                '1': {'status': constants.ACTIVE,
                      'updated_pending_status': True},
                '2': {'status': constants.ERROR,
                      'updated_pending_status': True}
            }
        }]
        self.driver.agent_rpc.update_status.assert_called_once_with(
            self.context, expected_report)

    def test_report_with_no_connection_changes(self):
        """Report with no change to any connections."""
        # Simulate first connection active, second requesting create
        conn1 = {'id': '1', 'status': constants.ACTIVE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        conn2 = {'id': '2', 'status': constants.DOWN,
                 'cisco': {'site_conn_id': u'Tunnel1'}}
        service = {'id': '123', 'status': constants.ACTIVE}
        self.driver.snapshot_service_state(service)
        self.driver.service_state['123'].snapshot_conn_state(conn1)
        self.driver.service_state['123'].snapshot_conn_state(conn2)
        # Simulate CSR status shows same status for connections
        self.driver.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-NO-IKE'), (u'Tunnel1', u'DOWN-NEGOTIATING')]

        self.driver.report_status(self.context)
        self.assertEqual(constants.ACTIVE, self._get_conn_status('123', '1'))
        self.assertEqual(constants.DOWN, self._get_conn_status('123', '2'))
        self.assertEqual(constants.ACTIVE, self._get_service_status('123'))
        self.assertEqual(0, self.driver.agent_rpc.update_status.call_count)

    def test_sync_when_remove_last_connection_from_service(self):
        """Sync request, for a service with no more connections."""

    def test_report_connection_delete(self):
        """Report for delete of connection on service."""
        # Simulate requesting delete of connection
        conn1 = {'id': '1', 'status': constants.PENDING_DELETE,
                 'cisco': {'site_conn_id': u'Tunnel0'}}
        service = {'id': '123', 'status': constants.ACTIVE}
        self.driver.snapshot_service_state(service)
        self.driver.service_state['123'].snapshot_conn_state(conn1)
        # Simulate CSR status of no connections present
        self.driver.csr.read_tunnel_statuses.return_value = []

        self.driver.report_status(self.context)
        self.assertIsNone(self.driver.service_state['123'].conn_state.get('1'))
        self.assertEqual(constants.DOWN, self._get_service_status('123'))
        expected_report = [{
            'id': '123',
            'updated_pending_status': False,
            'status': constants.DOWN,
            'ipsec_site_connections': {
                '1': {'status': None,
                      'updated_pending_status': True}
            }
        }]
        self.driver.agent_rpc.update_status.assert_called_once_with(
            self.context, expected_report)

    def test_sync_delete_of_service(self):
        """Delete of service that has no connections.

        The service driver ensures that there are no services in-use, when
        a delete is attempted.
        """
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [{
            'id': '123',
            'status': constants.PENDING_DELETE,
            'ipsec_conns': []
        }]
        self.driver.perform_pending_operations(self.context)
        # TODO(pcm) FUTURE - Implement tests to verify action completed

    def test_report_service_deletion(self):
        """Report for the deletion of a VPN service."""
        # Simulate requesting delete of VPN service
        service = {'id': '123', 'status': constants.PENDING_DELETE}
        self.driver.snapshot_service_state(service)

        self.driver.report_status(self.context)
        # TODO(pcm) FUTURE - Implement tests to verify reporting

    def test_report_two_sevices(self):
        """Report generation of two services with changes."""
        # Simulate two services, each with connections that are up
        conn1a = {'id': '1', 'status': constants.ACTIVE,
                  'cisco': {'site_conn_id': u'Tunnel0'}}
        conn1b = {'id': '1', 'status': constants.ACTIVE,
                  'cisco': {'site_conn_id': u'Tunnel0'}}
        service_a = {'id': '123', 'status': constants.ACTIVE}
        self.driver.snapshot_service_state(service_a)
        service_b = {'id': '456', 'status': constants.ACTIVE}
        self.driver.snapshot_service_state(service_b)
        self.driver.service_state['123'].snapshot_conn_state(conn1a)
        self.driver.service_state['456'].snapshot_conn_state(conn1b)
        # Simulate status from each CSR reports that the associated
        # connection is now down.
        self.driver.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'DOWN'), ]

        self.driver.report_status(self.context)
        self.assertEqual(constants.DOWN, self._get_conn_status('123', '1'))
        self.assertEqual(constants.DOWN, self._get_conn_status('456', '1'))
        self.assertEqual(constants.ACTIVE, self._get_service_status('123'))
        self.assertEqual(constants.ACTIVE, self._get_service_status('456'))
        self.assertEqual(2, self.driver.csr.read_tunnel_statuses.call_count)
        expected_report = [
            {
                'id': '123',
                'updated_pending_status': False,
                'status': constants.ACTIVE,
                'ipsec_site_connections': {
                    '1': {'status': constants.DOWN,
                          'updated_pending_status': False},
                }
            },
            {
                'id': '456',
                'updated_pending_status': False,
                'status': constants.ACTIVE,
                'ipsec_site_connections': {
                    '1': {'status': constants.DOWN,
                          'updated_pending_status': False},
                }
            }
        ]
        self.driver.agent_rpc.update_status.assert_called_once_with(
            self.context, expected_report)

    def test_mark_and_sweep(self):
        # TODO(pcm) implement
        pass



    # TODO(pcm) FUTURE - UTs for update action, when supported.

#     def test_vpnservice_updated(self):
#         with mock.patch.object(self.driver, 'sync') as sync:
#             context = mock.Mock()
#             self.driver.vpnservice_updated(context)
#             sync.assert_called_once_with(context, [])

#     def test_create_router(self):
#         process_id = _uuid()
#         process = mock.Mock()
#         process.vpnservice = FAKE_VPN_SERVICE
#         self.driver.processes = {
#             process_id: process}
#         self.driver.create_router(process_id)
#         process.enable.assert_called_once_with()
#
#     def test_destroy_router(self):
#         process_id = _uuid()
#         process = mock.Mock()
#         process.vpnservice = FAKE_VPN_SERVICE
#         self.driver.processes = {
#             process_id: process}
#         self.driver.destroy_router(process_id)
#         process.disable.assert_called_once_with()
#         self.assertNotIn(process_id, self.driver.processes)
#
#     def test_sync_added(self):
#         self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
#             FAKE_VPN_SERVICE]
#         context = mock.Mock()
#         process = mock.Mock()
#         process.vpnservice = FAKE_VPN_SERVICE
#         process.connection_status = {}
#         process.status = constants.ACTIVE
#         process.updated_pending_status = True
#         self.driver.process_status_cache = {}
#         self.driver.processes = {
#             FAKE_ROUTER_ID: process}
#         self.driver.sync(context, [])
#         self.agent.assert_has_calls([
#             mock.call.add_nat_rule(
#                 FAKE_ROUTER_ID,
#                 'POSTROUTING',
#                 '-s 10.0.0.0/24 -d 20.0.0.0/24 -m policy '
#                 '--dir out --pol ipsec -j ACCEPT ',
#                 top=True),
#             mock.call.add_nat_rule(
#                 FAKE_ROUTER_ID,
#                 'POSTROUTING',
#                 '-s 10.0.0.0/24 -d 30.0.0.0/24 -m policy '
#                 '--dir out --pol ipsec -j ACCEPT ',
#                 top=True),
#             mock.call.add_nat_rule(
#                 FAKE_ROUTER_ID,
#                 'POSTROUTING',
#                 '-s 10.0.0.0/24 -d 40.0.0.0/24 -m policy '
#                 '--dir out --pol ipsec -j ACCEPT ',
#                 top=True),
#             mock.call.add_nat_rule(
#                 FAKE_ROUTER_ID,
#                 'POSTROUTING',
#                 '-s 10.0.0.0/24 -d 50.0.0.0/24 -m policy '
#                 '--dir out --pol ipsec -j ACCEPT ',
#                 top=True),
#             mock.call.iptables_apply(FAKE_ROUTER_ID)
#         ])
#         process.update.assert_called_once_with()
#         self.driver.agent_rpc.update_status.assert_called_once_with(
#             context,
#             [{'status': 'ACTIVE',
#              'ipsec_site_connections': {},
#              'updated_pending_status': True,
#              'id': FAKE_VPN_SERVICE['id']}])
#
#     def test_sync_removed(self):
#         self.driver.agent_rpc.get_vpn_services_on_host.return_value = []
#         context = mock.Mock()
#         process_id = _uuid()
#         process = mock.Mock()
#         process.vpnservice = FAKE_VPN_SERVICE
#         self.driver.processes = {
#             process_id: process}
#         self.driver.sync(context, [])
#         process.disable.assert_called_once_with()
#         self.assertNotIn(process_id, self.driver.processes)
#
#     def test_sync_removed_router(self):
#         self.driver.agent_rpc.get_vpn_services_on_host.return_value = []
#         context = mock.Mock()
#         process_id = _uuid()
#         self.driver.sync(context, [{'id': process_id}])
#         self.assertNotIn(process_id, self.driver.processes)
