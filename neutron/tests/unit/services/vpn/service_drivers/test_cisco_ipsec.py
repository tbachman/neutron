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
# @author: Paul Michali, Cisco Systems, Inc.

import mock


# from neutron import context
from neutron import context
from neutron.db import api as dbapi
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.vpn.service_drivers import cisco_csr_db as csr_db
from neutron.services.vpn.service_drivers import cisco_ipsec as ipsec_driver
from neutron.tests import base

_uuid = uuidutils.generate_uuid

FAKE_ROUTER_ID = _uuid()
FAKE_VPN_CONN_ID = _uuid()
FAKE_IKE_ID = _uuid()
FAKE_IPSEC_ID = _uuid()

FAKE_VPN_CONNECTION = {
    'vpnservice_id': _uuid(),
    'id': FAKE_VPN_CONN_ID,
    'ikepolicy_id': FAKE_IKE_ID,
    'ipsecpolicy_id': FAKE_IPSEC_ID,
    'tenant_id': _uuid()
}
FAKE_VPN_SERVICE = {
    'router_id': FAKE_ROUTER_ID,
    'provider': 'fake_provider'
}
FAKE_HOST = 'fake_host'
CONN_DB_ACCESS = ('neutron.services.vpn.service_drivers.cisco_csr_db.'
                  'find_conn_with_policy')


class TestCiscoIPsecDriverValidation(base.BaseTestCase):

    def setUp(self):
        super(TestCiscoIPsecDriverValidation, self).setUp()
        self.addCleanup(mock.patch.stopall)
        mock.patch('neutron.openstack.common.rpc.create_connection').start()
        self.service_plugin = mock.Mock()
        self.driver = ipsec_driver.CiscoCsrIPsecVPNDriver(self.service_plugin)
        self.context = context.Context('some_user', 'some_tenant')
        self.vpn_service = mock.Mock()

    def test_ike_version_unsupported(self):
        """Failure test that Cisco CSR REST API does not support IKE v2."""
        policy_info = {'ike_version': 'v2',
                       'lifetime': {'units': 'seconds', 'value': 60}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_ike_version, policy_info)

    def test_ike_lifetime_not_in_seconds(self):
        """Failure test of unsupported lifetime units for IKE policy."""
        policy_info = {'lifetime': {'units': 'kilobytes', 'value': 1000}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          "IKE Policy", policy_info)

    def test_ipsec_lifetime_not_in_seconds(self):
        """Failure test of unsupported lifetime units for IPSec policy."""
        policy_info = {'lifetime': {'units': 'kilobytes', 'value': 1000}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          "IPSec Policy", policy_info)

    def test_ike_lifetime_seconds_values_at_limits(self):
        """Test valid lifetime values for IKE policy."""
        policy_info = {'lifetime': {'units': 'seconds', 'value': 60}}
        self.driver.validate_lifetime('IKE Policy', policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 86400}}
        self.driver.validate_lifetime('IKE Policy', policy_info)

    def test_ipsec_lifetime_seconds_values_at_limits(self):
        """Test valid lifetime values for IPSec policy."""
        policy_info = {'lifetime': {'units': 'seconds', 'value': 120}}
        self.driver.validate_lifetime('IPSec Policy', policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 2592000}}
        self.driver.validate_lifetime('IPSec Policy', policy_info)

    def test_ike_lifetime_values_invalid(self):
        """Failure test of unsupported lifetime values for IKE policy."""
        which = "IKE Policy"
        policy_info = {'lifetime': {'units': 'seconds', 'value': 59}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          which, policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 86401}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          which, policy_info)

    def test_ipsec_lifetime_values_invalid(self):
        """Failure test of unsupported lifetime values for IPSec policy."""
        which = "IPSec Policy"
        policy_info = {'lifetime': {'units': 'seconds', 'value': 119}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          which, policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 2592001}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          which, policy_info)

    def test_ipsec_connection_with_mtu_at_limits(self):
        """Test IPSec site-to-site connection with MTU at limits."""
        conn_info = {'mtu': 1500}
        self.driver.validate_mtu(conn_info)
        conn_info = {'mtu': 9192}
        self.driver.validate_mtu(conn_info)

    def test_ipsec_connection_with_invalid_mtu(self):
        """Failure test of IPSec site connection with unsupported MTUs."""
        conn_info = {'mtu': 1499}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_mtu, conn_info)
        conn_info = {'mtu': 9193}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_mtu, conn_info)

    def simulate_gw_ip_available(self):
        """Helper function indicating that tunnel has a gateway IP."""
        def have_one():
            return 1
        self.vpn_service.router.gw_port.fixed_ips.__len__ = have_one
        ip_addr_mock = mock.Mock()
        self.vpn_service.router.gw_port.fixed_ips = [ip_addr_mock]
        return ip_addr_mock

    def test_have_public_ip_for_router(self):
        """Ensure that router for IPSec connection has gateway IP."""
        self.simulate_gw_ip_available()
        self.driver.validate_public_ip_present(self.vpn_service)

    def test_router_with_missing_gateway_ip(self):
        """Failure test of IPSec connection with missing gateway IP."""
        self.simulate_gw_ip_available()
        self.vpn_service.router.gw_port = None
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_public_ip_present,
                          self.vpn_service)

    def test_peer_id_is_an_ip_address(self):
        """Ensure peer ID is an IP address for IPsec connection create."""
        ipsec_conn = {'peer_id': '10.10.10.10'}
        self.driver.validate_peer_id(ipsec_conn)

    def test_peer_id_is_not_ip_address(self):
        """Failure test of peer_id that is not an IP address."""
        ipsec_conn = {'peer_id': 'some-site.com'}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_peer_id, ipsec_conn)

    def test_validation_for_create_ipsec_connection(self):
        """Ensure all validation passes for IPSec site connection create."""
        self.simulate_gw_ip_available()
        # Provide the minimum needed items to validate
        ipsec_conn = {'id': '1',
                      'ikepolicy_id': '123',
                      'ipsecpolicy_id': '2',
                      'mtu': 1500,
                      'peer_id': '10.10.10.10'}
        self.service_plugin.get_ikepolicy = mock.Mock(
            return_value={'ike_version': 'v1',
                          'lifetime': {'units': 'seconds', 'value': 60}})
        self.service_plugin.get_ipsecpolicy = mock.Mock(
            return_value={'lifetime': {'units': 'seconds', 'value': 120}})
        self.driver.validate_ipsec_connection(self.context, ipsec_conn,
                                              self.vpn_service)


class TestCiscoIPsecDriverMapping(base.BaseTestCase):

    def setUp(self):
        super(TestCiscoIPsecDriverMapping, self).setUp()
        self.addCleanup(mock.patch.stopall)
        dbapi.configure_db()
        self.addCleanup(dbapi.clear_db)
        self.context = context.Context('some_user', 'some_tenant')
        self.session = self.context.session
        self.ipsec_dbase_mock = mock.patch(CONN_DB_ACCESS,
                                           autospec=True).start()
        self.ipsec_dbase_mock.return_value = None

    def test_identifying_next_tunnel_id(self):
        """Make sure available tunnel IDs can be reserved.

        Check before adding five entries, and then check for the next
        available, afterwards. Finally, remove one in the middle and
        ensure that it is the next available ID.
        """
        with self.session.begin():
            for i in xrange(5):
                tunnel = csr_db.get_next_available_tunnel_id(self.session)
                self.assertEqual(i, tunnel)
                conn_id = i * 10
                entry = csr_db.IdentifierMap(tenant_id='1',
                                             ipsec_site_conn_id='%d' % conn_id,
                                             csr_tunnel_id=tunnel,
                                             csr_ike_policy_id=100,
                                             csr_ipsec_policy_id=200)
                self.session.add(entry)
            tunnel = csr_db.get_next_available_tunnel_id(self.session)
            self.assertEqual(5, tunnel)
            # Remove the 3rd entry and verify that this is the next available
            sess_qry = self.session.query(csr_db.IdentifierMap)
            sess_qry.filter_by(ipsec_site_conn_id='20').delete()
            tunnel = csr_db.get_next_available_tunnel_id(self.session)
            self.assertEqual(2, tunnel)

    def test_no_more_tunnel_ids_available(self):
        """Failure test of trying to reserve tunnel, when none available."""
        fake_session = mock.Mock()
        all_tunnels_in_use = [(i,) for i in range(csr_db.MAX_CSR_TUNNELS)]
        fake_session.query.return_value = all_tunnels_in_use
        self.assertRaises(IndexError,
                          csr_db.get_next_available_tunnel_id, fake_session)

    def test_identifying_next_ike_policy_id(self):
        """Make sure available Cisco CSR IKE policy IDs can be reserved.

        Check before adding five entries, and then check for the next
        available, afterwards. Finally, remove one in the middle and
        ensure that it is the next available ID. Note: the IKE policy IDs
        are one based.
        """
        with self.session.begin():
            for i in xrange(1, 6):
                ike_id = csr_db.get_next_available_ike_policy_id(self.session)
                self.assertEqual(i, ike_id)
                conn_id = i * 10
                entry = csr_db.IdentifierMap(tenant_id='1',
                                             ipsec_site_conn_id='%d' % conn_id,
                                             csr_tunnel_id=i,
                                             csr_ike_policy_id=ike_id,
                                             csr_ipsec_policy_id=200)
                self.session.add(entry)
            ike_id = csr_db.get_next_available_ike_policy_id(self.session)
            self.assertEqual(6, ike_id)
            # Remove the 3rd entry and verify that this is the next available
            sess_qry = self.session.query(csr_db.IdentifierMap)
            sess_qry.filter_by(ipsec_site_conn_id='30').delete()
            ike_id = csr_db.get_next_available_ike_policy_id(self.session)
            self.assertEqual(3, ike_id)

    def test_no_more_ike_policy_ids_available(self):
        """Failure test of trying to reserve IKE policy ID, when none avail."""
        fake_session = mock.Mock()
        all_in_use = [(i,) for i in range(1, csr_db.MAX_CSR_IKE_POLICIES + 1)]
        fake_session.query.return_value = all_in_use
        self.assertRaises(IndexError,
                          csr_db.get_next_available_ike_policy_id,
                          fake_session)

    def simulate_existing_mappings(self, session):
        """Helper - create three mapping table entries.

        Each entry will have the same tenant ID. The IPSec site connection
        will be 10, 20, and 30. The mapped tunnel ID will be 1, 2, and 3.
        The mapped IKE policy ID will be 1, 2, and 3. The mapped IPSec policy
        ID will be 100, 200, and 300.
        """
        for i in xrange(1, 4):
            conn_id = i * 10
            entry = csr_db.IdentifierMap(tenant_id='1',
                                         ipsec_site_conn_id='%d' % conn_id,
                                         csr_tunnel_id=i,
                                         csr_ike_policy_id=i,
                                         csr_ipsec_policy_id=i)
            self.session.add(entry)

    def test_lookup_existing_ike_policy_mapping(self):
        """Ensure can find existing mappings for IKE policy."""
        with self.session.begin():
            self.simulate_existing_mappings(self.session)
            for i in xrange(1, 4):
                conn_id = str(i * 10)
                ike_id = csr_db.lookup_ike_policy_id_for(conn_id, self.session)
                self.assertEqual(i, ike_id)

    def test_getting_new_ike_policy_id(self):
        """Reserve new Cisco CSR IKE policy ID from mapping table.

        Simulate that an existing connection is not using the IKE policy,
        by mocking out database look-up, and ensure that a new policy ID
        is chosen.
        """
        with self.session.begin():
            self.simulate_existing_mappings(self.session)
            ike_id = csr_db.determine_csr_ike_policy_id('ike-uuid',
                                                        '123',
                                                        self.session)
            self.assertEqual(4, ike_id)

    def test_identifying_next_ipsec_policy_id(self):
        """Make sure available Cisco CSR IPSec policy IDs can be reserved.

        Check before adding five entries, and then check for the next
        available, afterwards. Finally, remove one in the middle and
        ensure that it is the next available ID. Note: the IPSec policy IDs
        are one based.
        """
        with self.session.begin():
            for i in xrange(1, 6):
                ipsec_id = csr_db.get_next_available_ipsec_policy_id(
                    self.session)
                self.assertEqual(i, ipsec_id)
                conn_id = i * 10
                entry = csr_db.IdentifierMap(tenant_id='1',
                                             ipsec_site_conn_id='%d' % conn_id,
                                             csr_tunnel_id=i,
                                             csr_ike_policy_id=100,
                                             csr_ipsec_policy_id=ipsec_id)
                self.session.add(entry)
            ipsec_id = csr_db.get_next_available_ipsec_policy_id(self.session)
            self.assertEqual(6, ipsec_id)
            # Remove the 3rd entry and verify that this is the next available
            sess_qry = self.session.query(csr_db.IdentifierMap)
            sess_qry.filter_by(ipsec_site_conn_id='30').delete()
            ipsec_id = csr_db.get_next_available_ipsec_policy_id(self.session)
            self.assertEqual(3, ipsec_id)

    def test_no_more_ipsec_policy_ids_available(self):
        """Failure test trying to reserve IPSec policy ID, when none avail."""
        fake_session = mock.Mock()
        all_in_use = [(i,)
                      for i in range(1, csr_db.MAX_CSR_IPSEC_POLICIES + 1)]
        fake_session.query.return_value = all_in_use
        self.assertRaises(IndexError,
                          csr_db.get_next_available_ipsec_policy_id,
                          fake_session)

    def test_lookup_existing_ipsec_policy_mapping(self):
        """Ensure can find existing mappings for IPSec policy."""
        with self.session.begin():
            self.simulate_existing_mappings(self.session)
            for i in xrange(1, 4):
                conn_id = str(i * 10)
                ipsec_id = csr_db.lookup_ipsec_policy_id_for(conn_id,
                                                             self.session)
                self.assertEqual(i, ipsec_id)

    def test_getting_new_ipsec_policy_id(self):
        """Reserve new Cisco CSR IPSec policy ID from mapping table.

        Simulate that an existing connection is not using the IPSec policy,
        by mocking out database look-up, and ensure that a new policy ID
        is chosen.
        """
        with self.session.begin():
            self.simulate_existing_mappings(self.session)
            ipsec_id = csr_db.determine_csr_ipsec_policy_id('ipsec-uuid',
                                                            '123',
                                                            self.session)
            self.assertEqual(4, ipsec_id)

    def test_create_tunnel_mapping(self):
        """Ensure new mappings are created, and mapping table updated.

        Simulate that an existing connection is not using the IKE and IPSec
        policies, by mocking out database look-ups, and ensure that new
        policy IDs are chosen.
        """
        conn_info = {'ikepolicy_id': '10',
                     'ipsecpolicy_id': '50',
                     'id': '100',
                     'tenant_id': '1000'}
        csr_db.create_tunnel_mapping(self.context, conn_info)
        tunnel_id, ike_id, ipsec_id = csr_db.get_tunnel_mapping_for(
            '100', self.session)
        self.assertEqual(0, tunnel_id)
        self.assertEqual(1, ike_id)
        self.assertEqual(1, ipsec_id)
        conn_info = {'ikepolicy_id': '20',
                     'ipsecpolicy_id': '60',
                     'id': '101',
                     'tenant_id': '1000'}
        csr_db.create_tunnel_mapping(self.context, conn_info)
        tunnel_id, ike_id, ipsec_id = csr_db.get_tunnel_mapping_for(
            '101', self.session)
        self.assertEqual(1, tunnel_id)
        self.assertEqual(2, ike_id)
        self.assertEqual(2, ipsec_id)

    def test_create_duplicate_mapping(self):
        """Failure test of adding the same mapping twice."""
        conn_info = {'ikepolicy_id': '10',
                     'ipsecpolicy_id': '50',
                     'id': '100',
                     'tenant_id': '1000'}
        csr_db.create_tunnel_mapping(self.context, conn_info)
        tunnel_id, ike_id, ipsec_id = csr_db.get_tunnel_mapping_for(
            '100', self.session)
        self.assertEqual(0, tunnel_id)
        self.assertEqual(1, ike_id)
        self.assertEqual(1, ipsec_id)
        self.assertRaises(csr_db.CsrInternalError,
                          csr_db.create_tunnel_mapping,
                          self.context, conn_info)

    def test_delete_tunnel_mapping(self):
        """Ensure new mappings table updated, when delete mappings."""
        # Create mappings, using new new policies for each
        tenant_id = '1000'
        for i in range(1, 6):
            conn_id = str(100 * i)
            conn_info = {'ikepolicy_id': '%d' % (10 * i),
                         'ipsecpolicy_id': '%d' % (20 * i),
                         'id': conn_id,
                         'tenant_id': tenant_id}
            csr_db.create_tunnel_mapping(self.context, conn_info)
            tunnel_id, ike_id, ipsec_id = csr_db.get_tunnel_mapping_for(
                conn_id, self.session)
            self.assertEqual(i - 1, tunnel_id)
            self.assertEqual(i, ike_id)
            self.assertEqual(i, ipsec_id)
        # Remove the third mapping and then check the list
        conn_info = {'ikepolicy_id': '%d' % 30,
                     'ipsecpolicy_id': '%d' % 60,
                     'id': '%d' % 300,
                     'tenant_id': tenant_id}
        csr_db.delete_tunnel_mapping(self.context, conn_info)
        for i in [1, 2, 4, 5]:
            conn_id = str(100 * i)
            tunnel_id, ike_id, ipsec_id = csr_db.get_tunnel_mapping_for(
                conn_id, self.session)
            self.assertEqual(i - 1, tunnel_id)
            self.assertEqual(i, ike_id)
            self.assertEqual(i, ipsec_id)
        self.assertRaises(csr_db.CsrInternalError,
                          csr_db.get_tunnel_mapping_for,
                          str(300), self.session)

    def test_get_cisco_ipsec_connection_info(self):
        """Ensure correct transform and mapping info is obtained."""
        mock.patch('neutron.openstack.common.rpc.create_connection').start()
        self.driver = ipsec_driver.CiscoCsrIPsecVPNDriver(mock.Mock())
        self.simulate_existing_mappings(self.session)
        expected = {'site_conn_id': u'Tunnel2',
                    'ike_policy_id': u'2',
                    'ipsec_policy_id': u'2'}
        actual = self.driver.get_cisco_connection_mappings('20', self.context)
        self.assertEqual(expected, actual)


class TestCiscoIPsecDriver(base.BaseTestCase):

    """Test that various incoming requests are sent to device driver."""

    def setUp(self):
        super(TestCiscoIPsecDriver, self).setUp()
        self.addCleanup(mock.patch.stopall)
        dbapi.configure_db()
        self.addCleanup(dbapi.clear_db)
        mock.patch('neutron.openstack.common.rpc.create_connection').start()

        l3_agent = mock.Mock()
        l3_agent.host = FAKE_HOST
        plugin = mock.Mock()
        plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        plugin_p = mock.patch('neutron.manager.NeutronManager.get_plugin')
        get_plugin = plugin_p.start()
        get_plugin.return_value = plugin
        service_plugin_p = mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins')
        get_service_plugin = service_plugin_p.start()
        get_service_plugin.return_value = {constants.L3_ROUTER_NAT: plugin}

        service_plugin = mock.Mock()
        service_plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        service_plugin._get_vpnservice.return_value = {
            'router_id': _uuid(),
            'provider': 'fake_provider'
        }
        self.driver = ipsec_driver.CiscoCsrIPsecVPNDriver(service_plugin)
        self.driver.validate_ipsec_connection = mock.Mock()
        self.ipsec_dbase_mock = mock.patch(CONN_DB_ACCESS,
                                           autospec=True).start()
        self.ipsec_dbase_mock.return_value = None

    def _test_update(self, func, args):
        ctxt = context.Context('', 'somebody')
        with mock.patch.object(self.driver.agent_rpc, 'cast') as cast:
            func(ctxt, *args)
            cast.assert_called_once_with(
                ctxt,
                {'args': {},
                 'namespace': None,
                 'method': 'vpnservice_updated'},
                version='1.0',
                topic='cisco_csr_ipsec_agent.fake_host')

    def test_create_ipsec_site_connection(self):
        self._test_update(self.driver.create_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION])

    def test_update_ipsec_site_connection(self):
        # TODO(pcm) FUTURE - Update test, when supported
        self.assertRaises(ipsec_driver.CsrUnsupportedError,
                          self._test_update,
                          self.driver.update_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION, FAKE_VPN_CONNECTION])

    def test_delete_ipsec_site_connection(self):
        self._test_update(self.driver.delete_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION])

    def test_update_vpnservice(self):
        self._test_update(self.driver.update_vpnservice,
                          [FAKE_VPN_SERVICE, FAKE_VPN_SERVICE])

    def test_delete_vpnservice(self):
        self._test_update(self.driver.delete_vpnservice,
                          [FAKE_VPN_SERVICE])
