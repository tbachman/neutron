# Copyright (c) 2014 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

import neutron.db.api as db
from neutron.extensions import portbindings
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import config as ml2_config
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_client
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_db
from neutron.plugins.ml2.drivers import type_vlan as vlan_config
from neutron.tests.unit import test_db_plugin

LOG = logging.getLogger(__name__)
MECHANISM_NAME = ('neutron.plugins.ml2.'
                  'drivers.cisco.n1kv.mech_cisco_n1kv.N1KVMechanismDriver')
ML2_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'
PHYS_NET = 'some-phys-net'
VLAN_MIN = 100
VLAN_MAX = 500


class FakeResponse(object):

    """
    This object is returned by mocked requests lib instead of normal response.

    Initialize it with the status code, header and buffer contents you wish to
    return.

    """
    def __init__(self, status, response_text, headers):
        self.buffer = response_text
        self.status_code = status
        self.headers = headers

    def json(self, *args, **kwargs):
        return self.buffer


class TestN1KVMechanismDriver(test_db_plugin.NeutronDbPluginV2TestCase):
    """Test Cisco Nexus1000V mechanism driver."""

    tenant_id = "some_tenant"

    DEFAULT_RESP_BODY = ""
    DEFAULT_RESP_CODE = 200
    DEFAULT_CONTENT_TYPE = ""
    fmt = "json"

    def setUp(self):

        ml2_opts = {
            'mechanism_drivers': ['cisco_n1kv'],
            'type_drivers': ['vlan'],
            'tenant_network_types': ['vlan']}
        ml2_cisco_opts = {
            'n1kv_vsm_ip': ['127.0.0.1'],
            'username': ['admin'],
            'password': ['Sfish123']
        }
        for opt, val in ml2_opts.items():
            ml2_config.cfg.CONF.set_override(opt, val, 'ml2')

        for opt, val in ml2_cisco_opts.items():
            ml2_config.cfg.CONF.set_override(opt, val, 'ml2_cisco_n1kv')

        # Configure the ML2 VLAN parameters
        phys_vrange = ':'.join([PHYS_NET, str(VLAN_MIN), str(VLAN_MAX)])
        vlan_config.cfg.CONF.set_override('network_vlan_ranges',
                                          [phys_vrange],
                                          'ml2_type_vlan')

        if not self.DEFAULT_RESP_BODY:
            self.DEFAULT_RESP_BODY = {
                "icehouse-pp": {"properties": {"name": "icehouse-pp",
                                               "id": "some-uuid-1"}},
                "default-pp": {"properties": {"name": "default-pp",
                                             "id": "some-uuid-2"}},
                "dhcp_pp": {"properties": {"name": "dhcp_pp",
                                           "id": "some-uuid-3"}},
            }

        # Creating a mock HTTP connection object for requests lib. The N1KV
        # client interacts with the VSM via HTTP. Since we don't have a VSM
        # running in the unit tests, we need to 'fake' it by patching the HTTP
        # library itself. We install a patch for a fake HTTP connection class.
        # Using __name__ to avoid having to enter the full module path.
        http_patcher = mock.patch(n1kv_client.requests.__name__ + ".request")
        FakeHttpConnection = http_patcher.start()
        # Now define the return values for a few functions that may be called
        # on any instance of the fake HTTP connection class.
        self.resp_headers = {"content-type": "application/json"}
        FakeHttpConnection.return_value = (FakeResponse(
                                           self.DEFAULT_RESP_CODE,
                                           self.DEFAULT_RESP_BODY,
                                           self.resp_headers))
        super(TestN1KVMechanismDriver, self).setUp(ML2_PLUGIN)
        self.mech_driver = importutils.import_object(MECHANISM_NAME)
        self.mech_driver.initialize()
        self.addCleanup(db.clear_db)


class TestN1KVMechDriverBasicGet(test_db_plugin.TestBasicGet,
                                 TestN1KVMechanismDriver):

    pass


class TestN1KVMechDriverHTTPResponse(test_db_plugin.TestV2HTTPResponse,
                                     TestN1KVMechanismDriver):

    pass


class TestN1KVMechDriverNetworksV2(test_db_plugin.TestNetworksV2,
                                   TestN1KVMechanismDriver):

    def test_create_network_with_default_n1kv_network_profile_id(self):
        """Test network create without passing network profile id."""
        with self.network() as network:
            np = n1kv_db.get_network_profile_by_type('vlan')
            net_np = n1kv_db.get_network_binding(network['network']['id'])
            self.assertEqual(network['network']['id'], net_np['network_id'])
            self.assertEqual(net_np['profile_id'], np['id'])


class TestN1KVMechDriverPortsV2(test_db_plugin.TestNetworksV2,
                                TestN1KVMechanismDriver):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True
    pass


class TestN1KVMechDriverSubnetsV2(test_db_plugin.TestSubnetsV2,
                                  TestN1KVMechanismDriver):

    pass
