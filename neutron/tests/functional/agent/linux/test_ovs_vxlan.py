# Copyright 2014 Cisco Systems, Inc.
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

from neutron.agent.linux import ovs_lib
from neutron.plugins.common import constants as p_const
from neutron.tests.functional.agent.linux import base_agent


BR_PREFIX = 'vx-'
INVALID_OFPORT_ID = '-1'


class TestOVSAgentVXLAN(base_agent.BaseLinuxTestCase):

    def setUp(self):
        super(TestOVSAgentVXLAN, self).setUp()

        self.root_helper = 'sudo'
        self._check_test_requirements()
        self.ovs = ovs_lib.BaseOVS(self.root_helper)
        self.br = self.create_ovs_bridge(self.ovs, BR_PREFIX)
        self.addCleanup(self.cleanup_bridge(self.br))

    def _check_test_requirements(self):
        if not self.check_sudo():
            self.skipTest('testing with sudo is not enabled')
        self.check_command(['which', 'ovs-vsctl'],
                           'Exit code: 1',
                           'ovs-vsctlis not installed')
        self.check_command([self.root_helper, '-n', 'ovs-vsctl', 'show'],
                           'Exit code: 1',
                           'password-less sudo not granted for ovs-vsctl')

    def test_vxlan_version_check(self):
        expected = self.is_vxlan_supported()
        actual = self.is_ovs_lib_vxlan_supported()
        self.assertEqual(actual, expected)

    def is_ovs_lib_vxlan_supported(self):
        vxlan_supported = True
        try:
            ovs_lib.check_ovs_vxlan_version(self.root_helper)
        except SystemError:
            vxlan_supported = False
        return vxlan_supported

    def is_vxlan_supported(self):
        self.port_name, self.vxlan_port = self.create_ovs_tunnel_port(
            BR_PREFIX,
            self.br.add_tunnel_port,
            "10.10.10.10",
            "10.10.10.20",
            p_const.TYPE_VXLAN)
        ofport = self.br.get_port_ofport(self.port_name)

        return (ofport == INVALID_OFPORT_ID)
