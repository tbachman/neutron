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

import os
import tempfile

from neutron.services.vpn.device_drivers import (
    cisco_csr_rest_client as csr_client)
from neutron.services.vpn.service_drivers import (
    cisco_cfg_loader as cfg_loader)
from neutron.tests import base


class TestCiscoCsrIPsecDeviceDriverConfigLoading(base.BaseTestCase):

    def create_tempfile(self, contents):
        (fd, path) = tempfile.mkstemp(prefix='test', suffix='.conf')
        try:
            os.write(fd, contents.encode('utf-8'))
        finally:
            os.close(fd)
        return path

    def test_loading_csr_configuration(self):
        """Ensure that Cisco CSR configs can be loaded from config files."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = 10.20.30.1\n'
                                        'tunnel_ip = 3.2.1.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n')
        expected = {'3.2.1.1': {'rest_mgmt_ip': '10.20.30.1',
                                'tunnel_ip': '3.2.1.3',
                                'username': 'me',
                                'password': 'secret',
                                'host': 'compute-node',
                                'mgmt_intf': 't1_p:1',
                                'timeout': 5.0}}
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual(expected, csrs_found)

    def test_loading_config_without_timeout(self):
        """Cisco CSR config without timeout will use default timeout."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = 10.20.30.1\n'
                                        'tunnel_ip = 3.2.1.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n')
        expected = {'3.2.1.1': {'rest_mgmt_ip': '10.20.30.1',
                                'tunnel_ip': '3.2.1.3',
                                'username': 'me',
                                'password': 'secret',
                                'host': 'compute-node',
                                'mgmt_intf': 't1_p:1',
                                'timeout': csr_client.TIMEOUT}}
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual(expected, csrs_found)

    def test_skip_loading_duplicate_csr_configuration(self):
        """Failure test that duplicate configurations are ignored."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = 10.20.30.1\n'
                                        'tunnel_ip = 3.2.1.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n'
                                        '[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = 5.5.5.3\n'
                                        'tunnel_ip = 3.2.1.6\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t2_p:1\n')
        expected = {'3.2.1.1': {'rest_mgmt_ip': '10.20.30.1',
                                'tunnel_ip': '3.2.1.3',
                                'username': 'me',
                                'password': 'secret',
                                'host': 'compute-node',
                                'mgmt_intf': 't1_p:1',
                                'timeout': 5.0}}
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual(expected, csrs_found)

    def test_fail_loading_config_with_invalid_timeout(self):
        """Failure test of invalid timeout in config info."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = 10.20.30.1\n'
                                        'tunnel_ip = 3.2.1.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = yes\n')
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_fail_loading_config_missing_required_info(self):
        """Failure test of config missing required info."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:1.1.1.0]\n'
                                        'tunnel_ip = 1.1.1.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n'
                                        '[CISCO_CSR_REST:2.2.2.0]\n'
                                        'rest_mgmt = 10.20.30.2\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n'
                                        '[CISCO_CSR_REST:3.3.3.0]\n'
                                        'rest_mgmt = 10.20.30.3\n'
                                        'tunnel_ip = 3.3.3.3\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n'
                                        '[CISCO_CSR_REST:4.4.4.0]\n'
                                        'rest_mgmt = 10.20.30.4\n'
                                        'tunnel_ip = 4.4.4.4\n'
                                        'username = me\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n'
                                        '[CISCO_CSR_REST:5.5.5.0]\n'
                                        'rest_mgmt = 10.20.30.5\n'
                                        'tunnel_ip = 5.5.5.5'
                                        'username = me\n'
                                        'password = secret\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n'
                                        '[CISCO_CSR_REST:6.6.6.0]\n'
                                        'rest_mgmt = 10.20.30.6\n'
                                        'tunnel_ip = 6.6.6.6'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'timeout = 5.0\n')
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_fail_loading_config_with_invalid_router_id(self):
        """Failure test of config with invalid rotuer ID."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:4.3.2.1.9]\n'
                                        'rest_mgmt = 10.20.30.1\n'
                                        'tunnel_ip = 4.3.2.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n')
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_fail_loading_config_with_invalid_mgmt_ip(self):
        """Failure test of configuration with invalid management IP address."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = 1.1.1.1.1\n'
                                        'tunnel_ip = 3.2.1.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n')
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_fail_loading_config_with_invalid_tunnel_ip(self):
        """Failure test of configuration with invalid tunnel IP address."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = 1.1.1.1\n'
                                        'tunnel_ip = 3.2.1.4.5\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n')
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_failure_no_configurations_entries(self):
        """Failure test config file without any CSR definitions."""
        cfg_file = self.create_tempfile('NO CISCO SECTION AT ALL\n')
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_failure_no_csr_configurations_entries(self):
        """Failure test config file without any CSR definitions."""
        cfg_file = self.create_tempfile('[SOME_CONFIG:123]\n'
                                        'username = me\n')
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_missing_config_value(self):
        """Failure test of config file missing a value for attribute."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = \n'
                                        'tunnel_ip = 3.2.1.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 5.0\n')
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)

    def test_ignores_invalid_attribute_in_config(self):
        """Test ignoring of config file with invalid attribute."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = 1.1.1.1\n'
                                        'bogus = abcdef\n'
                                        'tunnel_ip = 3.2.1.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t1_p:1\n'
                                        'timeout = 15.5\n')
        expected = {'3.2.1.1': {'rest_mgmt_ip': '1.1.1.1',
                                'tunnel_ip': '3.2.1.3',
                                'username': 'me',
                                'password': 'secret',
                                'host': 'compute-node',
                                'mgmt_intf': 't1_p:1',
                                'timeout': 15.5}}
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual(expected, csrs_found)

    def test_invalid_management_interface(self):
        """Failure test of invalid management interface name."""
        """Failure test of config file missing a value for attribute."""
        cfg_file = self.create_tempfile('[CISCO_CSR_REST:3.2.1.1]\n'
                                        'rest_mgmt = 1.1.1.1\n'
                                        'tunnel_ip = 3.2.1.3\n'
                                        'username = me\n'
                                        'password = secret\n'
                                        'host = compute-node\n'
                                        'mgmt_intf = t3_p:1\n'
                                        'timeout = 5.0\n')
        csrs_found = cfg_loader.find_available_csrs_from_config([cfg_file])
        self.assertEqual({}, csrs_found)
