# Copyright (c) 2013 OpenStack Foundation.
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

import contextlib
import mock
import os

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.common import config as cisco_plugin_config
from neutron.plugins.ml2 import config as ml2_config
from neutron.plugins.ml2.drivers.cisco import config as ml2_cisco_config
from neutron.plugins.ml2.drivers.cisco import mech_cisco_nexus
from neutron.plugins.ml2.drivers.cisco import nexus_snippets
from neutron.plugins.ml2.drivers import type_vlan as ml2_vlan_config
from neutron.plugins.openvswitch.common import config as ovs_config
from neutron.tests.unit import test_db_plugin

############################################################
#            Mandatory Configuration
# The tests in this module are a smoke test of the Cisco
# Nexus plugins that are intended to be run using an actual
# Nexus switch. In order to run the tests, you must have SSH
# access to a Nexus switch, and there must be an ethernet
# port available on the switch which you don't mind having
# VLANs configured and un-configured. To run the tests,
# modify the definitions of NEXUS_IP_ADDR, NEXUS_USER_NAME,
# NEXUS_PASSWORD, and NEXUS_INTERFACE below to values
# appropriate for your switch.
#
# If these settings are unmodified, the tests in this module
# will be skipped.
############################################################
NEXUS_IP_ADDR = '0.0.0.0'
NEXUS_USER_NAME = 'admin'
NEXUS_PASSWORD = 'myPassword'
NEXUS_INTERFACE = '1/1'

NEXUS_PORT = 22
LOG = logging.getLogger(__name__)
ML2_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'
CISCO_CORE_PLUGIN = 'neutron.plugins.cisco.network_plugin.PluginV2'
NEXUS_PLUGIN = 'neutron.plugins.cisco.nexus.cisco_nexus_plugin_v2.NexusPlugin'
NEXUS_DRIVER = ('neutron.plugins.cisco.nexus.'
                'cisco_nexus_network_driver_v2.CiscoNEXUSDriver')
NEXUS_DEV_ID = 'NEXUS_SWITCH'
PHYS_NET = 'physnet1'
BRIDGE_NAME = 'br-eth1'
COMP_HOST_NAME = 'testhost'
VLAN_START = 1000
VLAN_END = 1100
VLAN_1 = VLAN_START
VLAN_2 = VLAN_START + 1
NETWORK_NAME_1 = 'net1'
NETWORK_NAME_2 = 'net2'
CIDR_1 = '10.0.0.0/24'
CIDR_2 = '10.0.1.0/24'
DEVICE_ID_1 = '11111111-1111-1111-1111-111111111111'
DEVICE_ID_2 = '22222222-2222-2222-2222-222222222222'
DEVICE_OWNER = 'compute:None'

NCCLIENT_CLONE_CMD = 'git clone https://github.com/CiscoSystems/ncclient.git'
NCCLIENT_INSTALL_CMD = 'cd ncclient; python ncclient/setup.py install'

SHOW_RUNNING_VLAN_SNIPPET = """
  <show>
    <running-config>
      <vlan>
        <vlan-range>%s</vlan-range>
      </vlan>
    </running-config>
  </show> """

SHOW_RUNNING_INTERFACE_SNIPPET = """
  <show>
    <running-config>
      <interface>
        <intf-spec>%s</intf-spec>
      </interface>
    </running-config>
  </show> """

VLAN_CONFIG = 'vlan %s'
VLAN_NAME_CONFIG = 'name q-%s'
INTERFACE_VLAN_CONFIG = 'switchport trunk allowed vlan %s'


class CiscoNexusSmokeTest(test_db_plugin.TestPortsV2):
    """Base test class for Cisco Nexus smoke tests.

    This class implements the common (non-plugin-specific) setup, test
    cases, and utility methods that are required for performing brief
    smoke tests using one of the Cisco Nexus plugins and a real Nexus
    switch. This base class does not include any plugin-specific
    configuration; rather, it depends on child classes to provide this
    configuration.

    After configuring for a specific Cisco plugin, child classes are
    expected to set the following variables:
        core_plugin: (Required) A dot-separated path to the Neutron plugin
                     class to be used for testing (e.g. ML2_PLUGIN above).
        do_update_after_port_create: (Optional) Set to True if a
                     update_port is required after a create_port for
                     this plugin.

    Because this base class does not include plugin-specific configuration,
    we want to skip all test cases that are being performed in the context
    of this base class. The check for whether tests are being performed
    in the context of this base class is based on whether the core_plugin
    variable is non-None.

    When test cases are being performed in the context of a
    child of this base class, that child will inherit the smoke test
    cases which are defined in this (parent) base class, as well as
    any unit test cases defined in all ancestors of this base class.
    In this case, we want a test case to be run when two conditions are met:
        - The user has a Nexus switch on which to test, and the Nexus switch
          connection information (NEXUS_IP_ADDR, NEXUS_INTERFACE,
          NEXUS_USER_NAME, NEXUS_PASSWORD) have been provided by modifying
          the definitions at the top of this module.
        - The test case being run is explicitly defined in this base class.
          There is no need to run any test cases which are inherited from
          this base class' ancestors, since those tests were not written
          for smoke testing, and the inherited test cases are already
          run (with Cisco plugins configured) in other unit test modules.
    """

    core_plugin = None
    do_update_after_port_create = True
    _paramiko = None
    _ncclient = None
    _nexus = None

    def setUp(self):
        """Connect to a Nexus switch and start plugin if configured."""
        if not self.core_plugin:
            self.skipTest(
                "Plugin is not configured for this base test class")

        # Import ncclient and connect to Nexus switch
        self._import_ncclient()
        self._nexus = self._ncclient.connect(host=NEXUS_IP_ADDR,
                                             port=NEXUS_PORT,
                                             username=NEXUS_USER_NAME,
                                             password=NEXUS_PASSWORD)

        # The TestPortsV2 setUp overwrites home directory
        # environment ('~'), so cache it and restore it after
        # calling this (super) setUp to start the plugin.
        home = os.path.expanduser('~')
        super(CiscoNexusSmokeTest, self).setUp(self.core_plugin)
        os.environ['HOME'] = home

        self.port_create_status = 'DOWN'

    def skip_if_not_nexus_smoke_test(self):
        """Skip test if missing switch info or this isn't a Nexus smoke test.

        This method should be called early in the setUp() method of any
        class which is a child of this base test class. This method
        determines if a given test case which is being run in the context
        of that child class should proceed or should be skipped.

        This method skips the current test on either of two conditions:
        - Nexus switch connection information (NEXUS_IP_ADDR,
          NEXUS_INTERFACE, NEXUS_USER_NAME, NEXUS_PASSWORD) has not been
          provided by modifying the definitions at the top of this module.
        - The test case being run is not a smoke test which is defined
          in this base test class (e.g. it is inherited from parents
          of this base test class).
        """

        if NEXUS_IP_ADDR == '0.0.0.0':
            self.skipTest("Skip test since Nexus connection info is missing")

        #if self._testMethodName not in CiscoNexusSmokeTest.__dict__:
        if self.id().split('.')[-1] not in vars(CiscoNexusSmokeTest):
            self.skipTest("Not a Nexus switch smoke test case")

    def _import_ncclient(self):
        """Import the ncclient module.

        The ncclient module is not included in the Neutron tox test virtual
        environment, so it needs to be manually installed in the virtual
        environment. Provide a gentle reminder if there is an ImportError
        upon importing ncclient.

        """
        if not self._ncclient:
            try:
                self._ncclient = importutils.import_module('ncclient.manager')
            except ImportError, e:
                # Provide ncclient installation steps in exception
                e.args += ('Please install in the your virtual env with:',
                           NCCLIENT_CLONE_CMD,
                           NCCLIENT_INSTALL_CMD)
                raise

    @contextlib.contextmanager
    def _create_net_subnet_port(self, name='myname', cidr=CIDR_1,
                                device_id=DEVICE_ID_1, no_delete=False):
        """Create network, subnet, and port resources for test cases.

        Upon exit from this context manager, the (optionally) port, subnet,
        and then network are deleted.

        :param name: Name of network to be created
        :param cidr: cidr address of subnetwork to be created
        :param device_id: Device ID to use for port creation
        :param no_delete: If set to True, do not delete the port at the
                          end of testing

        """
        with self.network(name=name) as network:
            with self.subnet(network=network, cidr=cidr) as subnet:
                args = (portbindings.HOST_ID, 'device_id', 'device_owner')
                port_dict = {portbindings.HOST_ID: COMP_HOST_NAME,
                             'device_id': device_id,
                             'device_owner': DEVICE_OWNER}
                with self.port(subnet=subnet, fmt=self.fmt,
                               no_delete=no_delete,
                               arg_list=args, **port_dict) as port:
                    if self.do_update_after_port_create:
                        data = {'port': port_dict}
                        self._update('ports', port['port']['id'], data)
                yield port

    def _get_running_vlan_config(self, vlan):
        """Read running config for a VLAN from Nexus switch."""
        return self._nexus.get(
            ("subtree", SHOW_RUNNING_VLAN_SNIPPET % vlan))._raw

    def _get_running_ethernet_interface_config(self, intf):
        """Read running config for an ethernet intf from Nexus switch."""
        ether_intf = 'ethernet ' + intf
        return self._nexus.get(
            ("subtree", SHOW_RUNNING_INTERFACE_SNIPPET % ether_intf))._raw

    def _is_in_config(self, config, expected_config_lines):
        """Confirm that a list of lines appears in Nexus running config."""
        return all(line in config for line in expected_config_lines)

    def _is_vlan_configured(self, vlan):
        """Confirm that a VLAN is configured on the Nexus switch."""
        vlan_config = self._get_running_vlan_config(vlan)
        return self._is_in_config(
            vlan_config, [VLAN_CONFIG % vlan, VLAN_NAME_CONFIG % vlan])

    def _vlan_range_matches(self, intf, expected_vlan_range):
        """Confirm that an interface's allowed VLAN range is as expected."""
        intf_config = self._get_running_ethernet_interface_config(intf)
        if expected_vlan_range:
            return self._is_in_config(
                intf_config, [INTERFACE_VLAN_CONFIG % expected_vlan_range])
        else:
            # If it's expected that no VLANs are being allowed on this
            # interface, then the interface configuration can either include
            # the 'none' form of vlan configuration ('switchport trunk allowed
            # vlan none'), or the vlan configuration line can be missing
            # entirely.
            return (self._is_in_config(
                intf_config, [INTERFACE_VLAN_CONFIG % 'none'])
                or not self._is_in_config(
                    intf_config, [INTERFACE_VLAN_CONFIG % '']))

    def _delete_vlan(self, vlan):
        """Delete a VLAN on the Nexus switch, if it exists."""
        if self._is_vlan_configured(vlan):
            config = nexus_snippets.EXEC_CONF_SNIPPET % (
                nexus_snippets.CMD_NO_VLAN_CONF_SNIPPET % vlan)
            self._nexus.edit_config('running', config)

    def _delete_interface_vlan(self, intf, vlan):
        """Delete a VLAN from an intf's allowed VLANs on Nexus switch."""
        config = nexus_snippets.EXEC_CONF_SNIPPET % (
            nexus_snippets.CMD_NO_VLAN_INT_SNIPPET % (intf, vlan))
        self._nexus.edit_config('running', config)

    @contextlib.contextmanager
    def _assertCreateTwoPorts(self, intf, vlan_1, vlan_2):
        """Create two network/subnet/ports and check Nexus config."""
        with self._create_net_subnet_port(name=NETWORK_NAME_1,
                                          cidr=CIDR_1,
                                          device_id=DEVICE_ID_1,
                                          no_delete=True) as port_1:
            self.assertTrue(self._is_vlan_configured(vlan_1))
            self.assertTrue(self._vlan_range_matches(intf, str(vlan_1)))

            with self._create_net_subnet_port(name=NETWORK_NAME_2,
                                              cidr=CIDR_2,
                                              device_id=DEVICE_ID_2,
                                              no_delete=True) as port_2:
                vlan_range = '%s-%s' % (vlan_1, vlan_2)
                self.assertTrue(self._is_vlan_configured(vlan_2))
                self.assertTrue(
                    self._vlan_range_matches(intf, vlan_range))

                yield (port_1, port_2)

    def test_nexus_create_delete_ports(self):
        """Verify Nexus config while two ports are created and deleted."""
        vlan_1 = VLAN_1
        vlan_2 = VLAN_2
        intf = NEXUS_INTERFACE

        # Clear VLAN configuration if necessary
        self._delete_vlan(vlan_1)
        self._delete_vlan(vlan_2)
        self._delete_interface_vlan(intf, vlan_1)
        self._delete_interface_vlan(intf, vlan_2)

        # Create 2 ports, delete the first, then delete the second
        with self._assertCreateTwoPorts(intf, vlan_1,
                                        vlan_2) as (port_1, port_2):

            # Delete first port, check Nexus config
            self._delete('ports', port_1['port']['id'])
            self.assertFalse(self._is_vlan_configured(vlan_1))
            self.assertTrue(self._is_vlan_configured(vlan_2))
            self.assertTrue(self._vlan_range_matches(intf, str(vlan_2)))

            # Delete second port, check Nexus config
            self._delete('ports', port_2['port']['id'])
            self.assertFalse(self._is_vlan_configured(vlan_2))
            self.assertTrue(self._vlan_range_matches(intf, ''))

        # Create 2 ports, delete the second, then delete the first
        with self._assertCreateTwoPorts(intf, vlan_1,
                                        vlan_2) as (port_1, port_2):
            # Delete second port, check Nexus config
            self._delete('ports', port_2['port']['id'])
            self.assertFalse(self._is_vlan_configured(vlan_2))
            self.assertTrue(self._is_vlan_configured(vlan_1))
            self.assertTrue(self._vlan_range_matches(intf, str(vlan_1)))

            # Delete first port, check Nexus config
            self._delete('ports', port_1['port']['id'])
            self.assertFalse(self._is_vlan_configured(vlan_1))
            self.assertTrue(self._vlan_range_matches(intf, ''))


class CiscoML2MechDriverSmokeTest(CiscoNexusSmokeTest):

    def setUp(self):
        """Configure for ML2 Mechanism Driver testing using a Nexus switch.

        This setup includes:
        - Configure the ML2 plugin to use VLANs in the range of 1000-1100.
        - Configure the Cisco mechanism driver to use a switch at
          NEXUS_IP_ADDR with credentials NEXUS_USER_NAME/NEXUS_PASSWORD

        """
        self.skip_if_not_nexus_smoke_test()

        self.addCleanup(mock.patch.stopall)

        # Configure the ML2 mechanism drivers and network types
        ml2_opts = {
            'mechanism_drivers': ['cisco_nexus'],
            'tenant_network_types': ['vlan'],
        }
        for opt, val in ml2_opts.items():
            ml2_config.cfg.CONF.set_override(opt, val, 'ml2')
        self.addCleanup(ml2_config.cfg.CONF.reset)

        # Configure the ML2 VLAN parameters
        phys_vrange = ':'.join([PHYS_NET, str(VLAN_START), str(VLAN_END)])
        ml2_vlan_config.cfg.CONF.set_override('network_vlan_ranges',
                                              [phys_vrange],
                                              'ml2_type_vlan')
        self.addCleanup(ml2_vlan_config.cfg.CONF.reset)

        # Configure the Cisco Nexus mechanism driver
        nexus_config = {
            (NEXUS_IP_ADDR, 'username'): NEXUS_USER_NAME,
            (NEXUS_IP_ADDR, 'password'): NEXUS_PASSWORD,
            (NEXUS_IP_ADDR, 'ssh_port'): NEXUS_PORT,
            (NEXUS_IP_ADDR, COMP_HOST_NAME): NEXUS_INTERFACE,
        }
        nexus_patch = mock.patch.dict(
            ml2_cisco_config.ML2MechCiscoConfig.nexus_dict,
            nexus_config)
        nexus_patch.start()
        self.addCleanup(nexus_patch.stop)

        # Mock mech driver's _is_status_active method
        mock_status = mock.patch.object(
            mech_cisco_nexus.CiscoNexusMechanismDriver,
            '_is_status_active').start()
        mock_status.return_value = n_const.PORT_STATUS_ACTIVE

        # Mock mechanism driver's _get_vlanid method
        def _mock_get_vlanid(context):
            port = context.current
            if port['device_id'] == DEVICE_ID_1:
                return VLAN_START
            else:
                return VLAN_START + 1
        mock_vlanid = mock.patch.object(
            mech_cisco_nexus.CiscoNexusMechanismDriver,
            '_get_vlanid').start()
        mock_vlanid.side_effect = _mock_get_vlanid

        self.core_plugin = ML2_PLUGIN
        self.do_update_after_port_create = True
        super(CiscoML2MechDriverSmokeTest, self).setUp()


class CiscoNexusPluginSmokeTest(CiscoNexusSmokeTest):

    def setUp(self):
        """Configure for Cisco Nexus plugin testing using a Nexus Switch.

        This setup includes:
        - Configure the OVS plugin to use VLANs in the range of
          VLAN_START-VLAN_END.
        - Configure the Cisco plugin model to use the Nexus driver.
        - Configure the Nexus driver to use a Nexus switch at NEXUS_IP_ADDR,
          with credentials NEXUS_USER_NAME/NEXUS_PASSWORD.

        """
        self.skip_if_not_nexus_smoke_test()

        # Configure the OVS and Cisco plugins
        phys_bridge = ':'.join([PHYS_NET, BRIDGE_NAME])
        phys_vlan_range = ':'.join([PHYS_NET, str(VLAN_START), str(VLAN_END)])
        config = {
            ovs_config: {
                'OVS': {
                    'bridge_mappings': phys_bridge,
                    'network_vlan_ranges': [phys_vlan_range],
                    'tenant_network_type': 'vlan',
                },
            },
            cisco_plugin_config: {
                'CISCO': {'nexus_driver': NEXUS_DRIVER},
                'CISCO_PLUGINS': {'nexus_plugin': NEXUS_PLUGIN},
            },
        }
        for module in config:
            for group in config[module]:
                for opt, val in config[module][group].items():
                    module.cfg.CONF.set_override(opt, val, group)
            self.addCleanup(module.cfg.CONF.reset)

        # Configure the Nexus switch dictionary
        nexus_config = {
            (NEXUS_DEV_ID, NEXUS_IP_ADDR, 'username'): NEXUS_USER_NAME,
            (NEXUS_DEV_ID, NEXUS_IP_ADDR, 'password'): NEXUS_PASSWORD,
            (NEXUS_DEV_ID, NEXUS_IP_ADDR, 'ssh_port'): NEXUS_PORT,
            (NEXUS_DEV_ID, NEXUS_IP_ADDR, COMP_HOST_NAME): NEXUS_INTERFACE,
        }
        patch = mock.patch.dict(cisco_plugin_config.device_dictionary,
                                nexus_config)
        patch.start()
        self.addCleanup(patch.stop)

        self.core_plugin = CISCO_CORE_PLUGIN
        self.do_update_after_port_create = False
        super(CiscoNexusPluginSmokeTest, self).setUp()
