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

import mock
from oslo.config import cfg
from oslo_log import log as logging

import neutron
from neutron.api.v2 import attributes
from neutron.db import agents_db
from neutron.extensions import extraroute
from neutron.extensions import l3
from neutron.extensions import providernet as pnet
from neutron import manager
from neutron.plugins.cisco.common import cisco_constants as c_const
from neutron.plugins.cisco.device_manager import service_vm_lib
from neutron.plugins.cisco.extensions import routertype
from neutron.plugins.common import constants as service_constants
from neutron.tests.unit.cisco.device_manager import device_manager_test_support
from neutron.tests.unit.cisco.device_manager import test_db_device_manager
from neutron.tests.unit.cisco.l3 import l3_router_test_support
from neutron.tests.unit.cisco.l3 import test_db_routertype
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_extension_extraroute as test_ext_extraroute
from neutron.tests.unit import test_l3_plugin

LOG = logging.getLogger(__name__)


CORE_PLUGIN_KLASS = device_manager_test_support.CORE_PLUGIN_KLASS
L3_PLUGIN_KLASS = (
    "neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin."
    "TestApplianceL3RouterServicePlugin")
extensions_path = neutron.plugins.__path__[0] + '/cisco/extensions'


class TestL3RouterApplianceExtensionManager(
        test_db_routertype.L3TestRoutertypeExtensionManager):

    def get_resources(self):
        l3.RESOURCE_ATTRIBUTE_MAP['routers'].update(
            extraroute.EXTENDED_ATTRIBUTES_2_0['routers'])
        return super(TestL3RouterApplianceExtensionManager,
                     self).get_resources()


class TestNoL3NatPlugin(test_l3_plugin.TestNoL3NatPlugin,
                        agents_db.AgentDbMixin):

    # There is no need to expose agent REST API
    supported_extension_aliases = ["external-net", "provider"]
    NET_TYPE = 'vlan'

    def __init__(self):
        self.tags = {}
        self.tag = 1
        super(TestNoL3NatPlugin, self).__init__()

    def _make_network_dict(self, network, fields=None,
                           process_extensions=True):
        res = {'id': network['id'],
               'name': network['name'],
               'tenant_id': network['tenant_id'],
               'admin_state_up': network['admin_state_up'],
               'status': network['status'],
               'shared': network['shared'],
               'subnets': [subnet['id']
                           for subnet in network['subnets']]}
        try:
            tag = self.tags[network['id']]
        except KeyError:
            self.tag += 1
            tag = self.tag
            self.tags[network['id']] = tag
        res.update({pnet.PHYSICAL_NETWORK: 'phy',
                    pnet.NETWORK_TYPE: self.NET_TYPE,
                    pnet.SEGMENTATION_ID: tag})
        # Call auxiliary extend functions, if any
        if process_extensions:
            self._apply_dict_extend_functions(
                attributes.NETWORKS, res, network)
        return self._fields(res, fields)

    def get_network_profiles(self, context, filters=None, fields=None):
        return [{'id': "1234"}]

    def get_policy_profiles(self, context, filters=None, fields=None):
        return [{'id': "4321"}]


# A set routes capable L3 routing service plugin class supporting appliances
class TestApplianceL3RouterServicePlugin(
        l3_router_test_support.TestL3RouterServicePlugin):

    supported_extension_aliases = ["router", "extraroute",
                                   routertype.ROUTERTYPE_ALIAS]


class L3RouterApplianceTestCaseBase(
    test_db_plugin.NeutronDbPluginV2TestCase,
    test_db_routertype.RoutertypeTestCaseMixin,
    test_db_device_manager.DeviceManagerTestCaseMixin,
    l3_router_test_support.L3RouterTestSupportMixin,
        device_manager_test_support.DeviceManagerTestSupportMixin):

    resource_prefix_map = (test_db_device_manager.TestDeviceManagerDBPlugin
                           .resource_prefix_map)
    router_type = None

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()
        if not core_plugin:
            core_plugin = CORE_PLUGIN_KLASS
        if l3_plugin is None:
            l3_plugin = L3_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin}
        cfg.CONF.set_override('api_extensions_path',
                              l3_router_test_support.extensions_path)

        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        if ext_mgr is None:
            ext_mgr = TestL3RouterApplianceExtensionManager()

        super(L3RouterApplianceTestCaseBase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins,
            ext_mgr=ext_mgr)

        self.core_plugin = manager.NeutronManager.get_plugin()
        self.plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)

        self.setup_notification_driver()

        cfg.CONF.set_override('allow_sorting', True)
        self._define_keystone_authtoken()

        cfg.CONF.register_opt(
            cfg.BoolOpt('router_auto_schedule', default=True,
                        help=_('Allow auto scheduling of routers to '
                               'L3 agent.')))
        if self.router_type is not None:
            cfg.CONF.set_override('default_router_type', self.router_type,
                                  group='routing')

        self._mock_l3_admin_tenant()
        self._create_mgmt_nw_for_tests(self.fmt)
 #       templates = self._test_create_hosting_device_templates()
 #       self._test_create_routertypes(templates.values())
        self.core_plugin._svc_vm_mgr_obj = service_vm_lib.ServiceVMManager()
#        self._mock_svc_vm_create_delete(self.core_plugin)
        self._mock_io_file_ops()
        self._mock_cfg_agent_notifier(self.plugin)

    def restore_attribute_map(self):
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def tearDown(self):
        self._test_remove_routertypes()
        self._test_remove_hosting_device_templates()
        self._remove_mgmt_nw_for_tests()
        (neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin.
            TestApplianceL3RouterServicePlugin._mgmt_nw_uuid) = None
        (neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin.
            TestApplianceL3RouterServicePlugin._refresh_router_backlog) = True
        (neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin.
            TestApplianceL3RouterServicePlugin._nova_running) = False
        #TODO(bobmel): Investigate why the following lines need to be disabled
#        plugin = manager.NeutronManager.get_service_plugins()[
#            service_constants.L3_ROUTER_NAT]
#        plugin._heartbeat.stop()
        self.restore_attribute_map()
        super(L3RouterApplianceTestCaseBase, self).tearDown()


class L3RouterApplianceNamespaceTestCase(
    test_l3_plugin.L3NatTestCaseBase,
    test_ext_extraroute.ExtraRouteDBTestCaseBase,
        L3RouterApplianceTestCaseBase):

    router_type = c_const.NAMESPACE_ROUTER_TYPE

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin._check_and_get_fip_assoc')


class L3RouterApplianceVMTestCase(
    L3RouterApplianceNamespaceTestCase):

    router_type = c_const.CSR1KV_ROUTER_TYPE

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        super(L3RouterApplianceVMTestCase, self).setUp(
            core_plugin=core_plugin, l3_plugin=l3_plugin, dm_plugin=dm_plugin,
            ext_mgr=ext_mgr)

        self._mock_svc_vm_create_delete(self.core_plugin)
        self._mock_get_routertype_scheduler_always_none()


class L3AgentRouterApplianceTestCase(L3RouterApplianceTestCaseBase,
                                     test_l3_plugin.L3AgentDbTestCaseBase):

    router_type = c_const.NAMESPACE_ROUTER_TYPE

    def _test_notify_op_agent(self, target_func, *args):
        kargs = [item for item in args]
        kargs.append(self._l3_agent_mock)
        target_func(*kargs)


class L3CfgAgentRouterApplianceTestCase(L3RouterApplianceTestCaseBase,
                                        test_l3_plugin.L3AgentDbTestCaseBase):

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        super(L3CfgAgentRouterApplianceTestCase, self).setUp(
            core_plugin=core_plugin, l3_plugin=l3_plugin, dm_plugin=dm_plugin,
            ext_mgr=ext_mgr)

        self.orig_get_sync_data = self.plugin.get_sync_data
        self.plugin.get_sync_data = self.plugin.get_sync_data_ext

        self._mock_get_routertype_scheduler_always_none()

    def tearDown(self):
        self.plugin.get_sync_data = self.orig_get_sync_data
        super(L3CfgAgentRouterApplianceTestCase, self).tearDown()

    def _test_notify_op_agent(self, target_func, *args):
        kargs = [item for item in args]
        kargs.append(self._cfg_agent_mock)
        target_func(*kargs)
