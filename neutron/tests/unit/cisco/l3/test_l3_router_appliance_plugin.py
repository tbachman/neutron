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
# @author: Bob Melander, Cisco Systems, Inc.

import mock
from oslo.config import cfg

import neutron
from neutron.manager import NeutronManager
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.db.l3 import device_handling_db
from neutron.plugins.cisco.db.l3 import l3_router_appliance_db
from neutron.plugins.cisco.l3.rpc import l3_rpc_agent_api_noop
from neutron.plugins.cisco.l3 import service_vm_lib

from neutron.plugins.common import constants as service_constants
from neutron.tests.unit.cisco.l3 import device_handling_test_support
from neutron.tests.unit import test_extension_extraroute as test_ext_extraroute
from neutron.tests.unit import test_l3_plugin
from neutron.tests.unit import test_db_plugin

LOG = logging.getLogger(__name__)


CORE_PLUGIN_KLASS = 'neutron.tests.unit.test_l3_plugin.TestNoL3NatPlugin'
L3_PLUGIN_KLASS = (
    "neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin."
    "TestApplianceL3RouterServicePlugin")
extensions_path = neutron.plugins.__path__[0] + '/cisco/extensions'


# A set routes capable L3 routing service plugin class supporting appliances
class TestApplianceL3RouterServicePlugin(
    test_l3_plugin.TestL3NatServicePlugin,
    device_handling_db.DeviceHandlingMixin,
        l3_router_appliance_db.L3RouterApplianceDBMixin):

    supported_extension_aliases = ["router", "extraroute"]
    # Disable notifications from l3 base class to l3 agents
    l3_rpc_notifier = l3_rpc_agent_api_noop.L3AgentNotifyNoOp


class L3RouterApplianceTestCaseBase(
    test_db_plugin.NeutronDbPluginV2TestCase,
        device_handling_test_support.DeviceHandlingTestSupportMixin):

    def setUp(self, core_plugin=None, l3_plugin=None, ext_mgr=None):
        if not core_plugin:
            core_plugin = CORE_PLUGIN_KLASS
        if l3_plugin is None:
            l3_plugin = L3_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin}
        cfg.CONF.set_override('api_extensions_path', extensions_path)

        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        if ext_mgr is None:
            ext_mgr = test_ext_extraroute.ExtraRouteTestExtensionManager()

        super(L3RouterApplianceTestCaseBase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins,
            ext_mgr=ext_mgr)

        self.setup_notification_driver()

        cfg.CONF.set_override('allow_sorting', True)
        test_opts = [
            cfg.StrOpt('auth_protocol', default='http'),
            cfg.StrOpt('auth_host', default='localhost'),
            cfg.IntOpt('auth_port', default=35357),
            cfg.StrOpt('admin_user', default='neutron'),
            cfg.StrOpt('admin_password', default='secrete')]
        cfg.CONF.register_opts(test_opts, 'keystone_authtoken')

        self._mock_l3_admin_tenant()
        self._create_mgmt_nw_for_tests(self.fmt)
        self._mock_svc_vm_create_delete()
        l3_plugin_obj = NeutronManager.get_service_plugins()[
            service_constants.L3_ROUTER_NAT]
        l3_plugin_obj._svc_vm_mgr = service_vm_lib.ServiceVMManager()

    def tearDown(self):
        self._remove_mgmt_nw_for_tests()
        (neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin.
            TestApplianceL3RouterServicePlugin._mgmt_nw_uuid) = None
        super(L3RouterApplianceTestCaseBase, self).tearDown()


class L3RouterApplianceVMTestCase(
    test_l3_plugin.L3NatTestCaseBase,
    test_ext_extraroute.ExtraRouteDBTestCaseBase,
        L3RouterApplianceTestCaseBase):

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        super(L3RouterApplianceVMTestCase, self).setUp(
            core_plugin=core_plugin, l3_plugin=l3_plugin, ext_mgr=ext_mgr)

        self._mock_svc_vm_create_delete()


#class L3RouterApplianceVMTestCaseXML(L3RouterApplianceVMTestCase):
#    fmt = 'xml'


class L3AgentRouterApplianceVMTestCase(L3RouterApplianceTestCaseBase,
                                       test_l3_plugin.L3AgentDbTestCaseBase):

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        self.core_plugin = test_l3_plugin.TestNoL3NatPlugin()
        # service plugin providing L3 routing
        self.plugin = TestApplianceL3RouterServicePlugin()
        self.orig_get_sync_data = self.plugin.get_sync_data
        self.plugin.get_sync_data = self.plugin.get_sync_data_ext

        super(L3AgentRouterApplianceVMTestCase, self).setUp(
            core_plugin=core_plugin, l3_plugin=l3_plugin, ext_mgr=ext_mgr)

        self._mock_svc_vm_create_delete()

    def tearDown(self):
        self.plugin.get_sync_data = self.orig_get_sync_data
        super(L3AgentRouterApplianceVMTestCase, self).tearDown()

    def _test_notify_op_agent(self, target_func, *args):
        l3_rpc_agent_api_str = (
            'neutron.plugins.cisco.l3.rpc.l3_router_rpc_joint_agent_api'
            '.L3RouterJointAgentNotifyAPI')
        plugin = NeutronManager.get_service_plugins()[
            service_constants.L3_ROUTER_NAT]
        oldNotify = plugin.l3_rpc_notifier
        try:
            with mock.patch(l3_rpc_agent_api_str) as notifyApi:
                plugin.l3_rpc_notifier = notifyApi
                kargs = [item for item in args]
                kargs.append(notifyApi)
                target_func(*kargs)
        except Exception:
            plugin.l3_rpc_notifier = oldNotify
            raise
        else:
            plugin.l3_rpc_notifier = oldNotify
