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

import copy
import mock

from oslo.config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.common import constants
from neutron.common import test_lib
from neutron import context as q_context
from neutron import manager
from neutron.plugins.common import constants as plugin_consts
from neutron.plugins.cisco.common import cisco_constants as c_const
from neutron.plugins.cisco.db.scheduler import (
    l3_routertype_aware_schedulers_db as router_sch_db)
from neutron.plugins.cisco.device_manager.rpc import devmgr_rpc_cfgagent_api
from neutron.plugins.cisco.extensions import routerhostingdevice
from neutron.plugins.cisco.extensions import routertype
from neutron.plugins.cisco.l3.rpc import l3_router_rpc_cfg_agent_api
from neutron.tests import base
from neutron.tests.unit.cisco.device_manager import device_manager_test_support
from neutron.tests.unit.cisco.device_manager import test_db_device_manager
from neutron.tests.unit.cisco.l3 import l3_router_test_support
from neutron.tests.unit.cisco.l3 import test_db_routertype
from neutron.tests.unit.cisco.l3 import test_l3_router_appliance_plugin
from neutron.tests.unit import test_l3_plugin
from neutron.tests.unit import test_l3_schedulers

LOG = logging.getLogger(__name__)


CORE_PLUGIN_KLASS = device_manager_test_support.CORE_PLUGIN_KLASS
L3_PLUGIN_KLASS = (
    "neutron.tests.unit.cisco.l3.test_l3_routertype_aware_schedulers."
    "TestSchedulingCapableL3RouterServicePlugin")


# A scheduler-enabled routertype capable L3 routing service plugin class
class TestSchedulingCapableL3RouterServicePlugin(
    l3_router_test_support.TestL3RouterServicePlugin,
        router_sch_db.L3RouterTypeAwareSchedulerDbMixin):

    supported_extension_aliases = ["router", routertype.ROUTERTYPE_ALIAS,
                                   constants.L3_AGENT_SCHEDULER_EXT_ALIAS]

    def __init__(self):
        self.agent_notifiers.update(
            {constants.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI(),
             c_const.AGENT_TYPE_L3_CFG:
             l3_router_rpc_cfg_agent_api.L3RouterCfgAgentNotifyAPI(self),
             c_const.AGENT_TYPE_CFG:
             devmgr_rpc_cfgagent_api.DeviceMgrCfgAgentNotifyAPI})
        self.router_scheduler = importutils.import_object(
            cfg.CONF.routing.router_type_aware_scheduler_driver)
        self.l3agent_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)


class L3RoutertypeAwareL3AgentSchedulerTestCase(
    test_l3_schedulers.L3SchedulerTestCase,
        test_db_routertype.RoutertypeTestCaseMixin,
        test_db_device_manager.DeviceManagerTestCaseMixin,
        l3_router_test_support.L3RouterTestSupportMixin,
        device_manager_test_support.DeviceManagerTestSupportMixin):

    resource_prefix_map = (test_db_device_manager.TestDeviceManagerDBPlugin
                           .resource_prefix_map)

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        if not core_plugin:
            core_plugin = CORE_PLUGIN_KLASS
        if l3_plugin is None:
            l3_plugin = L3_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin}

        cfg.CONF.set_override('api_extensions_path',
                              l3_router_test_support.extensions_path)
        ext_mgr = test_db_routertype.L3TestRoutertypeExtensionManager()

        # call grandparent's setUp() to avoid that wrong plugin and
        # extensions are used.
        super(test_l3_schedulers.L3SchedulerTestCase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins,
            ext_mgr=ext_mgr)

        self._define_keystone_authtoken()
        cfg.CONF.set_override('default_router_type',
                              c_const.NAMESPACE_ROUTER_TYPE, group='routing')

        self.adminContext = q_context.get_admin_context()
        self.plugin = manager.NeutronManager.get_plugin()
        self.l3_plugin = manager.NeutronManager.get_service_plugins().get(
            plugin_consts.L3_ROUTER_NAT)
        # work-around to make some tests in super class, which assumes core
        # plugin does the l3 routing, run correctly
        self.plugin.router_scheduler = (
            self.l3_plugin.l3agent_scheduler)
        self._register_l3_agents()

        self._mock_l3_admin_tenant()
        templates = self._test_create_hosting_device_templates()
        self._test_create_routertypes(templates.values())

    def tearDown(self):
        self._test_remove_routertypes()
        self._test_remove_hosting_device_templates()
        super(L3RoutertypeAwareL3AgentSchedulerTestCase, self).tearDown()


class L3RoutertypeAwareChanceL3AgentSchedulerTestCase(
    test_l3_schedulers.L3AgentChanceSchedulerTestCase,
        L3RoutertypeAwareL3AgentSchedulerTestCase):

    def test_scheduler_auto_schedule_when_agent_added(self):
        # in our test setup the auto_schedule_routers function is provided by
        # the separate l3 service plugin, not the core plugin
        self.plugin.auto_schedule_routers = (
            self.l3_plugin.auto_schedule_routers)
        super(L3RoutertypeAwareChanceL3AgentSchedulerTestCase,
              self).test_scheduler_auto_schedule_when_agent_added()


class L3RoutertypeAwareLeastRoutersL3AgentSchedulerTestCase(
    test_l3_schedulers.L3AgentLeastRoutersSchedulerTestCase,
        L3RoutertypeAwareL3AgentSchedulerTestCase):

    def setUp(self):
        cfg.CONF.set_override('router_scheduler_driver',
                              'neutron.scheduler.l3_agent_scheduler.'
                              'LeastRoutersScheduler')
        # call grandparent's setUp() to avoid that wrong scheduler is used
        super(test_l3_schedulers.L3AgentLeastRoutersSchedulerTestCase,
              self).setUp()


#TODO(bobmel): Activate unit tests for DVR

#TODO(bobmel): Add unit tests for HA in Cisco devices (not Linux namespaces)


class L3RoutertypeAwareHostingDeviceSchedulerBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(L3RoutertypeAwareHostingDeviceSchedulerBaseTestCase,
              self).setUp()
#        self.scheduler = FakeL3Scheduler()
        self.plugin = mock.Mock()

    def test_new_router_is_backlogged(self):
        pass

    def test_backlogged_router_is_scheduled_if_hosting_device(self):
        pass

    def test_router_remains_backlogged_if_no_hosting_device(self):
        pass


class L3RoutertypeAwareHostingDeviceScheduler(
    test_l3_plugin.L3NatTestCaseMixin,
        test_l3_router_appliance_plugin.L3RouterApplianceTestCaseBase):

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        # save possible test_lib.test_config 'config_files' dict entry so we
        # can restore it after tests since we will change its value
        self._old_config_files = copy.copy(test_lib.test_config.get(
            'config_files'))
        if l3_plugin is None:
            l3_plugin = L3_PLUGIN_KLASS
        super(L3RoutertypeAwareHostingDeviceScheduler, self).setUp(
            core_plugin, l3_plugin, dm_plugin, ext_mgr)
        # include config files for device manager service plugin and router
        # service plugin since we define a number of hosting device templates,
        # hosting devices and routertypes there
        self._add_device_manager_plugin_ini_file()
        self._add_router_plugin_ini_file()
        #TODO(bobmel): Fix bug in test_extensions.py and we can remove the
        # below call to setup_config()
        self.setup_config()
        # do pool management in same green thread
        self._mock_eventlet_greenpool_spawn_n()
        self._mock_svc_vm_create_delete(self.core_plugin)
        # set a very long processing interval and instead call the
        # _process_backlogged_routers function directly in the tests
        cfg.CONF.set_override('backlog_processing_interval', 100,
                              group='routing')

    def tearDown(self):
        if self._old_config_files is None:
            test_lib.test_config.pop('config_files', None)
        else:
            test_lib.test_config['config_files'] = self._old_config_files
        super(L3RoutertypeAwareHostingDeviceScheduler, self).tearDown()

    def bob_test(self):
        with self.subnet() as s:
            self._set_net_external(s['subnet']['network_id'])
            with self.router(external_gateway_info={
                    'network_id': s['subnet']['network_id']}) as router:
                r = router['router']
                self.assertIsNone(r[routerhostingdevice.HOSTING_DEVICE_ATTR])
                self.plugin._process_backlogged_routers()
                self.assertIsNotNone(
                    r[routerhostingdevice.HOSTING_DEVICE_ATTR])

    def test_add_router_to_hosting_device(self):
        pass

    def test_schedule_router_distributed(self):
        pass

    def test_get_hosting_device_candidates(self):
        pass

    def test_get_hosting_devices_hosting_routers(self):
        pass

    #####

    def test_router_reschedule_from_dead_hosting_device(self):
        pass

    def test_router_no_reschedule_from_dead_admin_down_hosting_device(self):
        pass

    def test_rpc_sync_routers_ext(self):
        pass

    def test_router_auto_schedule_for_specified_routers(self):
        pass

    def test_router_schedule_with_hosting_device_candidates(self):
        pass

    def test_router_without_l3_cfg_agents(self):
        pass

    def test_router_without_hosting_devices(self):
        pass

    def test_router_sync_data(self):
        pass

    def test_router_add_to_hosting_device(self):
        pass

    def test_router_add_to_hosting_device_insufficient_slots(self):
        pass

    def test_router_add_to_hosting_device_with_admin_state_down(self):
        pass

    def test_router_add_to_hosting_device_two_times(self):
        pass

    def test_router_add_to_two_hosting_devices(self):
        pass

    def test_router_policy(self):
        pass

    def test_hosting_device_keep_services_off(self):
        # Introduce new option: keep_services_on_agents_with_admin_state_down
        # Here set to keep_services_on_agents_with_admin_state_down = False
        # routers on hosting device that is set to admin down should be removed
        #  from that hosting device
        pass

    def test_hosting_device_keep_services_on(self):
        # Introduce new option: keep_services_on_agents_with_admin_state_down
        # Here set to keep_services_on_agents_with_admin_state_down = False
        # routers on hosting device that set to admin down should stay on that
        # hosting device
        pass

    def test_list_routers_by_hosting_device_with_invalid_hosting_device(self):
        pass


class HostingDeviceRouterL3CfgAgentNotifierTestCase():

    def test_router_add_to_hosting_device_notification(self):
        pass

    def test_router_remove_from_hosting_device_notification(self):
        pass
