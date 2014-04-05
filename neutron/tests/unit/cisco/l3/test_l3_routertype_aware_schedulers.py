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

from oslo.config import cfg

from neutron.common import constants
from neutron import context as q_context
from neutron import manager
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.l3.common import constants as cl3_const
from neutron.plugins.cisco.l3.db import (l3_routertype_aware_schedulers_db as
                                         router_sch_db)
from neutron.plugins.cisco.l3.extensions import routertype
from neutron.tests.unit.cisco.device_manager import device_manager_convenience
from neutron.tests.unit.cisco.device_manager import test_db_device_manager
from neutron.tests.unit.cisco.l3 import l3_router_convenience
from neutron.tests.unit.cisco.l3 import test_db_routertype
from neutron.tests.unit import test_l3_schedulers

LOG = logging.getLogger(__name__)


CORE_PLUGIN_KLASS = device_manager_convenience.CORE_PLUGIN_KLASS
L3_PLUGIN_KLASS = (
    "neutron.tests.unit.cisco.l3.test_l3_routertype_aware_schedulers."
    "TestL3RouterServicePlugin")


# A scheduler-enabled routertype capable L3 routing service plugin class
class TestL3RouterServicePlugin(
    l3_router_convenience.TestL3RouterServicePlugin,
        router_sch_db.L3RouterTypeAwareSchedulerDbMixin):

    supported_extension_aliases = ["router", routertype.ROUTERTYPE_ALIAS,
                                   constants.L3_AGENT_SCHEDULER_EXT_ALIAS]

    def __init__(self):
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_type_aware_scheduler_driver)
        self.l3agent_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)


class L3RoutertypeAwareSchedulerTestCase(
    test_l3_schedulers.L3SchedulerTestCase,
        router_sch_db.L3RouterTypeAwareSchedulerDbMixin,
        test_db_routertype.RoutertypeTestCaseMixin,
        test_db_device_manager.DeviceManagerTestCaseMixin,
        l3_router_convenience.L3RouterConvenienceMixin,
        device_manager_convenience.DeviceManagerConvenienceMixin):

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
                              l3_router_convenience.extensions_path)
        ext_mgr = test_db_routertype.L3TestRoutertypeExtensionManager()
        # call grandparent's setUp() to avoid that wrong plugin and
        # extensions are used.
        super(test_l3_schedulers.L3SchedulerTestCase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins,
            ext_mgr=ext_mgr)

        cfg.CONF.set_override('default_router_type',
                              cl3_const.NAMESPACE_ROUTER_TYPE)

        self.adminContext = q_context.get_admin_context()
        self.plugin = manager.NeutronManager.get_plugin()
        self._register_l3_agents()

        templates = self._test_create_hosting_device_templates()
        self._test_create_routertypes(
            templates['network_node']['hosting_device_template']['id'])
        self._create_mgmt_nw_for_tests(self.fmt)

        self._mock_l3_admin_tenant()
        self._mock_svc_vm_create_delete()

    def tearDown(self):
        self._remove_mgmt_nw_for_tests()
        self._test_remove_routertypes()
        self._test_remove_hosting_device_templates()
        super(L3RoutertypeAwareSchedulerTestCase, self).tearDown()


class L3RoutertypeAwareChanceSchedulerTestCase(
    test_l3_schedulers.L3AgentChanceSchedulerTestCase,
        L3RoutertypeAwareSchedulerTestCase):
    pass


class L3RoutertypeAwareLeastRoutersSchedulerTestCase(
    test_l3_schedulers.L3AgentLeastRoutersSchedulerTestCase,
        L3RoutertypeAwareSchedulerTestCase):

    def setUp(self):
        cfg.CONF.set_override('router_scheduler_driver',
                              'neutron.scheduler.l3_agent_scheduler.'
                              'LeastRoutersScheduler')
        super(L3RoutertypeAwareLeastRoutersSchedulerTestCase, self).setUp()
