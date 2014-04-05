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

from neutron import context as q_context
from neutron.db import agents_db
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.l3.common import constants as cl3_const
from neutron.plugins.cisco.l3.db import (l3_routertype_aware_schedulers_db as
                                         router_sch_db)
from neutron.tests.unit import test_l3_plugin
from neutron.tests.unit import test_l3_schedulers


_uuid = uuidutils.generate_uuid


class TestNoL3NatPlugin(test_l3_plugin.TestNoL3NatPlugin,
                        agents_db.AgentDbMixin):
    supported_extension_aliases = ["external-net", "agent"]


class L3RoutertypeAwareSchedulerTestCase(
    test_l3_schedulers.L3SchedulerTestCase,
        router_sch_db.L3RouterTypeAwareSchedulerDbMixin):

    def setUp(self):
        # the plugin without L3 support
        plugin = ('neutron.tests.unit.cisco.l3.'
                  'test_l3_routertype_aware_schedulers.TestNoL3NatPlugin')
        # the L3 service plugin
        l3_plugin = (
            'neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin.'
            'TestL3RouterAppliancePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        ext_mgr = test_l3_schedulers.L3SchedulerTestExtensionManager()
        # call grandparent's setUp() to avoid that wrong plugin and
        # extensions are used.
        super(test_l3_schedulers.L3SchedulerTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)

        cfg.CONF.set_override('default_router_type',
                              cl3_const.NAMESPACE_ROUTER_TYPE)

        #TODO(bobmel): use contextmanager to create router types etc
        self._register_hosting_device_templates()
        self._register_routertypes()

        #TODO(bobmel): BEGIN OF remove code
        self.ns_router_type = {
            'id': _uuid(),
            'name': cl3_const.NAMESPACE_ROUTER_TYPE,
            'description': '',
            'template_id': '',
            'slot_need': 0,
            'scheduler': mock.Mock(),
            'cfg_agent_driver': mock.Mock()}

        # Mock router type
        self.mock1 = mock.patch(
            'neutron.plugins.cisco.l3.db.l3_router_appliance_db.'
            'L3RouterApplianceDBMixin.get_router_type',
            mock.Mock(return_value=self.ns_router_type))
        self.mock1.start()

        # Mock router type
        self.mock2 = mock.patch(
            'neutron.plugins.cisco.l3.db.l3_router_appliance_db.'
            'L3RouterApplianceDBMixin.get_namespace_router_type_id',
            mock.Mock(return_value=self.ns_router_type['id']))
        self.mock2.start()
        #TODO(bobmel): END OF remove code

        self.adminContext = q_context.get_admin_context()
        self.plugin = manager.NeutronManager.get_plugin()
        self._register_l3_agents()


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

