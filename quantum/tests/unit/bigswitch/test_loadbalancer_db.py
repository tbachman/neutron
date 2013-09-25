# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Big Switch Networks, Inc.  All rights reserved.
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
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com
#

import os

from quantum.api.extensions import ExtensionMiddleware
from quantum.api.extensions import PluginAwareExtensionManager
from quantum.common import config
import quantum.extensions
from quantum.plugins.bigswitch.plugin import QuantumRestProxyV2
from quantum.plugins.common import constants
from quantum.tests.unit.db.loadbalancer import test_db_loadbalancer


DB_CORE_PLUGIN_KLASS = (
"quantum.plugins.bigswitch.plugin.QuantumRestProxyV2"
)
DB_LB_PLUGIN_KLASS = (
"quantum.plugins.bigswitch.plugin.QuantumRestProxyV2"
)
ROOTDIR = os.path.dirname(__file__) + '../../..'
ETCDIR = os.path.join(ROOTDIR, 'etc')

extensions_path = ':'.join(quantum.extensions.__path__)


def new_setUp(self, core_plugin=None, lb_plugin=None):
    service_plugins = {'lb_plugin_name': DB_LB_PLUGIN_KLASS}

    super(test_db_loadbalancer.LoadBalancerPluginDbTestCase,
          self).setUp(service_plugins=service_plugins)

    self._subnet_id = "0c798ed8-33ba-11e2-8b28-000c291c4d14"

    plugin = QuantumRestProxyV2()
    ext_mgr = PluginAwareExtensionManager(
        extensions_path,
        {constants.LOADBALANCER: plugin}
    )
    app = config.load_paste_app('extensions_test_app')
    self.ext_api = ExtensionMiddleware(app, ext_mgr=ext_mgr)


orig_setUp = test_db_loadbalancer.TestLoadBalancer.setUp


class TestBigSwitchProxyLoadBalancer(test_db_loadbalancer.TestLoadBalancer):

    def setUp(self, core_plugin=None, lb_plugin=None):
        test_db_loadbalancer.TestLoadBalancer.setUp = new_setUp
        super(TestBigSwitchProxyLoadBalancer, self).setUp()

    def tearDown(self):
        test_db_loadbalancer.TestLoadBalancer.setUp = orig_setUp
