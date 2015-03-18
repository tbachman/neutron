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

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.db import common_db_mixin
from neutron.extensions import l3
import neutron.plugins
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.db.l3 import l3_router_appliance_db
from neutron.plugins.cisco.db.l3 import routertype_db
from neutron.plugins.cisco.extensions import routertype
from neutron.plugins.common import constants as service_constants
#from neutron.plugins.cisco.l3.rpc import l3_rpc_agent_api_noop
from neutron.tests.unit import test_l3_plugin

LOG = logging.getLogger(__name__)


L3_PLUGIN_KLASS = (
    "neutron.tests.unit.cisco.l3.l3_router_test_support."
    "TestL3RouterServicePlugin")
extensions_path = neutron.plugins.__path__[0] + '/cisco/extensions'


class L3RouterTestSupportMixin:

    def _mock_get_routertype_scheduler_always_none(self):
        self.get_routertype_scheduler_fcn_p = mock.patch(
            'neutron.plugins.cisco.db.l3.l3_router_appliance_db.'
            'L3RouterApplianceDBMixin._get_router_type_scheduler',
            mock.Mock(return_value=None))
        self.get_routertype_scheduler_fcn_p.start()

    def _mock_cfg_agent_notifier(self, plugin):
        # Mock notifications to l3 agent and Cisco config agent
        self._l3_agent_mock = mock.MagicMock()
        self._cfg_agent_mock = mock.MagicMock()
        plugin.agent_notifiers = {
            constants.AGENT_TYPE_L3: self._l3_agent_mock,
            cisco_constants.AGENT_TYPE_L3_CFG: self._cfg_agent_mock}

    def _define_keystone_authtoken(self):
        test_opts = [
            cfg.StrOpt('auth_uri', default='http://localhost:35357/v2.0/'),
            cfg.StrOpt('identity_uri', default='http://localhost:5000'),
            #cfg.StrOpt('admin_user', default='neutron'),
            cfg.StrOpt('username', default='neutron'),
            #cfg.StrOpt('admin_password', default='secrete'),
            cfg.StrOpt('password', default='secrete'),
            cfg.StrOpt('project_name', default='service')]
        cfg.CONF.register_opts(test_opts, 'keystone_authtoken')


class TestL3RouterBaseExtensionManager(object):

    def get_resources(self):
        l3.RESOURCE_ATTRIBUTE_MAP['routers'].update(
            routertype.EXTENDED_ATTRIBUTES_2_0['routers'])
        res = l3.L3.get_resources()
        for item in routertype.Routertype.get_resources():
            res.append(item)
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            l3.RESOURCE_ATTRIBUTE_MAP)
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            routertype.RESOURCE_ATTRIBUTE_MAP)
        return res

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


# A routertype capable L3 routing service plugin class
class TestL3RouterServicePlugin(
    common_db_mixin.CommonDbMixin,
    routertype_db.RoutertypeDbMixin,
        l3_router_appliance_db.L3RouterApplianceDBMixin):

    supported_extension_aliases = ["router", routertype.ROUTERTYPE_ALIAS]
#    # Disable notifications from l3 base class to l3 agents
#    l3_rpc_notifier = l3_rpc_agent_api_noop.L3AgentNotifyNoOp

    def get_plugin_type(self):
        return service_constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        return "L3 Routing Service Plugin for testing"