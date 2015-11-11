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
import sys

import mock
import netaddr
from oslo_utils import uuidutils

from neutron.common import constants as l3_constants
from neutron.plugins.cisco.common import cisco_constants
from neutron.tests import base

from neutron.plugins.cisco.cfg_agent.device_drivers.asr1k import (
    aci_asr1k_routing_driver as driver)
from neutron.plugins.cisco.cfg_agent.device_drivers.asr1k import (
    asr1k_snippets as snippets)
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    cisco_csr1kv_snippets as csr_snippets)
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    iosxe_routing_driver as iosxe_driver)
from neutron.plugins.cisco.cfg_agent.service_helpers import (
    routing_svc_helper)
from neutron.plugins.cisco.extensions import routerrole
from neutron.tests.unit.plugins.cisco.cfg_agent import (
    test_asr1k_routing_driver as asr1ktest)

sys.modules['ncclient'] = mock.MagicMock()
sys.modules['ciscoconfparse'] = mock.MagicMock()
from neutron.plugins.cisco.db.l3.ha_db import HA_GROUP
from neutron.plugins.cisco.db.l3.ha_db import HA_INFO
from neutron.plugins.cisco.db.l3.ha_db import HA_PORT
from neutron.plugins.cisco.extensions import ha
from neutron.openstack.common import uuidutils


_uuid = uuidutils.generate_uuid
FAKE_ID = _uuid()
PORT_ID = _uuid()


class ASR1kRoutingDriverAci(asr1ktest.ASR1kRoutingDriver):
    def setUp(self):
        super(ASR1kRoutingDriverAci, self).setUp()

        device_params = {'management_ip_address': 'fake_ip',
                         'protocol_port': 22,
                         'credentials': {"user_name": "stack",
                                         "password": "cisco"},
                         'timeout': None,
                         'id': '0000-1',
                         'device_id': 'ASR-1'
                         }
        self.driver = driver.AciASR1kRoutingDriver(**device_params)
        self.driver._ncc_connection = mock.MagicMock()
        self.driver._check_response = mock.MagicMock(return_value=True)
        int_ports = [self.port]
        self.ri_global.router['tenant_id'] = _uuid()
        self.router['tenant_id'] = _uuid()
        self.ri = routing_svc_helper.RouterInfo(FAKE_ID, self.router)
        self.vrf = self.ri.router['tenant_id']
        self.driver._get_vrfs = mock.Mock(return_value=[self.vrf])

    def test_internal_network_added(self):
        self.driver._do_create_sub_interface = mock.MagicMock()

        self.driver.internal_network_added(self.ri, self.port)

        self.assertFalse(self.driver._do_create_sub_interface.called)

    def test_internal_network_removed(self):
        self.driver._do_remove_sub_interface = mock.MagicMock()
        interface = 'GigabitEthernet0/0/0' + '.' + str(self.vlan_int)

        self.driver.internal_network_removed(self.ri, self.port)

        self.assertFalse(self.driver._do_remove_sub_interface.called)
