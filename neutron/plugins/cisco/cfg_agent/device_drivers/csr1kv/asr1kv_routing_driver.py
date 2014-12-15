# Copyright 2015 Cisco Systems, Inc.  All rights reserved.
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

import logging

from neutron.plugins.cisco.cfg_agent import cfg_exceptions as cfg_exc
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    csr1kv_routing_driver as csr1kv_driver)

LOG = logging.getLogger(__name__)


class ASR1kRoutingDriver(csr1kv_driver.CSR1kvRoutingDriver):

    def __init__(self, **device_params):
        super(ASR1kRoutingDriver,self).__init__(**device_params)

    def _get_interface_name_from_hosting_port(self, port):
        try:
            vlan = port['hosting_info']['segmentation_id']
            int_prefix = port['hosting_info']['physical_interface']
            intfc_name = '%s.%s' % (int_prefix, vlan)
            return intfc_name
        except KeyError, e:
            params = {'key': e}
            raise cfg_exc.DriverExpectedKeyNotSetException(**params)

    def _enable_intfs(self, conn):
        """For ASR we dont need to do anything"""
        return True