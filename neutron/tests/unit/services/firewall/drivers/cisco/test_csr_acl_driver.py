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
import requests

from neutron.services.firewall.drivers.cisco import csr_acl_driver
# For now import csr_rest_client from the VPN directory.
# A bug fix will split that file to sperate rest client and VPN handling.
from neutron.services.vpn.device_drivers import cisco_csr_rest_client
from neutron.tests import base


FAKE_ACL_ID = 'acl123'
FAKE_FW = {
    'id': '123456789',
    'admin_state_up': True,
    'vendor_ext': {
        'acl_id': FAKE_ACL_ID,
        'host_mngt_ip': '192.169.101.5',
        'host_usr_nm': 'lab',
        'host_usr_pw': 'lab',
        'if_list': [
            {
                'direction': 'inside',
                'port': {
                    'id': 'fake_port_id',
                    'hosting_info': {
                        #map to interface GigabitEthernet3.101
                        'segmentation_id': 101,
                        'hosting_port_name': 't2_p:1',
                    },
                },
            },
        ]
    },
    'firewall_rule_list': [
        {
            'enabled': True,
            'name': 'r1',
            'ip_version': 4,
            'protocol': 'tcp',
            'action': 'allow',
        },
    ]
}


class TestCsrAclDriver(base.BaseTestCase):

    def setUp(self):
        super(TestCsrAclDriver, self).setUp()

        settings = {
            'rest_mgmt_ip': FAKE_FW['vendor_ext']['host_mngt_ip'] + ':55443',
            'username': FAKE_FW['vendor_ext']['host_usr_nm'],
            'password': FAKE_FW['vendor_ext']['host_usr_pw'],
            'timeout': 30,
        }
        self.csr = cisco_csr_rest_client.CsrRestClient(settings)

        self.csracl = csr_acl_driver.CsrAclDriver()
        self.csracl._get_csr_host = mock.Mock(return_value=self.csr)

        self.acl_data = self.csracl._get_acl_rule_data(FAKE_FW)
        self.aclapi_rsp = 'https://' + FAKE_FW[
                'vendor_ext']['host_mngt_ip'] + '/' + FAKE_ACL_ID

    def _set_csracl_mocks(self):
        self.csracl._post_acl = mock.Mock()
        self.csracl._post_acl_to_intfs = mock.Mock()
        self.csracl._del_acl = mock.Mock()
        self.csracl._put_acl = mock.Mock()
        self.csracl._del_acl_on_intf = mock.Mock()
        self.csracl._get_acl_intf = mock.Mock()

    def _set_csr_mocks(self):
        self.csr.post_request = mock.Mock()
        self.csr.delete_request = mock.Mock()
        self.csr.get_request = mock.Mock()
        self.csr.put_request = mock.Mock()

    def _test_post_acl(self):
        self._set_csr_mocks()
        self.csr.post_request.return_value = self.aclapi_rsp
        rc = self.csracl._post_acl(self.csr, self.acl_data)

        self.csr.post_request.assert_called_once_with('acl', self.acl_data)
        if self.csr.status == requests.codes.CREATED:
            self.assertEqual(FAKE_ACL_ID, rc)
        else:
            self.assertEqual('', rc)

    def test_post_acl_err(self):
        self.csr.status = 500
        self._test_post_acl()

    def test_post_acl(self):
        self.csr.status = requests.codes.CREATED
        self._test_post_acl()

    def _test_del_acl(self):
        self._set_csr_mocks()
        rc = self.csracl._del_acl(self.csr, FAKE_ACL_ID)

        self.csr.delete_request.assert_called_once_with('acl/' + FAKE_ACL_ID)
        if self.csr.status == requests.codes.NO_CONTENT:
            self.assertEqual(True, rc)
        else:
            self.assertEqual(False, rc)

    def test_del_acl_err(self):
        self.csr.status = 500
        self._test_del_acl()

    def test_del_acl(self):
        self.csr.status = requests.codes.NO_CONTENT
        self._test_del_acl()

    def _test_put_acl(self):
        self._set_csr_mocks()
        rc = self.csracl._put_acl(self.csr, FAKE_ACL_ID, self.acl_data)

        self.csr.put_request.assert_called_once_with(
            'acl/' + FAKE_ACL_ID, self.acl_data)
        if self.csr.status == requests.codes.NO_CONTENT:
            self.assertEqual(True, rc)
        else:
            self.assertEqual(False, rc)

    def test_put_acl_err(self):
        self.csr.status = 500
        self._test_put_acl()

    def test_put_acl(self):
        self.csr.status = requests.codes.NO_CONTENT
        self._test_put_acl()

    def _test_post_acl_to_intfs(self):
        self._set_csr_mocks()
        self.csr.post_request.return_value = 'fake_post_rsp'
        status_data = {
            'fw_id': FAKE_FW['id'],
            'acl_id': FAKE_ACL_ID,
            'if_list': []
        }
        fw_if = FAKE_FW['vendor_ext']['if_list'][0]
        if_name = self.csracl._get_interface_name_from_hosting_port(
            fw_if['port'])
        acl_if_data = {
            'if-id': if_name, 'direction': fw_if['direction']}
        api = 'acl/' + FAKE_ACL_ID + '/interfaces'

        self.csracl._post_acl_to_intfs(FAKE_FW, self.csr,
            FAKE_ACL_ID, status_data)

        self.csr.post_request.assert_called_once_with(api, acl_if_data)
        if self.csr.status == requests.codes.CREATED:
            self.assertEqual(
                [{'port_id': fw_if['port']['id'], 'status': 'OK'}],
                status_data['if_list'])
        else:
            self.assertEqual(
                [{'port_id': fw_if['port']['id'], 'status': 'ERROR'}],
                status_data['if_list'])

    def test_post_acl_to_intfs_err(self):
        self.csr.status = 500
        self._test_post_acl_to_intfs()

    def test_post_acl_to_intfs(self):
        self.csr.status = requests.codes.CREATED
        self._test_post_acl_to_intfs()

    def test_del_acl_on_intf(self):
        self._set_csr_mocks()
        self.csr.status = requests.codes.NO_CONTENT
        csr_acl_intfs = [
            {
                'acl-id': FAKE_ACL_ID,
                'if-id': 'GigabitEthernet3.101',
                'direction': 'inside'
            }
        ]
        api = 'acl/%s/interfaces/%s_%s' % (
            FAKE_ACL_ID, csr_acl_intfs[0]['if-id'],
            csr_acl_intfs[0]['direction'])

        self.csracl._del_acl_on_intf(self.csr, FAKE_ACL_ID, csr_acl_intfs)
        self.csr.delete_request.assert_called_once_with(api)

    def _test_get_acl_intf(self):
        self._set_csr_mocks()
        api = 'acl/%s/interfaces' % FAKE_ACL_ID
        get_rsp = {'items': [{'fake_k1': 'fake_d1'}]}
        self.csr.get_request.return_value = get_rsp
        rsp = self.csracl._get_acl_intf(self.csr, FAKE_ACL_ID)

        self.csr.get_request.assert_called_once_with(api)
        if self.csr.status == requests.codes.OK:
            self.assertEqual(get_rsp['items'], rsp)
        else:
            self.assertEqual('', rsp)

    def test_get_acl_intf_err(self):
        self.csr.status = 500
        self._test_get_acl_intf()

    def test_get_acl_intf(self):
        self.csr.status = requests.codes.OK
        self._test_get_acl_intf()

    def test_create_fw_admin_state_not_up(self):
        FAKE_FW['admin_state_up'] = False
        self._set_csracl_mocks()
        self.csracl._post_acl.return_value = FAKE_ACL_ID
        rc, status = self.csracl.create_firewall(None, FAKE_FW)

        self.csracl._post_acl.assert_called_once_with(self.csr, self.acl_data)
        self.assertEqual(True, rc)
        self.assertEqual(
            {'fw_id': FAKE_FW['id'], 'acl_id': FAKE_ACL_ID, 'if_list': []},
            status)

        FAKE_FW['admin_state_up'] = True

    def test_create_fw_post_acl_err(self):
        self._set_csracl_mocks()
        self.csracl._post_acl.return_value = ''
        rc, status = self.csracl.create_firewall(None, FAKE_FW)

        self.csracl._post_acl.assert_called_once_with(self.csr, self.acl_data)
        self.assertEqual(False, rc)

    def test_create_fw(self):
        self._set_csracl_mocks()
        self.csracl._post_acl.return_value = FAKE_ACL_ID
        status_data = {
            'fw_id': FAKE_FW['id'],
            'acl_id': FAKE_ACL_ID,
            'if_list': []
        }
        rc, status = self.csracl.create_firewall(None, FAKE_FW)

        self.csracl._post_acl.assert_called_once_with(self.csr, self.acl_data)
        self.csracl._post_acl_to_intfs.assert_called_once_with(
            FAKE_FW, self.csr, FAKE_ACL_ID, status_data)
        self.assertEqual(True, rc)

    def _test_del_fw(self, del_acl_rc):
        self._set_csracl_mocks()
        self.csracl._del_acl.return_value = del_acl_rc
        rc = self.csracl.delete_firewall(None, FAKE_FW)

        self.csracl._del_acl.assert_called_once_with(self.csr, FAKE_ACL_ID)
        self.assertEqual(del_acl_rc, rc)

    def test_delete_fw(self):
        self._test_del_fw(True)

    def test_delete_fw_err(self):
        self._test_del_fw(False)

    def test_udpate_fw_put_acl_err(self):
        self._set_csracl_mocks()
        self.csracl._put_acl.return_value = False
        acldata = self.acl_data
        acldata['acl-id'] = FAKE_ACL_ID
        rc, status = self.csracl.update_firewall(None, FAKE_FW)

        self.csracl._put_acl.assert_called_once_with(
            self.csr, FAKE_ACL_ID, acldata)
        self.assertEqual(False, rc)

    def _test_update_fw(self, admin_stat_up):
        FAKE_FW['admin_state_up'] = admin_stat_up
        self._set_csracl_mocks()
        self.csracl._put_acl.return_value = True
        acldata = self.acl_data
        acldata['acl-id'] = FAKE_ACL_ID
        fake_acl_intf_list = [{'if-id': 'GigabitEthernet3.101'}]
        self.csracl._get_acl_intf.return_value = fake_acl_intf_list
        status_data = {
            'fw_id': FAKE_FW['id'],
            'acl_id': FAKE_ACL_ID,
            'if_list': []
        }

        rc, status = self.csracl.update_firewall(None, FAKE_FW)

        self.csracl._put_acl.assert_called_once_with(
            self.csr, FAKE_ACL_ID, acldata)
        self.csracl._get_acl_intf.assert_called_once_with(self.csr,
                                                          FAKE_ACL_ID)
        self.csracl._del_acl_on_intf.assert_called_once_with(
            self.csr, FAKE_ACL_ID, fake_acl_intf_list)
        self.assertEqual(True, rc)
        if not admin_stat_up:
            self.assertEqual(status_data, status)
        else:
            self.csracl._post_acl_to_intfs.assert_called_once_with(
                FAKE_FW, self.csr, FAKE_ACL_ID, status_data)

        FAKE_FW['admin_state_up'] = True

    def test_update_fw_admin_state_not_up(self):
        self._test_update_fw(False)

    def test_update_fw(self):
        self._test_update_fw(True)


class TestCsrAclDriverValidation(base.BaseTestCase):
    def setUp(self):
        super(TestCsrAclDriverValidation, self).setUp()
        self.csracl = csr_acl_driver.CsrAclDriver()

    def test_create_fw_no_admin_state(self):
        del FAKE_FW['admin_state_up']
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['admin_state_up'] = True

    def test_create_fw_no_vendor_ext(self):
        fw = copy.deepcopy(FAKE_FW)
        del fw['vendor_ext']
        rc, status = self.csracl.create_firewall(None, fw)
        self.assertEqual(False, rc)

    def test_create_fw_no_host_mngt_ip(self):
        del FAKE_FW['vendor_ext']['host_mngt_ip']
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['vendor_ext']['host_mngt_ip'] = '192.169.101.5'

    def test_create_fw_no_host_usr_nm(self):
        del FAKE_FW['vendor_ext']['host_usr_nm']
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['vendor_ext']['host_usr_nm'] = 'lab'

    def test_create_fw_no_host_usr_pw(self):
        del FAKE_FW['vendor_ext']['host_usr_pw']
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['vendor_ext']['host_usr_pw'] = 'lab'

    def test_create_fw_no_if_list(self):
        fw = copy.deepcopy(FAKE_FW)
        del fw['vendor_ext']['if_list']
        rc, status = self.csracl.create_firewall(None, fw)
        self.assertEqual(False, rc)

    def test_create_fw_no_direction(self):
        fw = copy.deepcopy(FAKE_FW)
        del fw['vendor_ext']['if_list'][0]['direction']
        rc, status = self.csracl.create_firewall(None, fw)
        self.assertEqual(False, rc)

    def test_create_fw_invalid_direction(self):
        fw = copy.deepcopy(FAKE_FW)
        fw['vendor_ext']['if_list'][0]['direction'] = 'dir'
        rc, status = self.csracl.create_firewall(None, fw)
        self.assertEqual(False, rc)

    def test_create_fw_no_port(self):
        fw = copy.deepcopy(FAKE_FW)
        del fw['vendor_ext']['if_list'][0]['port']
        rc, status = self.csracl.create_firewall(None, fw)
        self.assertEqual(False, rc)

    def test_create_fw_no_host_info(self):
        fw = copy.deepcopy(FAKE_FW)
        del fw['vendor_ext']['if_list'][0]['port']['hosting_info']
        rc, status = self.csracl.create_firewall(None, fw)
        self.assertEqual(False, rc)

    def test_create_fw_no_segmentation_id(self):
        fw = copy.deepcopy(FAKE_FW)
        del fw['vendor_ext']['if_list'][0]['port']['hosting_info'][
            'segmentation_id']
        rc, status = self.csracl.create_firewall(None, fw)
        self.assertEqual(False, rc)

    def test_create_fw_no_host_port_name(self):
        fw = copy.deepcopy(FAKE_FW)
        del fw['vendor_ext']['if_list'][0]['port']['hosting_info'][
            'hosting_port_name']
        rc, status = self.csracl.create_firewall(None, fw)
        self.assertEqual(False, rc)

    def test_create_fw_invalid_host_port_name(self):
        FAKE_FW['vendor_ext']['if_list'][0]['port']['hosting_info'][
            'hosting_port_name'] = 't3_p:1'
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['vendor_ext']['if_list'][0]['port']['hosting_info'][
            'hosting_port_name'] = 't2_p:1'

    def test_create_fw_no_rule_list(self):
        fw = copy.deepcopy(FAKE_FW)
        del fw['firewall_rule_list']
        rc, status = self.csracl.create_firewall(None, fw)
        self.assertEqual(False, rc)

    def test_create_fw_rule_no_name(self):
        del FAKE_FW['firewall_rule_list'][0]['name']
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['firewall_rule_list'][0]['name'] = 'r1'

    def test_create_fw_rule_no_ipv(self):
        del FAKE_FW['firewall_rule_list'][0]['ip_version']
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['firewall_rule_list'][0]['ip_version'] = 4

    def test_create_fw_rule_not_ipv4(self):
        FAKE_FW['firewall_rule_list'][0]['ip_version'] = 6
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['firewall_rule_list'][0]['ip_version'] = 4

    def test_create_fw_rule_no_protocol(self):
        del FAKE_FW['firewall_rule_list'][0]['protocol']
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['firewall_rule_list'][0]['protocol'] = 'tcp'

    def test_create_fw_rule_no_action(self):
        del FAKE_FW['firewall_rule_list'][0]['action']
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['firewall_rule_list'][0]['action'] = 'allow'

    def test_create_fw_rule_invalid_action(self):
        FAKE_FW['firewall_rule_list'][0]['action'] = 'action'
        rc, status = self.csracl.create_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['firewall_rule_list'][0]['action'] = 'allow'

    def test_update_fw_no_acl_id(self):
        del FAKE_FW['vendor_ext']['acl_id']
        rc, status = self.csracl.update_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['vendor_ext']['acl_id'] = FAKE_ACL_ID

    def test_delete_fw_no_acl_id(self):
        del FAKE_FW['vendor_ext']['acl_id']
        rc = self.csracl.delete_firewall(None, FAKE_FW)
        self.assertEqual(False, rc)

        FAKE_FW['vendor_ext']['acl_id'] = FAKE_ACL_ID
