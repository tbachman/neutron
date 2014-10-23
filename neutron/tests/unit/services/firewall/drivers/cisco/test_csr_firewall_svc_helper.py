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

from neutron.common import config as base_config
from neutron import context as n_context
from neutron.plugins.cisco.cfg_agent import cfg_agent
from neutron.plugins.common import constants
from neutron.services.firewall.drivers.cisco import csr_firewall_svc_helper
from neutron.tests import base


HOST = 'myhost'
FAKE_FW = {'id': '1234'}
FAKE_FW_STATUS = {
    'fw_id': '1234',
    'acl_id': 'acl123',
    'if_list': []
}


class TestCsrFirewallServiceHelper(base.BaseTestCase):

    def setUp(self):
        super(TestCsrFirewallServiceHelper, self).setUp()

        self.conf = cfg.ConfigOpts()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(cfg_agent.CiscoCfgAgent.OPTS)
        self.agent = mock.Mock()

        self.fwpluginapi_cls_p = mock.patch(
            'neutron.services.firewall.drivers.cisco.'
            'csr_firewall_svc_helper.CsrFirewalllPluginApi')
        self.fwpluginapi_cls = self.fwpluginapi_cls_p.start()
        self.fwplugin_api = mock.Mock()
        self.fwpluginapi_cls.return_value = self.fwplugin_api
        self.fwplugin_api.get_firewalls_for_device = mock.MagicMock()
        self.fwplugin_api.get_firewalls_for_tenant = mock.MagicMock()
        self.fwplugin_api.get_tenants_with_firewalls = mock.MagicMock()
        self.fwplugin_api.firewall_deleted = mock.MagicMock()
        self.fwplugin_api.set_firewall_status = mock.MagicMock()
        mock.patch('neutron.common.rpc.create_connection').start()

        self.fw_svc_helper = csr_firewall_svc_helper.CsrFirewallServiceHelper(
            HOST, self.conf, self.agent)

        self.fw_svc_helper.acl_driver = mock.Mock()
        self.fw_svc_helper.ev_q = mock.Mock()
        self.fw_svc_helper.ev_q.enqueue = mock.Mock()

        self.ctx = mock.Mock()

    def test_create_firewall(self):
        self.fw_svc_helper.create_firewall(self.ctx, FAKE_FW, HOST)
        self.fw_svc_helper.ev_q.enqueue.assert_called_with(
            'csr_fw_ev_q', {'ev': 'FW_EV_CREATE', 'ctx': self.ctx,
                            'fw': FAKE_FW, 'host': HOST})

    def test_update_firewall(self):
        self.fw_svc_helper.update_firewall(self.ctx, FAKE_FW, HOST)
        self.fw_svc_helper.ev_q.enqueue.assert_called_with(
            'csr_fw_ev_q', {'ev': 'FW_EV_UPDATE', 'ctx': self.ctx,
                            'fw': FAKE_FW, 'host': HOST})

    def test_delete_firewall(self):
        self.fw_svc_helper.delete_firewall(self.ctx, FAKE_FW, HOST)
        self.fw_svc_helper.ev_q.enqueue.assert_called_with(
            'csr_fw_ev_q', {'ev': 'FW_EV_DELETE', 'ctx': self.ctx,
                            'fw': FAKE_FW, 'host': HOST})

    def _test_fullsync(self, fw_stat, fn_nm):
        self.fw_svc_helper._invoke_fw_driver = mock.Mock()
        self.fw_svc_helper.fullsync = True
        self.fwplugin_api.get_tenants_with_firewalls.return_value = ['1']
        fw1 = FAKE_FW
        fw1['status'] = fw_stat
        self.fwplugin_api.get_firewalls_for_tenant.return_value = [fw1]
        ctx_p = mock.patch.object(n_context, 'Context').start()
        ctx_p.return_value = self.ctx
        self.fw_svc_helper.process_service()
        self.fw_svc_helper._invoke_fw_driver.assert_called_with(
            self.ctx, fw1, fn_nm)
        self.assertEqual(False, self.fw_svc_helper.fullsync)

    def test_proc_service_fullsync_fw_pending_c(self):
        self._test_fullsync('PENDING_CREATE', 'create_firewall')

    def test_proc_service_fullsync_fw_pending_u(self):
        self._test_fullsync('PENDING_UPDATE', 'update_firewall')

    def test_proc_service_fullsync_fw_pending_d(self):
        self._test_fullsync('PENDING_DELETE', 'delete_firewall')

    def _test_dvc(self, fw_state, fn_nm):
        self.fw_svc_helper._invoke_fw_driver = mock.Mock()
        self.fw_svc_helper.fullsync = False
        ctx_p = mock.patch.object(n_context, 'Context').start()
        ctx_p.return_value = self.ctx
        fw1 = FAKE_FW
        fw1['status'] = fw_state
        self.fwplugin_api.get_firewalls_for_device.return_value = [fw1]
        self.fw_svc_helper.process_service(device_ids=['123'])
        self.fw_svc_helper._invoke_fw_driver.assert_called_with(
            self.ctx, fw1, fn_nm)

    def test_proc_service_dvcids_fw_pending_c(self):
        self._test_dvc('PENDING_CREATE', 'create_firewall')

    def test_proc_service_dvcids_fw_pending_u(self):
        self._test_dvc('PENDING_UPDATE', 'update_firewall')

    def test_proc_service_dvcids_fw_pending_d(self):
        self._test_dvc('PENDING_DELETE', 'delete_firewall')

    def _test_fw_evt(self, evt, fn_nm):
        self.fw_svc_helper._invoke_fw_driver = mock.Mock()
        self.fw_svc_helper.fullsync = False
        evt_data = {'ev': evt, 'ctx': self.ctx,
                    'fw': FAKE_FW, 'host': HOST}
        evt_q_returns = [evt_data, None]

        def _ev_dequeue_side_effect(*args):
            return evt_q_returns.pop(0)

        self.fw_svc_helper.ev_q.dequeue = mock.Mock(
            side_effect=_ev_dequeue_side_effect)

        self.fw_svc_helper.process_service()
        self.fw_svc_helper._invoke_fw_driver.assert_called_once_with(
            self.ctx, FAKE_FW, fn_nm)

    def test_proc_service_fw_evt_c(self):
        self._test_fw_evt('FW_EV_CREATE', 'create_firewall')

    def test_proc_service_fw_evt_u(self):
        self._test_fw_evt('FW_EV_UPDATE', 'update_firewall')

    def test_proc_service_fw_evt_d(self):
        self._test_fw_evt('FW_EV_DELETE', 'delete_firewall')

    def test_invoke_fw_driver_for_delete(self):
        self.fw_svc_helper.acl_driver.delete_firewall = mock.Mock()

        self.fw_svc_helper.acl_driver.delete_firewall.return_value = True
        self.fw_svc_helper._invoke_fw_driver(
            self.ctx, FAKE_FW, 'delete_firewall')
        self.fw_svc_helper.acl_driver.delete_firewall.assert_called_with(
            None, FAKE_FW)
        self.fwplugin_api.firewall_deleted.assert_called_with(
            self.ctx, FAKE_FW['id'])

        self.fw_svc_helper.acl_driver.delete_firewall.return_value = False
        self.fw_svc_helper._invoke_fw_driver(
            self.ctx, FAKE_FW, 'delete_firewall')
        self.fwplugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ERROR)

    def test_invoke_fw_driver_for_create(self):
        self.fw_svc_helper.acl_driver.create_firewall = mock.Mock()

        self.fw_svc_helper.acl_driver.create_firewall.return_value = (
            True, FAKE_FW_STATUS)
        self.fw_svc_helper._invoke_fw_driver(
            self.ctx, FAKE_FW, 'create_firewall')
        self.fw_svc_helper.acl_driver.create_firewall.assert_called_with(
            None, FAKE_FW)
        self.fwplugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ACTIVE, FAKE_FW_STATUS)

        self.fw_svc_helper.acl_driver.create_firewall.return_value = (
            False, {})
        self.fw_svc_helper._invoke_fw_driver(
            self.ctx, FAKE_FW, 'create_firewall')
        self.fwplugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ERROR)

    def test_invoke_fw_driver_for_update(self):
        self.fw_svc_helper.acl_driver.update_firewall = mock.Mock()

        self.fw_svc_helper.acl_driver.update_firewall.return_value = (
            True, FAKE_FW_STATUS)
        self.fw_svc_helper._invoke_fw_driver(
            self.ctx, FAKE_FW, 'update_firewall')
        self.fw_svc_helper.acl_driver.update_firewall.assert_called_with(
            None, FAKE_FW)
        self.fwplugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ACTIVE, FAKE_FW_STATUS)

        self.fw_svc_helper.acl_driver.update_firewall.return_value = (
            False, {})
        self.fw_svc_helper._invoke_fw_driver(
            self.ctx, FAKE_FW, 'update_firewall')
        self.fwplugin_api.set_firewall_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ERROR)
