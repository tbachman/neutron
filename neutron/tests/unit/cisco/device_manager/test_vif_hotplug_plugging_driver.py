import mock
from oslo_log import log as logging

from neutron.common import exceptions as n_exc
from neutron.tests import base

from neutron.plugins.cisco.db.device_manager.hosting_device_manager_db import (
    HostingDeviceManagerMixin)
from neutron.plugins.cisco.device_manager.plugging_drivers.\
    vif_hotplug_plugging_driver import VIFHotPlugPluggingDriver

LOG = logging.getLogger(__name__)


class TestVIFHotPlugPluggingDriver(base.BaseTestCase):

    def setUp(self):
        super(TestVIFHotPlugPluggingDriver, self).setUp()

    def test_delete_resource_port_fail_always(self):
        mgmt_port_id = 'fake_port_id'
        mocked_plugin = mock.MagicMock()
        mock_ctx = mock.MagicMock()
        mocked_plugin.delete_port = mock.MagicMock(
            side_effect=n_exc.NeutronException)

        with mock.patch.object(VIFHotPlugPluggingDriver,
                               '_core_plugin') as plugin:
            plugin.__get__ = mock.MagicMock(return_value=mocked_plugin)
            plugging_driver = VIFHotPlugPluggingDriver()
            self.assertRaises(
                n_exc.NeutronException,
                plugging_driver._delete_resource_port,
                mock_ctx,
                mgmt_port_id)

    def test_delete_resource_port_fail_only_twice(self):
        mgmt_port_id = 'fake_port_id'
        mocked_plugin = mock.MagicMock()
        mock_ctx = mock.MagicMock()
        mocked_plugin.delete_port = mock.MagicMock(
            side_effect=[n_exc.NeutronException, n_exc.NeutronException,
                         mock.Mock])
        with mock.patch.object(VIFHotPlugPluggingDriver,
                               '_core_plugin') as plugin:
            plugin.__get__ = mock.MagicMock(return_value=mocked_plugin)
            plugging_driver = VIFHotPlugPluggingDriver()
            plugging_driver._delete_resource_port(mock_ctx,
                                                          mgmt_port_id)
            self.assertEquals(3, mocked_plugin.delete_port.call_count)

    def test_delete_resource_port_handle_port_not_found(self):
        mgmt_port_id = 'fake_port_id'
        mocked_plugin = mock.MagicMock()
        mock_ctx = mock.MagicMock()
        mocked_plugin.delete_port = mock.MagicMock(
            side_effect=n_exc.PortNotFound(port_id=mgmt_port_id))
        with mock.patch.object(VIFHotPlugPluggingDriver,
                               '_core_plugin') as plugin:
            plugin.__get__ = mock.MagicMock(return_value=mocked_plugin)
            plugging_driver = VIFHotPlugPluggingDriver()
            plugging_driver._delete_resource_port(mock_ctx,
                                                          mgmt_port_id)
            self.assertEquals(1, mocked_plugin.delete_port.call_count)

    @mock.patch.object(HostingDeviceManagerMixin, 'l3_tenant_id')
    def test_setup_logical_port_connectivity(self, mock_l3tenant):
        mock_portdb = {'id': 'fake_port_id',
                       'tenant_id': 'fake_tenant_id',
                       'device_id': 'fake_device_id',
                       'device_owner': 'fake_device_owner'}
        hosting_device_id = 'fake_hosting_device_id'
        mocked_plugin = mock.MagicMock()
        mock_ctx = mock.MagicMock()
        with mock.patch.object(VIFHotPlugPluggingDriver,
                               '_core_plugin') as plugin:
            plugin.__get__ = mock.MagicMock(return_value=mocked_plugin)
            plugging_driver = VIFHotPlugPluggingDriver()
            plugging_driver._svc_vm_mgr = mock.MagicMock()
            plugging_driver.setup_logical_port_connectivity(
                mock_ctx, mock_portdb, hosting_device_id)
            plugging_driver._svc_vm_mgr.interface_attach\
                .assert_called_once_with(hosting_device_id, mock_portdb['id'])

    def test_create_hosting_device_resources(self):
        complementary_id = 'fake_complementary_id'
        tenant_id = 'fake_tenantid'
        mgmt_context = {'mgmt_nw_id': 'fake_mgmt_nw_id',
                        'mgmt_sec_grp_id': 'fake_mgmt_sec_grp_id'}
        max_hosted = 'fake_max_hosted'
        mocked_plugin = mock.MagicMock()
        mock_ctx = mock.MagicMock()
        with mock.patch.object(VIFHotPlugPluggingDriver,
                               '_core_plugin') as plugin:
            plugin.__get__ = mock.MagicMock(return_value=mocked_plugin)
            plugging_driver = VIFHotPlugPluggingDriver()
            plugging_driver.create_hosting_device_resources(
                mock_ctx, complementary_id, tenant_id, mgmt_context,
                max_hosted)
            self.assertEqual(True, mocked_plugin.create_port.called)
            self.assertEqual(1, mocked_plugin.create_port.call_count)

    def test_create_hosting_device_resources_exception(self):
        complementary_id = 'fake_complementary_id'
        tenant_id = 'fake_tenantid'
        mgmt_context = {'mgmt_nw_id': 'fake_mgmt_nw_id',
                        'mgmt_sec_grp_id': 'fake_mgmt_sec_grp_id'}
        max_hosted = 'fake_max_hosted'
        mock_delete_resources = mock.MagicMock()
        mocked_plugin = mock.MagicMock()
        mocked_plugin.create_port = mock.MagicMock(
            side_effect=n_exc.NeutronException)

        mock_ctx = mock.MagicMock()
        with mock.patch.object(VIFHotPlugPluggingDriver,
                               '_core_plugin') as plugin:
            plugin.__get__ = mock.MagicMock(return_value=mocked_plugin)
            plugging_driver = VIFHotPlugPluggingDriver()
            plugging_driver.delete_hosting_device_resources = (
                mock_delete_resources)
            result = plugging_driver.create_hosting_device_resources(
                mock_ctx, complementary_id, tenant_id, mgmt_context,
                max_hosted)
            self.assertEqual(True, mocked_plugin.create_port.called)
            self.assertEqual(1, mocked_plugin.create_port.call_count)
            self.assertEqual(True, mock_delete_resources.called)
            self.assertEqual(1, mock_delete_resources.call_count)
            self.assertEqual(None, result['mgmt_port'])
            self.assertEqual([], result['ports'])
