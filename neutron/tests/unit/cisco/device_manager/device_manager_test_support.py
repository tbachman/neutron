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
from novaclient import exceptions as nova_exc
from oslo.config import cfg
from oslo_log import log as logging
from oslo.utils import excutils

from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.common import test_lib
from neutron import context as n_context
from neutron.i18n import _LE
from neutron.db import agents_db
from neutron import manager
from neutron.openstack.common import uuidutils
import neutron.plugins
from neutron.plugins.cisco.db.device_manager import hosting_device_manager_db
from neutron.plugins.cisco.extensions import (ciscohostingdevicemanager as
                                              ciscodevmgr)
from neutron.plugins.common import constants
from neutron.tests import base
from neutron.tests.unit import test_l3_plugin

LOG = logging.getLogger(__name__)


_uuid = uuidutils.generate_uuid

CORE_PLUGIN_KLASS = (
    'neutron.tests.unit.cisco.device_manager.device_manager_test_support.'
    'TestCorePlugin')
extensions_path = ':' + neutron.plugins.__path__[0] + '/cisco/extensions'


class DeviceManagerTestSupportMixin:

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _mock_l3_admin_tenant(self):
        # Mock l3 admin tenant
        self.tenant_id_fcn_p = mock.patch(
            'neutron.plugins.cisco.db.device_manager.'
            'hosting_device_manager_db.HostingDeviceManagerMixin.l3_tenant_id')
        self.tenant_id_fcn = self.tenant_id_fcn_p.start()
        self.tenant_id_fcn.return_value = "L3AdminTenantId"

    def _create_mgmt_nw_for_tests(self, fmt):
        self._mgmt_nw = self._make_network(fmt,
                                           cfg.CONF.general.management_network,
                                           True, tenant_id="L3AdminTenantId",
                                           shared=False)
        self._mgmt_subnet = self._make_subnet(fmt, self._mgmt_nw,
                                              "10.0.100.1", "10.0.100.0/24",
                                              ip_version=4)

    def _remove_mgmt_nw_for_tests(self):
        q_p = "network_id=%s" % self._mgmt_nw['network']['id']
        subnets = self._list('subnets', query_params=q_p)
        if subnets:
            for p in self._list('ports', query_params=q_p).get('ports'):
                self._delete('ports', p['id'])
            self._delete('subnets', self._mgmt_subnet['subnet']['id'])
            self._delete('networks', self._mgmt_nw['network']['id'])
        hosting_device_manager_db.HostingDeviceManagerMixin._mgmt_nw_uuid = (
            None)

    # # Functions to mock service VM creation.
    # def _dispatch_service_vm_mock(self, context, instance_name, vm_image,
    #                               vm_flavor, hosting_device_drv, mgmt_port,
    #                               ports=None):
    #     vm_id = uuidutils.generate_uuid()
    #
    #     try:
    #         # Assumption for now is that this does not need to be
    #         # plugin dependent, only hosting device type dependent.
    #         hosting_device_drv.create_config(context, mgmt_port)
    #     except IOError:
    #         return
    #
    #     if mgmt_port is not None:
    #         p_dict = {'port': {'device_id': vm_id,
    #                            'device_owner': 'nova'}}
    #         self._core_plugin.update_port(context, mgmt_port['id'], p_dict)
    #
    #     for port in ports or {}:
    #         p_dict = {'port': {'device_id': vm_id,
    #                            'device_owner': 'nova'}}
    #         self._core_plugin.update_port(context, port['id'], p_dict)
    #
    #     myserver = {'server': {'adminPass': "MVk5HPrazHcG",
    #                 'id': vm_id,
    #                 'links': [{'href': "http://openstack.example.com/v2/"
    #                                    "openstack/servers/" + vm_id,
    #                            'rel': "self"},
    #                           {'href': "http://openstack.example.com/"
    #                                    "openstack/servers/" + vm_id,
    #                            'rel': "bookmark"}]}}
    #
    #     return myserver['server']
    #
    # def _delete_service_vm_mock(self, context, vm_id):
    #         result = True
    #
    #         try:
    #             ports = self._core_plugin.get_ports(
    #                 context, filters={'device_id': [vm_id]})
    #             for port in ports:
    #                 self._core_plugin.delete_port(context, port['id'])
    #         except n_exc.NeutronException as e:
    #             LOG.error('Failed to delete service VM %(id)s due to '
    #                       '%(err)s', {'id': vm_id, 'err': e})
    #             result = False
    #         return result

    # def _mock_svc_vm_create_delete(self):
    #     # Mock creation/deletion of service VMs
    #     self.dispatch_svc_vm_fcn_p = mock.patch(
    #         'neutron.plugins.cisco.device_manager.service_vm_lib'
    #         '.ServiceVMManager.dispatch_service_vm',
    #         self._dispatch_service_vm_mock)
    #     self.dispatch_svc_vm_fcn_p.start()
    #
    #     self.delete_svc_vm_fcn_p = mock.patch(
    #         'neutron.plugins.cisco.device_manager.service_vm_lib'
    #         '.ServiceVMManager.delete_service_vm',
    #         self._delete_service_vm_mock)
    #     self.delete_svc_vm_fcn_p.start()

    # Function used to mock novaclient services list
    def _novaclient_services_list(self, all=True):
        services = set(['nova-conductor', 'nova-cert', 'nova-scheduler',
                        'nova-compute'])
        full_list = [FakeResource(binary=res) for res in services]
        _all = all

        def response():
            if _all:
                return full_list
            else:
                return full_list[2:]
        return response

    # Function used to mock novaclient servers create
    def _novaclient_servers_create(self, instance_name, image_id, flavor_id,
                                   nics, files, config_drive):
        fake_vm = FakeResource()
        for nic in nics:
            p_dict = {'port': {'device_id': fake_vm.id,
                               'device_owner': 'nova'}}
            self._core_plugin.update_port(n_context.get_admin_context(),
                                          nic['port-id'], p_dict)
        return fake_vm

    # Function used to mock novaclient servers delete
    def _novaclient_servers_delete(self, vm_id):
        q_p = "device_id=%s" % vm_id
        ports = self._list('ports', query_params=q_p)
        for port in ports.get('ports', []):
            try:
                self._delete('ports', port['id'])
            except Exception as e:
                with excutils.save_and_reraise_exception(reraise=False):
                    LOG.error(_LE('Failed to delete port %(p_id)s for vm '
                                  'instance %(v_id)s due to %(err)s'),
                              {'p_id': port['id'], 'v_id': vm_id, 'err': e})
                    raise nova_exc.InternalServerError()

    def _mock_svc_vm_create_delete(self, plugin):
        # Mock novaclient methods for creation/deletion of service VMs
        mock.patch(
            'neutron.plugins.cisco.device_manager.service_vm_lib.n_utils'
            '.find_resource', lambda *args, **kw: FakeResource()).start()
        self._nclient_services_mock = mock.MagicMock()
        self._nclient_services_mock.list = self._novaclient_services_list()
        mock.patch.object(plugin._svc_vm_mgr_obj._nclient, 'services',
                          self._nclient_services_mock).start()
        nclient_servers_mock = mock.MagicMock()
        nclient_servers_mock.create = self._novaclient_servers_create
        nclient_servers_mock.delete = self._novaclient_servers_delete
        mock.patch.object(plugin._svc_vm_mgr_obj._nclient, 'servers',
                          nclient_servers_mock).start()

    def _mock_dispatch_pool_maintenance(self):
        # Mock creation/deletion of service VMs
        dispatch_pool_maintenance_job_fcn_p = mock.patch(
            'neutron.plugins.cisco.db.device_manager.hosting_device_manager_db'
            '.HostingDeviceManagerMixin._dispatch_pool_maintenance_job')
        dispatch_pool_maintenance_job_fcn_p .start()

    def _mock_eventlet_greenpool_spawn_n(self):
        # Mock GreenPool's spawn_n to execute the specified function directly
        self._greenpool_mock = mock.MagicMock()
        self._greenpool_mock.return_value.spawn_n = (
            lambda f, *args,  **kwargs: f(*args, **kwargs))
        _eventlet_greenpool_fcn_p = mock.patch(
            'neutron.plugins.cisco.db.device_manager.hosting_device_manager_db'
            '.eventlet.GreenPool', self._greenpool_mock)
        _eventlet_greenpool_fcn_p.start()

    def _mock_io_file_ops(self):
        # Mock library functions for config drive file operations
        cfg_template = '\n'.join(['interface GigabitEthernet1',
                                  'ip address <ip> <mask>',
                                  'no shutdown'])
        m = mock.mock_open(read_data=cfg_template)
        m.return_value.__iter__.return_value = cfg_template.splitlines()
        mock.patch('neutron.plugins.cisco.device_manager.'
                   'hosting_device_drivers.csr1kv_hd_driver.open', m,
                   create=True).start()

    def _test_remove_all_hosting_devices(self):
        """Removes all hosting devices created during a test."""
        devmgr = manager.NeutronManager.get_service_plugins()[
            constants.DEVICE_MANAGER]
        context = n_context.get_admin_context()
        devmgr.delete_all_hosting_devices(context, True)

    def _get_fake_resource(self, tenant_id=None, id=None):
        return {'id': id or _uuid(),
                'tenant_id': tenant_id or _uuid()}

    def _get_test_context(self, user_id=None, tenant_id=None, is_admin=False):
        return n_context.Context(user_id, tenant_id, is_admin,
                                 load_admin_roles=True)

    def _add_device_manager_plugin_ini_file(self):
        # includes config files for device manager service plugin
        cfg_file = (
            base.TEST_ROOT_DIR +
            '/unit/cisco/etc/cisco_device_manager_plugin.ini')
        if 'config_files' in test_lib.test_config:
            test_lib.test_config['config_files'].append(cfg_file)
        else:
            test_lib.test_config['config_files'] = [cfg_file]


class TestDeviceManagerExtensionManager(object):

    def get_resources(self):
        res = ciscodevmgr.Ciscohostingdevicemanager.get_resources()
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            ciscodevmgr.RESOURCE_ATTRIBUTE_MAP)
        return res

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


# A core plugin supporting Cisco device manager functionality
class TestCorePlugin(test_l3_plugin.TestNoL3NatPlugin, agents_db.AgentDbMixin,
                     hosting_device_manager_db.HostingDeviceManagerMixin):

    supported_extension_aliases = ["external-net",
                                   ciscodevmgr.HOSTING_DEVICE_MANAGER_ALIAS]


# Used to fake Glance images, Nova VMs and Nova services
class FakeResource(object):
    def __init__(self, id=None, enabled='enabled', state='up', binary=None):
        self.id = id or _uuid()
        self.status = enabled
        self.state = state
        self.binary = binary