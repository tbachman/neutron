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

from novaclient import exceptions as nova_exc
from novaclient import utils as n_utils
from novaclient.v1_1 import client
from oslo.config import cfg

from neutron.i18n import _LE
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.common import cisco_constants as c_constants

LOG = logging.getLogger(__name__)


SERVICE_VM_LIB_OPTS = [
    cfg.StrOpt('templates_path',
               default='/opt/stack/data/neutron/cisco/templates',
               help=_("Path to templates for hosting devices.")),
    cfg.StrOpt('service_vm_config_path',
               default='/opt/stack/data/neutron/cisco/config_drive',
               help=_("Path to config drive files for service VM instances.")),
]

cfg.CONF.register_opts(SERVICE_VM_LIB_OPTS, "general")


class ServiceVMManager(object):

    def __init__(self, user=None, passwd=None, l3_admin_tenant=None,
                 auth_url=''):
        self._nclient = client.Client(user, passwd, l3_admin_tenant, auth_url,
                                      service_type="compute")

    @property
    def _core_plugin(self):
        try:
            return self._plugin
        except AttributeError:
            self._plugin = manager.NeutronManager.get_plugin()
            return self._plugin

    def nova_services_up(self):
        """Checks if required Nova services are up and running.

        returns: True if all needed Nova services are up, False otherwise
        """
        required = set(['nova-conductor', 'nova-cert', 'nova-scheduler',
                        'nova-compute', 'nova-consoleauth'])
        try:
            services = self._nclient.services.list()
        # There are several individual Nova client exceptions but they have
        # no other common base than Exception, hence the long list.
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound, nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                Exception) as e:
            LOG.error(_LE('Failure determining running Nova services: %s'), e)
            return False
        return not bool(required.difference(
            [service.binary for service in services
             if service.status == 'enabled' and service.state == 'up']))

    def get_service_vm_status(self, vm_id):
        try:
            status = self._nclient.servers.get(vm_id).status
        # There are several individual Nova client exceptions but they have
        # no other common base than Exception, hence the long list.
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound, nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                Exception) as e:
            LOG.error(_LE('Failed to get status of service VM instance '
                          '%(id)s, due to %(err)s'), {'id': vm_id, 'err': e})
            status = c_constants.SVM_ERROR
        return status

    #TODO(remove fake function later)
    def dispatch_service_vm(self, context, instance_name, vm_image,
                            vm_flavor, hosting_device_drv, mgmt_port,
                            ports=None):
        if self._core_plugin.__class__.__name__ != 'CSR1kv_OVSNeutronPluginV2':
            return self.dispatch_service_vm_real(context, instance_name,
                                                 vm_image, vm_flavor,
                                                 hosting_device_drv,
                                                 mgmt_port, ports)
        else:
            return self.dispatch_service_vm_fake(context, instance_name,
                                                 vm_image, vm_flavor,
                                                 hosting_device_drv,
                                                 mgmt_port, ports)

    def dispatch_service_vm_real(self, context, instance_name, vm_image,
                                 vm_flavor, hosting_device_drv, mgmt_port,
                                 ports=None):
        nics = [{'port-id': mgmt_port['id']}]
        for port in ports:
            nics.append({'port-id': port['id']})

        try:
            image = n_utils.find_resource(self._nclient.images, vm_image)
            flavor = n_utils.find_resource(self._nclient.flavors, vm_flavor)
        except (nova_exc.CommandError, Exception) as e:
            LOG.error(_LE('Failure finding needed Nova resource: %s'), e)
            return

        try:
            # Assumption for now is that this does not need to be
            # plugin dependent, only hosting device type dependent.
            files = hosting_device_drv.create_config(context, mgmt_port)
        except IOError:
            return

        try:
            server = self._nclient.servers.create(
                instance_name, image.id, flavor.id, nics=nics, files=files,
                config_drive=(files != {}))
        # There are several individual Nova client exceptions but they have
        # no other common base than Exception, therefore the long list.
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound, nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                Exception) as e:
            LOG.error(_LE('Failed to create service VM instance: %s'), e)
            return
        return {'id': server.id}

    #TODO(remove fake function later)
    def delete_service_vm(self, context, vm_id):
        if self._core_plugin.__class__.__name__ != 'CSR1kv_OVSNeutronPluginV2':
            return self.delete_service_vm_real(context, vm_id)
        else:
            return self.delete_service_vm_fake(context, vm_id)

    def delete_service_vm_real(self, context, vm_id):
        try:
            self._nclient.servers.delete(vm_id)
            return True
        # There are several individual Nova client exceptions but they have
        # no other common base than Exception, therefore the long list.
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound, nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                Exception) as e:
            LOG.error(_LE('Failed to delete service VM instance %(id)s, '
                        'due to %(err)s'), {'id': vm_id, 'err': e})
            return False

    # TODO(bobmel): Move this to fake_service_vm_lib.py file with
    # FakeServiceVMManager
    def dispatch_service_vm_fake(self, context, instance_name, vm_image,
                                 vm_flavor, hosting_device_drv, mgmt_port,
                                 ports=None):
        vm_id = uuidutils.generate_uuid()
        try:
            # Assumption for now is that this does not need to be
            # plugin dependent, only hosting device type dependent.
            files = hosting_device_drv.create_config(context, mgmt_port)
        except IOError:
            return

        if mgmt_port is not None:
            p_dict = {'port': {'device_id': vm_id,
                               'device_owner': 'nova'}}
            self._core_plugin.update_port(context, mgmt_port['id'], p_dict)

        for port in ports:
            p_dict = {'port': {'device_id': vm_id,
                               'device_owner': 'nova'}}
            self._core_plugin.update_port(context, port['id'], p_dict)

        myserver = {'server': {'adminPass': "MVk5HPrazHcG",
                    'id': vm_id,
                    'links': [{'href': "http://openstack.example.com/v2/"
                                       "openstack/servers/" + vm_id,
                               'rel': "self"},
                              {'href': "http://openstack.example.com/"
                                       "openstack/servers/" + vm_id,
                               'rel': "bookmark"}]}}

        return myserver['server']

    def delete_service_vm_fake(self, context, vm_id):
        result = True

        try:
            ports = self._core_plugin.get_ports(context,
                                                filters={'device_id': [vm_id]})
            for port in ports:
                self._core_plugin.delete_port(context, port['id'])
        except Exception as e:
            LOG.error(_LE('Failed to delete service VM %(id)s due to %(err)s'),
                      {'id': vm_id, 'err': e})
            result = False
        return result
