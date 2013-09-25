# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
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
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.

import abc

from oslo.config import cfg

from quantum.api import extensions
from quantum.api.v2 import attributes as attr
from quantum.api.v2 import base
from quantum.common import exceptions as qexception
from quantum import manager
from quantum.openstack.common import uuidutils
from quantum.plugins.common import constants
from quantum.plugins.services.service_base import ServicePluginBase


# Service Chain Exceptions
class ServicesListEmpty(qexception.NotFound):
    message = _("Services list cannot be empty")


class ServicesTypeListEmpty(qexception.NotFound):
    message = _("Services type list cannot be empty")


class ServiceChainNotFound(qexception.NotFound):
    message = _("Service chain %(service_chain_id)s could not be found")


class ServiceChainInUse(qexception.InUse):
    message = _("Service chain %(service_chain_id)s is still active")


class ServiceChainNoNetworks(qexception.InvalidInput):
    message = _("Either source or destination network should be specified for "
                "service chain")


class ServiceChainTemplateNotFound(qexception.NotFound):
    message = _("Service Chain Template %(template_id)s could not be found")


service_types = ['L3', 'L2', 'BumpInTheWire', 'Tap']


def _convert_to_uuid_list(value_list):
    return value_list
    if value_list is None:
        #(TODO(rtapadar))raise ServicesListEmpty()
        return value_list
    for sc_id in value_list:
        if not uuidutils.is_uuid_like(sc_id):
            msg = _("'%s' is not an integer or uuid") % sc_id
            raise qexception.InvalidInput(error_message=msg)
    return value_list


def _convert_to_service_type_list(value_list):
    if value_list is None:
        raise ServicesTypeListEmpty()
    for st_id in value_list:
        if st_id not in service_types:
            msg = _("'%s' is not a valid service type") % st_id
            raise qexception.InvalidInput(error_message=msg)
    return value_list


RESOURCE_ATTRIBUTE_MAP = {
    'service_chain_templates': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'services_types_list': {'allow_post': True, 'allow_put': True,
                                'is_visible': True,
                                'convert_to': _convert_to_service_type_list},
        'shared': {'allow_post': False, 'allow_put': False,
                   'default': True, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
    },
    'service_chains': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'template_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:uuid': None},
                        'is_visible': True},
        'source_network_id': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:uuid': None},
                              'is_visible': True},
        'destination_network_id': {'allow_post': True, 'allow_put': True,
                                   'validate': {'type:uuid': None},
                                   'is_visible': True},
        'services_list': {'allow_post': True, 'allow_put': True,
                          'is_visible': True,
                          'convert_to': _convert_to_uuid_list},
    },
}


class Servicechain(extensions.ExtensionDescriptor):
    """ Service chain extension"""

    @classmethod
    def get_name(cls):
        return "service-chain"

    @classmethod
    def get_alias(cls):
        return "service-chain"

    @classmethod
    def get_description(cls):
        return "Extension for Services Chains"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/servicechains/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2013-04-25T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        exts = []
        plugin = manager.QuantumManager.get_plugin()
        for resource_name in ['service_chain', 'service_chain_template']:
            collection_name = resource_name.replace('_', '-') + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params, allow_bulk=True,
                                              allow_pagination=True,
                                              allow_sorting=True)

            ex = extensions.ResourceExtension(collection_name,
                                              controller,
                                              attr_map=params)
            exts.append(ex)

        return exts

    def update_attributes_map(self, attributes):
        super(Servicechain, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class ServiceChainPluginBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_service_chains(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_service_chain(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_service_chain(self, context, service_chain):
        pass

    @abc.abstractmethod
    def update_service_chain(self, context, id, service_chain):
        pass

    @abc.abstractmethod
    def delete_service_chain(self, context, id):
        pass

    @abc.abstractmethod
    def get_service_chain_templates(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_service_chain_template(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_service_chain_template(self, context, service_chain_template):
        pass

    @abc.abstractmethod
    def update_service_chain_template(self, context, id,
                                      service_chain_template):
        pass

    @abc.abstractmethod
    def delete_service_chain_template(self, context, id):
        pass
