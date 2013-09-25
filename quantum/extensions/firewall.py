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
from quantum.plugins.common import constants
from quantum.plugins.services.service_base import ServicePluginBase


# Firewall Exceptions
class FirewallNotFound(qexception.NotFound):
    message = _("Firewall %(firewall_id)s could not be found")


class FirewallInUse(qexception.InUse):
    message = _("Firewall %(firewall_id)s is still active")


class FirewallPolicyNotFound(qexception.NotFound):
    message = _("FirewallPolicy %(firewall_policy_id)s could not be found")


class FirewallPolicyInUse(qexception.InUse):
    message = _("FirewallPolicy %(firewall_policy_id)s is being used")


class FirewallRuleNotFound(qexception.NotFound):
    message = _("FirewallRule %(firewall_rule_id)s could not be found")


class FirewallRuleInUse(qexception.InUse):
    message = _("FirewallPolicy %(firewall_rule_id)s is being used")


class FirewallRuleInvalidProtocol(qexception.InvalidInput):
    message = _("Firewall rule protocol %(protocol)s not supported. "
                "Only protocol values %(values)s supported.")


class FirewallRuleInvalidAction(qexception.InvalidInput):
    message = _("Firewall rule action %(action)s not supported. "
                "Only action values %(values)s supported.")


class FirewallInvalidPortValue(qexception.InvalidInput):
    message = _("Invalid value for port %(port)s")


fw_supported_protocols = [None, 'tcp', 'udp', 'icmp']
fw_supported_actions = ['allow', 'deny']


def convert_protocol_to_case_insensitive(value):
    if value is None:
        return value
    try:
        return value.lower()
    except AttributeError:
        raise FirewallRuleInvalidProtocol(
            protocol=value, values=fw_supported_protocols)


def convert_action_to_case_insensitive(value):
    if value is None:
        return value
    try:
        return value.lower()
    except AttributeError:
        raise FirewallRuleInvalidAction(
            protocol=value, values=fw_supported_actions)


def convert_validate_port_value(port):
    if port is None:
        return port
    try:
        val = int(port)
    except (ValueError, TypeError):
        raise FirewallInvalidPortValue(port=port)

    if val >= 0 and val <= 65535:
        return val
    else:
        raise FirewallInvalidPortValue(port=port)


def convert_none_to_empty_list(value):
    return [] if value is None else value
RESOURCE_ATTRIBUTE_MAP = {
    'firewall_rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'direction': {'allow_post': True, 'allow_put': True,
                      'is_visible': True,
                      'validate': {'type:values': ['ingress', 'egress']}},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol_to_case_insensitive,
                     'validate': {'type:values': fw_supported_protocols}},
        'source_ip_address': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:ip_address_or_none': None},
                              'is_visible': True, 'default': None},
        'destination_ip_address': {'allow_post': True, 'allow_put': True,
                                   'validate': {'type:ip_address_or_none':
                                                None},
                                   'is_visible': True, 'default': None},
        'port_range_min': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'port_range_max': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'application': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'action': {'allow_post': True, 'allow_put': True,
                   'convert_to': convert_action_to_case_insensitive,
                   'validate': {'type:values': fw_supported_actions},
                   'is_visible': True, 'default': 'deny'},
        # TODO (Sumit): # this needs to change to hold attr names
        'dynamic_attributes': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:string': None},
                               'default': '', 'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'shared': {'allow_post': False, 'allow_put': False,
                   'default': True, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
    },
    'firewall_policies': {
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
        'firewall_rules_list': {'allow_post': True, 'allow_put': True,
                                'default': [], 'is_visible': True},
        'audited': {'allow_post': True, 'allow_put': True,
                    'default': False, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True, 'required_by_policy': True,
                    'enforce_policy': True},
        'shared': {'allow_post': False, 'allow_put': False,
                   'default': True, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
    },
    'firewalls': {
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
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'firewall_policy_id': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:uuid': None},
                               'is_visible': True},
        'shared': {'allow_post': False, 'allow_put': False,
                   'default': True, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
    },
}


class Firewall(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Firewall service"

    @classmethod
    def get_alias(cls):
        return "firewall"

    @classmethod
    def get_description(cls):
        return "Extension for Firewall service"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/Quantum/FWaaS/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2013-02-25T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.PLURALS.update(dict(my_plurals))
        resources = []
        plugin = manager.QuantumManager.get_service_plugins()[
            constants.FIREWALL]
        for collection_name in RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for resources with 'y' ending
            if collection_name == 'firewall_policies':
                resource_name = 'firewall_policy'
            else:
                resource_name = collection_name[:-1]

            params = RESOURCE_ATTRIBUTE_MAP[collection_name]

            member_actions = {}

            controller = base.create_resource(
                collection_name, resource_name, plugin, params,
                member_actions=member_actions,
                allow_pagination=cfg.CONF.allow_pagination,
                allow_sorting=cfg.CONF.allow_sorting)

            if resource_name == 'firewall':
                resource = extensions.ResourceExtension(
                    collection_name,
                    controller,
                    member_actions=member_actions,
                    attr_map=params)
            else:
                resource = extensions.ResourceExtension(
                    collection_name,
                    controller,
                    path_prefix=constants.COMMON_PREFIXES[constants.FIREWALL],
                    member_actions=member_actions,
                    attr_map=params)
            resources.append(resource)

        return resources

    @classmethod
    def get_plugin_interface(cls):
        return FirewallPluginBase

    def update_attributes_map(self, attributes):
        super(Firewall, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class FirewallPluginBase(ServicePluginBase):
    __metaclass__ = abc.ABCMeta

    def get_plugin_name(self):
        return constants.FIREWALL

    def get_plugin_type(self):
        return constants.FIREWALL

    def get_plugin_description(self):
        return 'Firewall service plugin'

    @abc.abstractmethod
    def get_firewalls(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall(self, context, firewall):
        pass

    @abc.abstractmethod
    def update_firewall(self, context, id, firewall):
        pass

    @abc.abstractmethod
    def delete_firewall(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_rules(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_rule(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall_rule(self, context, firewall_rule):
        pass

    @abc.abstractmethod
    def update_firewall_rule(self, context, id, firewall_rule):
        pass

    @abc.abstractmethod
    def delete_firewall_rule(self, context, id):
        pass

    @abc.abstractmethod
    def get_firewall_policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_firewall_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_firewall_policy(self, context, firewall_policy):
        pass

    @abc.abstractmethod
    def update_firewall_policy(self, context, id, firewall_policy):
        pass

    @abc.abstractmethod
    def delete_firewall_policy(self, context, id):
        pass
