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
#
# @author: Bob Melander, Cisco Systems, Inc.

import contextlib
import logging

import mock
from oslo.config import cfg
import webob.exc

from neutron.api import extensions as api_ext
from neutron.common import config
from neutron import context
import neutron.extensions
from neutron.extensions import firewall
from neutron.openstack.common import importutils
from neutron.openstack.common import timeutils
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.plugins.cisco.l3.common import constants as cl3_constants
from neutron.plugins.cisco.l3.db import hosting_device_manager_db as hdm_db
from neutron.plugins.cisco.l3.extensions import ciscohostingdevicemanager
from neutron.tests.unit import test_db_plugin


LOG = logging.getLogger(__name__)
DB_DM_PLUGIN_KLASS = (
    "neutron.plugins.cisco.l3.db.hosting_device_manager_db."
    "HostingDeviceManagerMixin")
extensions_path = ':' + neutron.plugins.__path__[0] + '/cisco/l3/extensions'
NN_TEMPLATE_NAME = cl3_constants.NETWORK_NODE_TEMPLATE
NN_CATEGORY = ciscohostingdevicemanager.NETWORK_NODE_CATEGORY
VM_CATEGORY = ciscohostingdevicemanager.VM_CATEGORY
HW_CATEGORY = ciscohostingdevicemanager.HARDWARE_CATEGORY
DEFAULT_SERVICE_TYPES = 'router'
NETWORK_NODE_SERVICE_TYPES = 'router:fwaas:vpn'
NOOP_DEVICE_DRIVER = ('neutron.plugins.cisco.l3.hosting_device_drivers.'
                      'noop_hd_driver.NoopHostingDeviceDriver')
NOOP_PLUGGING_DRIVER = ('neutron.plugins.cisco.l3.plugging_drivers.'
                        'noop_plugging_driver.NoopPluggingDriver')
DESCRIPTION = 'default description'
SHARED = True
ACTION = 'allow'
ENABLED = True
ADMIN_STATE_UP = True


timestamp = timeutils.utcnow


class DeviceManagerTestCaseMixin(object):

    def _create_hosting_device(self, fmt, template_id, management_port_id,
                               admin_state_up, expected_res_status=None, **kwargs):
        data = {'hosting_device': self._get_test_hosting_device_attr(
            template_id=template_id, management_port_id=management_port_id,
            admin_state_up=admin_state_up, **kwargs)}
        hd_req = self.new_create_request('hosting_devices', data, fmt)
        hd_res = hd_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(hd_res.status_int, expected_res_status)
        return hd_res

    @contextlib.contextmanager
    def hosting_device(self, template_id, management_port_id, fmt=None,
                       admin_state_up=True, no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_hosting_device(fmt, template_id, management_port_id,
                                          admin_state_up, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        hosting_device = self.deserialize(fmt or self.fmt, res)
        yield hosting_device
        if not no_delete:
            self._delete('hosting_devices',
                         hosting_device['hosting_device']['id'])

    def _create_hosting_device_template(self, fmt, name, enabled,
                                        host_category,
                                        expected_res_status=None, **kwargs):
        data = {'hosting_device_template':
                    self._get_test_hosting_device_template_attr(
                        name=name, enabled=enabled,
                        host_category=host_category, **kwargs)}
        hdt_req = self.new_create_request('hosting_device_templates', data,
                                          fmt)

        hdt_res = hdt_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(hdt_res.status_int, expected_res_status)
        return hdt_res

    @contextlib.contextmanager
    def hosting_device_template(self, fmt=None, name='device_template_1',
                                enabled=True, host_category=VM_CATEGORY,
                                no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_hosting_device_template(fmt, name, enabled,
                                                   host_category, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        hd_template = self.deserialize(fmt or self.fmt, res)
        yield hd_template
        if not no_delete:
            self._delete('hosting_device_templates',
                         hd_template['hosting_device_template']['id'])

    def _get_test_hosting_device_attr(self, template_id, management_port_id,
                                      admin_state_up=True, **kwargs):
        data = {
            'tenant_id': kwargs.get('tenant_id', self._tenant_id),
            'template_id': template_id,
            'credentials_id': kwargs.get('credentials_id'),
            'device_id': kwargs.get('device_id', 'mfc_device_id'),
            'admin_state_up': admin_state_up,
            'management_port_id': management_port_id,
            'protocol_port': kwargs.get('protocol_port', 22),
            'cfg_agent_id': kwargs.get('cfg_agent_id'),
            'booting_time': kwargs.get('booting_time', 0),
            'tenant_bound': kwargs.get('tenant_bound'),
            'auto_delete_on_fail': kwargs.get('auto_delete_on_fail', False)}
        return data

    def _get_test_hosting_device_template_attr(self, name='device_template_1',
                                               enabled=True,
                                               host_category=VM_CATEGORY,
                                               **kwargs):
        data = {
            'tenant_id': kwargs.get('tenant_id', self._tenant_id),
            'name': name,
            'enabled': enabled,
            'host_category': host_category,
            'service_types': kwargs.get('service_types',
                                        DEFAULT_SERVICE_TYPES),
            'image': kwargs.get('image'),
            'flavor': kwargs.get('flavor'),
            'default_credentials_id': kwargs.get('default_credentials_id'),
            'configuration_mechanism': kwargs.get('configuration_mechanism'),
            'protocol_port': kwargs.get('protocol_port', 22),
            'booting_time': kwargs.get('booting_time', 0),
            'slot_capacity': kwargs.get('slot_capacity', 0),
            'desired_slots_free': kwargs.get('desired_slots_free', 0),
            'tenant_bound': kwargs.get('tenant_bound', []),
            'device_driver': kwargs.get('device_driver', NOOP_DEVICE_DRIVER),
            'plugging_driver': kwargs.get('plugging_driver',
                                          NOOP_PLUGGING_DRIVER)}
        return data

    def _test_list_resources(self, resource, items,
                             neutron_context=None,
                             query_params=None):
        if resource.endswith('y'):
            resource_plural = resource.replace('y', 'ies')
        else:
            resource_plural = resource + 's'

        res = self._list(resource_plural,
                         neutron_context=neutron_context,
                         query_params=query_params)
        resource = resource.replace('-', '_')
        self.assertEqual(sorted([i['id'] for i in res[resource_plural]]),
                         sorted([i[resource]['id'] for i in items]))

    def _replace_hosting_device_status(self, attrs, old_status, new_status):
        if attrs['status'] is old_status:
            attrs['status'] = new_status
        return attrs

    def _create_mgmt_nw_for_tests(self, fmt):
        self.mgmt_nw = self._make_network(fmt, cfg.CONF.management_network,
                                          True, tenant_id="L3AdminTenantId",
                                          shared=False)
        self.mgmt_subnet = self._make_subnet(fmt, self.mgmt_nw,
                                             "10.0.100.1", "10.0.100.0/24",
                                             ip_version=4)

    def _remove_mgmt_nw_for_tests(self):
        q_p = "network_id=%s" % self.mgmt_nw['network']['id']
        subnets = self._list('subnets', query_params=q_p)
        if subnets:
            for p in self._list('ports', query_params=q_p).get('ports'):
                self._delete('ports', p['id'])
            self._delete('subnets', self.mgmt_subnet['subnet']['id'])
            self._delete('networks', self.mgmt_nw['network']['id'])


class TestDeviceManagerDBPlugin(test_db_plugin.NeutronDbPluginV2TestCase,
                                DeviceManagerTestCaseMixin):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.DEVICE_MANAGER])
        for k in ciscohostingdevicemanager.RESOURCE_ATTRIBUTE_MAP.keys())

    def setUp(self, core_plugin=None, dm_plugin=None, ext_mgr=None):
        if dm_plugin is None:
            dm_plugin = DB_DM_PLUGIN_KLASS
        service_plugins = {'dm_plugin_name': dm_plugin}
        cfg.CONF.set_override('api_extensions_path', extensions_path)
        hdm_db.HostingDeviceManagerMixin.supported_extension_aliases = (
            [ciscohostingdevicemanager.HOSTING_DEVICE_MANAGER_ALIAS])
        super(TestDeviceManagerDBPlugin, self).setUp(
            ext_mgr=ext_mgr, service_plugins=service_plugins)

        if not ext_mgr:
            self.plugin = importutils.import_object(dm_plugin)
            ext_mgr = api_ext.PluginAwareExtensionManager(
                extensions_path, {constants.DEVICE_MANAGER: self.plugin})
            app = config.load_paste_app('extensions_test_app')
            self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)

        self._create_mgmt_nw_for_tests(self.fmt)

    def tearDown(self):
        self._remove_mgmt_nw_for_tests()
        super(TestDeviceManagerDBPlugin, self).tearDown()

    def test_create_vm_hosting_device(self):
        with self.hosting_device_template() as hdt:
            with self.port(subnet=self.mgmt_subnet) as mgmt_port:
                attrs = self._get_test_hosting_device_attr(
                    template_id=hdt['hosting_device_template']['id'],
                    management_port_id=mgmt_port['port']['id'],
                    auto_delete_on_fail=True)
                with self.hosting_device(
                        template_id=hdt['hosting_device_template']['id'],
                        management_port_id=mgmt_port['port']['id'],
                        auto_delete_on_fail=True) as hd:
                    for k, v in attrs.iteritems():
                        self.assertEqual(hd['hosting_device'][k], v)

    def test_create_hw_hosting_device(self):
        with self.hosting_device_template(host_category=HW_CATEGORY) as hdt:
            with self.port(subnet=self.mgmt_subnet) as mgmt_port:
                attrs = self._get_test_hosting_device_attr(
                    template_id=hdt['hosting_device_template']['id'],
                    management_port_id=mgmt_port['port']['id'])
                with self.hosting_device(
                        template_id=hdt['hosting_device_template']['id'],
                        management_port_id=mgmt_port['port']['id']) as hd:
                    for k, v in attrs.iteritems():
                        self.assertEqual(hd['hosting_device'][k], v)

    def _test_delete_hosting_device_in_use(self):
        pass



    def test_create_vm_hosting_device_template(self):
        attrs = self._get_test_hosting_device_template_attr()

        with self.hosting_device_template() as hdt:
            for k, v in attrs.iteritems():
                self.assertEqual(hdt['hosting_device_template'][k], v)

    def test_create_hw_hosting_device_template(self):
        attrs = self._get_test_hosting_device_template_attr(
            host_category=HW_CATEGORY)

        with self.hosting_device_template(host_category=HW_CATEGORY) as hdt:
            for k, v in attrs.iteritems():
                self.assertEqual(hdt['hosting_device_template'][k], v)

    def test_create_nn_hosting_device_template(self):
        attrs = self._get_test_hosting_device_template_attr(
            host_category=NN_CATEGORY)

        with self.hosting_device_template(host_category=NN_CATEGORY) as hdt:
            for k, v in attrs.iteritems():
                self.assertEqual(hdt['hosting_device_template'][k], v)

        pass

    def _test_show_hosting_device_template(self):
        pass

    def _test_list_hosting_device_templates(self):
        pass

    def _test_update_hosting_device_template(self):
        pass

    def _test_delete_hosting_device_template(self):
        pass

    def _test_delete_hosting_device_template_in_use(self):
        pass







class TestDeviceManagerDBPlugin_copy_from(DeviceManagerTestCaseMixin):

    def test_create_firewall_policy(self):
        name = "firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name)

        with self.firewall_policy(name=name, shared=SHARED,
                                  firewall_rules=None,
                                  audited=AUDITED) as firewall_policy:
            for k, v in attrs.iteritems():
                self.assertEqual(firewall_policy['firewall_policy'][k], v)

    def test_create_firewall_policy_with_rules(self):
        name = "firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name)

        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3')) as fr:
            fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
            attrs['firewall_rules'] = fw_rule_ids
            with self.firewall_policy(name=name, shared=SHARED,
                                      firewall_rules=fw_rule_ids,
                                      audited=AUDITED) as fwp:
                for k, v in attrs.iteritems():
                    self.assertEqual(fwp['firewall_policy'][k], v)

    def test_create_firewall_policy_with_previously_associated_rule(self):
        with self.firewall_rule() as fwr:
            fw_rule_ids = [fwr['firewall_rule']['id']]
            with self.firewall_policy(firewall_rules=fw_rule_ids):
                res = self._create_firewall_policy(
                    None, 'firewall_policy2', description=DESCRIPTION,
                    shared=SHARED, firewall_rules=fw_rule_ids,
                    audited=AUDITED)
                self.assertEqual(res.status_int, 409)

    def test_show_firewall_policy(self):
        name = "firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name)

        with self.firewall_policy(name=name, shared=SHARED,
                                  firewall_rules=None,
                                  audited=AUDITED) as fwp:
            req = self.new_show_request('firewall_policies',
                                        fwp['firewall_policy']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_policy'][k], v)

    def test_list_firewall_policies(self):
        with contextlib.nested(self.firewall_policy(name='fwp1',
                                                    description='fwp'),
                               self.firewall_policy(name='fwp2',
                                                    description='fwp'),
                               self.firewall_policy(name='fwp3',
                                                    description='fwp')
                               ) as fw_policies:
            self._test_list_resources('firewall_policy',
                                      fw_policies,
                                      query_params='description=fwp')

    def test_update_firewall_policy(self):
        name = "new_firewall_policy1"
        attrs = self._get_test_firewall_policy_attrs(name)

        with self.firewall_policy(shared=SHARED,
                                  firewall_rules=None,
                                  audited=AUDITED) as fwp:
            data = {'firewall_policy': {'name': name}}
            req = self.new_update_request('firewall_policies', data,
                                          fwp['firewall_policy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_policy'][k], v)

    def test_update_firewall_policy_with_rules(self):
        attrs = self._get_test_firewall_policy_attrs()

        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3')) as fr:
            with self.firewall_policy() as fwp:
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                attrs['firewall_rules'] = fw_rule_ids
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                attrs['audited'] = False
                for k, v in attrs.iteritems():
                    self.assertEqual(res['firewall_policy'][k], v)

    def test_update_firewall_policy_replace_rules(self):
        attrs = self._get_test_firewall_policy_attrs()

        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3'),
                               self.firewall_rule(name='fwr4')) as frs:
            fr1 = frs[0:2]
            fr2 = frs[2:4]
            with self.firewall_policy() as fwp:
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr1]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)

                fw_rule_ids = [r['firewall_rule']['id'] for r in fr2]
                attrs['firewall_rules'] = fw_rule_ids
                new_data = {'firewall_policy':
                            {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', new_data,
                                              fwp['firewall_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                attrs['audited'] = False
                for k, v in attrs.iteritems():
                    self.assertEqual(res['firewall_policy'][k], v)

    def test_update_firewall_policy_reorder_rules(self):
        attrs = self._get_test_firewall_policy_attrs()

        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3'),
                               self.firewall_rule(name='fwr4')) as fr:
            with self.firewall_policy() as fwp:
                fw_rule_ids = [fr[2]['firewall_rule']['id'],
                               fr[3]['firewall_rule']['id']]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                # shuffle the rules, add more rules
                fw_rule_ids = [fr[1]['firewall_rule']['id'],
                               fr[3]['firewall_rule']['id'],
                               fr[2]['firewall_rule']['id'],
                               fr[0]['firewall_rule']['id']]
                attrs['firewall_rules'] = fw_rule_ids
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                rules = []
                for rule_id in fw_rule_ids:
                    req = self.new_show_request('firewall_rules',
                                                rule_id,
                                                fmt=self.fmt)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))
                    rules.append(res['firewall_rule'])
                self.assertEqual(rules[0]['position'], 1)
                self.assertEqual(rules[0]['id'], fr[1]['firewall_rule']['id'])
                self.assertEqual(rules[1]['position'], 2)
                self.assertEqual(rules[1]['id'], fr[3]['firewall_rule']['id'])
                self.assertEqual(rules[2]['position'], 3)
                self.assertEqual(rules[2]['id'], fr[2]['firewall_rule']['id'])
                self.assertEqual(rules[3]['position'], 4)
                self.assertEqual(rules[3]['id'], fr[0]['firewall_rule']['id'])

    def test_update_firewall_policy_with_non_existing_rule(self):
        attrs = self._get_test_firewall_policy_attrs()

        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2')) as fr:
            with self.firewall_policy() as fwp:
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                # appending non-existent rule
                fw_rule_ids.append(uuidutils.generate_uuid())
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = req.get_response(self.ext_api)
                #check that the firewall_rule was not found
                self.assertEqual(res.status_int, 404)
                #check if none of the rules got added to the policy
                req = self.new_show_request('firewall_policies',
                                            fwp['firewall_policy']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in attrs.iteritems():
                    self.assertEqual(res['firewall_policy'][k], v)

    def test_delete_firewall_policy(self):
        ctx = context.get_admin_context()
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            req = self.new_delete_request('firewall_policies', fwp_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)
            self.assertRaises(firewall.FirewallPolicyNotFound,
                              self.plugin.get_firewall_policy,
                              ctx, fwp_id)

    def test_delete_firewall_policy_with_rule(self):
        ctx = context.get_admin_context()
        attrs = self._get_test_firewall_policy_attrs()
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall_rule(name='fwr1') as fr:
                fr_id = fr['firewall_rule']['id']
                fw_rule_ids = [fr_id]
                attrs['firewall_rules'] = fw_rule_ids
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                fw_rule = self.plugin.get_firewall_rule(ctx, fr_id)
                self.assertEqual(fw_rule['firewall_policy_id'], fwp_id)
                req = self.new_delete_request('firewall_policies', fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)
                self.assertRaises(firewall.FirewallPolicyNotFound,
                                  self.plugin.get_firewall_policy,
                                  ctx, fwp_id)
                fw_rule = self.plugin.get_firewall_rule(ctx, fr_id)
                self.assertIsNone(fw_rule['firewall_policy_id'])

    def test_delete_firewall_policy_with_firewall_association(self):
        attrs = self._get_test_firewall_attrs()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=
                               ADMIN_STATE_UP):
                req = self.new_delete_request('firewall_policies', fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 409)

    def test_create_firewall_rule(self):
        attrs = self._get_test_firewall_rule_attrs()

        with self.firewall_rule() as firewall_rule:
            for k, v in attrs.iteritems():
                self.assertEqual(firewall_rule['firewall_rule'][k], v)

        attrs['source_port'] = None
        attrs['destination_port'] = None
        with self.firewall_rule(source_port=None,
                                destination_port=None) as firewall_rule:
            for k, v in attrs.iteritems():
                self.assertEqual(firewall_rule['firewall_rule'][k], v)

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.firewall_rule(source_port=10000,
                                destination_port=80) as firewall_rule:
            for k, v in attrs.iteritems():
                self.assertEqual(firewall_rule['firewall_rule'][k], v)

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.firewall_rule(source_port='10000',
                                destination_port='80') as firewall_rule:
            for k, v in attrs.iteritems():
                self.assertEqual(firewall_rule['firewall_rule'][k], v)

    def test_show_firewall_rule_with_fw_policy_not_associated(self):
        attrs = self._get_test_firewall_rule_attrs()
        with self.firewall_rule() as fw_rule:
            req = self.new_show_request('firewall_rules',
                                        fw_rule['firewall_rule']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_rule'][k], v)

    def test_show_firewall_rule_with_fw_policy_associated(self):
        attrs = self._get_test_firewall_rule_attrs()
        with self.firewall_rule() as fw_rule:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                data = {'firewall_policy':
                        {'firewall_rules':
                         [fw_rule['firewall_rule']['id']]}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                req = self.new_show_request('firewall_rules',
                                            fw_rule['firewall_rule']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in attrs.iteritems():
                    self.assertEqual(res['firewall_rule'][k], v)

    def test_list_firewall_rules(self):
        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3')) as fr:
            query_params = 'protocol=tcp'
            self._test_list_resources('firewall_rule', fr,
                                      query_params=query_params)

    def test_update_firewall_rule(self):
        name = "new_firewall_rule1"
        attrs = self._get_test_firewall_rule_attrs(name)

        attrs['source_port'] = '10:20'
        attrs['destination_port'] = '30:40'
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'source_port': '10:20',
                                      'destination_port': '30:40'}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_rule'][k], v)

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'source_port': 10000,
                                      'destination_port': 80}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_rule'][k], v)

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'source_port': '10000',
                                      'destination_port': '80'}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_rule'][k], v)

        attrs['source_port'] = None
        attrs['destination_port'] = None
        with self.firewall_rule() as fwr:
            data = {'firewall_rule': {'name': name,
                                      'source_port': None,
                                      'destination_port': None}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in attrs.iteritems():
                self.assertEqual(res['firewall_rule'][k], v)

    def test_update_firewall_rule_with_policy_associated(self):
        name = "new_firewall_rule1"
        attrs = self._get_test_firewall_rule_attrs(name)
        with self.firewall_rule() as fwr:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                fwr_id = fwr['firewall_rule']['id']
                data = {'firewall_policy': {'firewall_rules': [fwr_id]}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                data = {'firewall_rule': {'name': name}}
                req = self.new_update_request('firewall_rules', data,
                                              fwr['firewall_rule']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                attrs['firewall_policy_id'] = fwp_id
                for k, v in attrs.iteritems():
                    self.assertEqual(res['firewall_rule'][k], v)
                req = self.new_show_request('firewall_policies',
                                            fwp['firewall_policy']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertEqual(res['firewall_policy']['firewall_rules'],
                                 [fwr_id])
                self.assertEqual(res['firewall_policy']['audited'], False)

    def test_delete_firewall_rule(self):
        ctx = context.get_admin_context()
        with self.firewall_rule(no_delete=True) as fwr:
            fwr_id = fwr['firewall_rule']['id']
            req = self.new_delete_request('firewall_rules', fwr_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)
            self.assertRaises(firewall.FirewallRuleNotFound,
                              self.plugin.get_firewall_rule,
                              ctx, fwr_id)

    def test_delete_firewall_rule_with_policy_associated(self):
        attrs = self._get_test_firewall_rule_attrs()
        with self.firewall_rule() as fwr:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['firewall_policy_id'] = fwp_id
                fwr_id = fwr['firewall_rule']['id']
                data = {'firewall_policy': {'firewall_rules': [fwr_id]}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                req = self.new_delete_request('firewall_rules', fwr_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 409)

    #TODO(bobmel): Start copying here!!!

    def test_create_firewall(self):
        name = "firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall(name=name,
                               firewall_policy_id=fwp_id,
                               admin_state_up=
                               ADMIN_STATE_UP) as firewall:
                for k, v in attrs.iteritems():
                    self.assertEqual(firewall['firewall'][k], v)

    def test_show_firewall(self):
        name = "firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall(name=name,
                               firewall_policy_id=fwp_id,
                               admin_state_up=
                               ADMIN_STATE_UP) as firewall:
                req = self.new_show_request('firewalls',
                                            firewall['firewall']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in attrs.iteritems():
                    self.assertEqual(res['firewall'][k], v)

    def test_list_firewalls(self):
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with contextlib.nested(self.firewall(name='fw1',
                                                 firewall_policy_id=fwp_id,
                                                 description='fw'),
                                   self.firewall(name='fw2',
                                                 firewall_policy_id=fwp_id,
                                                 description='fw'),
                                   self.firewall(name='fw3',
                                                 firewall_policy_id=fwp_id,
                                                 description='fw')) as fwalls:
                self._test_list_resources('firewall', fwalls,
                                          query_params='description=fw')

    def test_update_firewall(self):
        name = "new_firewall1"
        attrs = self._get_test_firewall_attrs(name)

        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            attrs['firewall_policy_id'] = fwp_id
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=
                               ADMIN_STATE_UP) as firewall:
                data = {'firewall': {'name': name}}
                req = self.new_update_request('firewalls', data,
                                              firewall['firewall']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in attrs.iteritems():
                    self.assertEqual(res['firewall'][k], v)

    def test_delete_firewall(self):
        ctx = context.get_admin_context()
        with self.firewall_policy() as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               no_delete=True) as fw:
                fw_id = fw['firewall']['id']
                req = self.new_delete_request('firewalls', fw_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)
                self.assertRaises(firewall.FirewallNotFound,
                                  self.plugin.get_firewall,
                                  ctx, fw_id)

    def test_insert_rule_in_policy_with_prior_rules_added_via_update(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        attrs['firewall_list'] = []
        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3')) as frs:
            fr1 = frs[0:2]
            fwr3 = frs[2]
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['id'] = fwp_id
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr1]
                attrs['firewall_rules'] = fw_rule_ids[:]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                self._rule_action('insert', fwp_id, fw_rule_ids[0],
                                  insert_before=fw_rule_ids[0],
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPConflict.code,
                                  expected_body=None)
                fwr3_id = fwr3['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr3_id)
                self._rule_action('insert', fwp_id, fwr3_id,
                                  insert_before=fw_rule_ids[0],
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)

    def test_insert_rule_in_policy_failures(self):
        with self.firewall_rule(name='fwr1') as fr1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fr1_id = fr1['firewall_rule']['id']
                fw_rule_ids = [fr1_id]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                # test inserting with empty request body
                self._rule_action('insert', fwp_id, '123',
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None, body_data={})
                # test inserting when firewall_rule_id is missing in
                # request body
                insert_data = {'insert_before': '123',
                               'insert_after': '456'}
                self._rule_action('insert', fwp_id, '123',
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None,
                                  body_data=insert_data)
                # test inserting when firewall_rule_id is None
                insert_data = {'firewall_rule_id': None,
                               'insert_before': '123',
                               'insert_after': '456'}
                self._rule_action('insert', fwp_id, '123',
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None,
                                  body_data=insert_data)
                # test inserting when firewall_policy_id is incorrect
                self._rule_action('insert', '123', fr1_id,
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test inserting when firewall_policy_id is None
                self._rule_action('insert', None, fr1_id,
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None)

    def test_insert_rule_for_previously_associated_rule(self):
        with self.firewall_rule() as fwr:
            fwr_id = fwr['firewall_rule']['id']
            fw_rule_ids = [fwr_id]
            with self.firewall_policy(firewall_rules=fw_rule_ids):
                with self.firewall_policy(name='firewall_policy2') as fwp:
                    fwp_id = fwp['firewall_policy']['id']
                    insert_data = {'firewall_rule_id': fwr_id}
                    self._rule_action(
                        'insert', fwp_id, fwr_id, insert_before=None,
                        insert_after=None,
                        expected_code=webob.exc.HTTPConflict.code,
                        expected_body=None, body_data=insert_data)

    def test_insert_rule_in_policy(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        attrs['firewall_list'] = []
        with contextlib.nested(self.firewall_rule(name='fwr0'),
                               self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3'),
                               self.firewall_rule(name='fwr4'),
                               self.firewall_rule(name='fwr5'),
                               self.firewall_rule(name='fwr6')) as fwr:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['id'] = fwp_id
                # test insert when rule list is empty
                fwr0_id = fwr[0]['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr0_id)
                self._rule_action('insert', fwp_id, fwr0_id,
                                  insert_before=None,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert at top of rule list, insert_before and
                # insert_after not provided
                fwr1_id = fwr[1]['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr1_id)
                insert_data = {'firewall_rule_id': fwr1_id}
                self._rule_action('insert', fwp_id, fwr0_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs, body_data=insert_data)
                # test insert at top of list above existing rule
                fwr2_id = fwr[2]['firewall_rule']['id']
                attrs['firewall_rules'].insert(0, fwr2_id)
                self._rule_action('insert', fwp_id, fwr2_id,
                                  insert_before=fwr1_id,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert at bottom of list
                fwr3_id = fwr[3]['firewall_rule']['id']
                attrs['firewall_rules'].append(fwr3_id)
                self._rule_action('insert', fwp_id, fwr3_id,
                                  insert_before=None,
                                  insert_after=fwr0_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert in the middle of the list using
                # insert_before
                fwr4_id = fwr[4]['firewall_rule']['id']
                attrs['firewall_rules'].insert(1, fwr4_id)
                self._rule_action('insert', fwp_id, fwr4_id,
                                  insert_before=fwr1_id,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert in the middle of the list using
                # insert_after
                fwr5_id = fwr[5]['firewall_rule']['id']
                attrs['firewall_rules'].insert(1, fwr5_id)
                self._rule_action('insert', fwp_id, fwr5_id,
                                  insert_before=None,
                                  insert_after=fwr2_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert when both insert_before and
                # insert_after are set
                fwr6_id = fwr[6]['firewall_rule']['id']
                attrs['firewall_rules'].insert(1, fwr6_id)
                self._rule_action('insert', fwp_id, fwr6_id,
                                  insert_before=fwr5_id,
                                  insert_after=fwr5_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)

    def test_remove_rule_from_policy(self):
        attrs = self._get_test_firewall_policy_attrs()
        attrs['audited'] = False
        attrs['firewall_list'] = []
        with contextlib.nested(self.firewall_rule(name='fwr1'),
                               self.firewall_rule(name='fwr2'),
                               self.firewall_rule(name='fwr3')) as fr1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                attrs['id'] = fwp_id
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr1]
                attrs['firewall_rules'] = fw_rule_ids[:]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                # test removing a rule from a policy that does not exist
                self._rule_action('remove', '123', fw_rule_ids[1],
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test removing a rule in the middle of the list
                attrs['firewall_rules'].remove(fw_rule_ids[1])
                self._rule_action('remove', fwp_id, fw_rule_ids[1],
                                  expected_body=attrs)
                # test removing a rule at the top of the list
                attrs['firewall_rules'].remove(fw_rule_ids[0])
                self._rule_action('remove', fwp_id, fw_rule_ids[0],
                                  expected_body=attrs)
                # test removing remaining rule in the list
                attrs['firewall_rules'].remove(fw_rule_ids[2])
                self._rule_action('remove', fwp_id, fw_rule_ids[2],
                                  expected_body=attrs)
                # test removing rule that is not associated with the policy
                self._rule_action('remove', fwp_id, fw_rule_ids[2],
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None)

    def test_remove_rule_from_policy_failures(self):
        with self.firewall_rule(name='fwr1') as fr1:
            with self.firewall_policy() as fwp:
                fwp_id = fwp['firewall_policy']['id']
                fw_rule_ids = [fr1['firewall_rule']['id']]
                data = {'firewall_policy':
                        {'firewall_rules': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp_id)
                req.get_response(self.ext_api)
                # test removing rule that does not exist
                self._rule_action('remove', fwp_id, '123',
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test removing rule with bad request
                self._rule_action('remove', fwp_id, '123',
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None, body_data={})
                # test removing rule with firewall_rule_id set to None
                self._rule_action('remove', fwp_id, '123',
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None,
                                  body_data={'firewall_rule_id': None})


class TestDeviceManagerDBPluginXML(TestDeviceManagerDBPlugin):
    fmt = 'xml'
