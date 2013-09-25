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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import firewall
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils


LOG = logging.getLogger(__name__)


class FirewallPolicyRuleAssociation(model_base.BASEV2, models_v2.HasId):
    __tablename__ = 'firewall_policy_rule_association'
    firewall_rule_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('firewall_rule.id'))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policy.id'))


class FirewallRule(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall rule."""
    __tablename__ = 'firewall_rule'
    direction = sa.Column(sa.Enum('ingress', 'egress',
                                  name='firewallrules_direction'))
    protocol = sa.Column(sa.String(40))
    description = sa.Column(sa.String(1024))
    source_ip_address = sa.Column(sa.String(128))
    destination_ip_address = sa.Column(sa.String(128))
    port_range_min = sa.Column(sa.Integer)
    port_range_max = sa.Column(sa.Integer)
    application = sa.Column(sa.String(256))
    action = sa.Column(sa.Enum('allow', 'deny',
                                  name='firewallrules_action'))
    dynamic_attributes = sa.Column(sa.String(1024))


class FirewallPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall Policy resource"""
    __tablename__ = 'firewall_policy'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    firewall_rules = orm.relationship(FirewallRule,
                                      secondary=
                                      'firewall_policy_rule_association')
    audited = sa.Column(sa.Boolean)


class Firewall(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall resource"""
    __tablename__ = 'firewall'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policy.id'))


class Firewall_db_mixin(firewall.FirewallPluginBase):
    """Mixin class to add Firewall methods to db_plugin_base_v2"""


    def _get_firewall(self, context, id):
        try:
            fw = self._get_by_id(context, Firewall, id)
        except exc.NoResultFound:
            raise firewall.FirewallNotFound(firewall_id=id)
        except exc.MultipleResultsFound:
            LOG.error(_('Multiple firewalls match for %s'), id)
            raise firewall.FirewallNotFound(firewall_id=id)
        return fw

    def _get_firewall_policy(self, context, id):
        try:
            firewall_policy = self._get_by_id(context, FirewallPolicy, id)
        except exc.NoResultFound:
            raise firewall.FirewallPolicyNotFound(firewall_policy_id=id)
        except exc.MultipleResultsFound:
            LOG.error(_('Multiple firewalls match for %s'), id)
            raise firewall.FirewallPolicyNotFound(firewall_policy_id=id)
        return firewall_policy

    def _get_firewall_rule(self, context, id):
        try:
            firewall_rule = self._get_by_id(context, FirewallRule, id)
        except exc.NoResultFound:
            raise firewall.FirewallRuleNotFound(firewall_rule_id=id)
        except exc.MultipleResultsFound:
            LOG.error(_('Multiple firewall rules match for %s'), id)
            raise firewall.FirewallRuleNotFound(firewall_rule_id=id)
        return firewall_rule

    def _make_firewall_dict(self, fw, fields=None):
        res = {'id': fw['id'],
               'name': fw['name'],
               'description': fw['description'],
               'tenant_id': fw['tenant_id'],
               'admin_state_up': fw['admin_state_up'],
               'status': fw['status'],
               'firewall_policy_id': fw['firewall_policy_id']}
        return self._fields(res, fields)

    def _make_firewall_policy_dict(self, firewall_policy, fields=None):
        fw_rules = []
        for rule in firewall_policy['firewall_rules']:
            fw_rules.append(rule['id'])
        res = {'id': firewall_policy['id'],
               'name': firewall_policy['name'],
               'description': firewall_policy['description'],
               'tenant_id': firewall_policy['tenant_id'],
               'audited': firewall_policy['audited'],
               'firewall_rules_list': fw_rules}
        return self._fields(res, fields)

    def _make_firewall_rule_dict(self, firewall_rule, fields=None):
        res = {'id': firewall_rule['id'],
               'description': firewall_rule['description'],
               'direction': firewall_rule['direction'],
               'tenant_id': firewall_rule['tenant_id'],
               'protocol': firewall_rule['protocol'],
               'source_ip_address': firewall_rule['source_ip_address'],
               'destination_ip_address':
               firewall_rule['destination_ip_address'],
               'port_range_min': firewall_rule['port_range_min'],
               'port_range_max': firewall_rule['port_range_max'],
               'application': firewall_rule['application'],
               'action': firewall_rule['action'],
               'dynamic_attributes': firewall_rule['dynamic_attributes']}
        return self._fields(res, fields)

    def create_firewall(self, context, fwall):
        fw = fwall['firewall']
        tenant_id = self._get_tenant_id_for_create(context, fw)
        with context.session.begin(subtransactions=True):
            firewall_db = Firewall(id=uuidutils.generate_uuid(),
                                   tenant_id=tenant_id,
                                   name=fw['name'],
                                   description=fw['description'],
                                   firewall_policy_id=
                                   fw['firewall_policy_id'],
                                   admin_state_up=fw['admin_state_up'],
                                   status="ACTIVE")
            context.session.add(firewall_db)
        return self._make_firewall_dict(firewall_db)

    def update_firewall(self, context, id, fwall):
        fw = fwall['firewall']
        with context.session.begin(subtransactions=True):
            firewall_db = self._get_firewall(context, id)
            # Ensure we actually have something to update
            if fw.keys():
                firewall_db.update(fw)
        return self._make_firewall_dict(firewall_db)

    def delete_firewall(self, context, id):
        with context.session.begin(subtransactions=True):
            fw = self._get_firewall(context, id)

            # TODO (Sumit) Ensure that the firewall is not active

            context.session.delete(fw)

    def get_firewall(self, context, id, fields=None):
        fw = self._get_firewall(context, id)
        return self._make_firewall_dict(fw, fields)

    def get_firewalls(self, context, filters=None, fields=None):
        return self._get_collection(context, Firewall,
                                    self._make_firewall_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_count(self, context, filters=None):
        return self._get_collection_count(context, Firewall,
                                          filters=filters)

    def create_firewall_policy(self, context, firewall_policy):
        fwp = firewall_policy['firewall_policy']
        tenant_id = self._get_tenant_id_for_create(context, fwp)
        with context.session.begin(subtransactions=True):
            fwp_db = FirewallPolicy(id=uuidutils.generate_uuid(),
                                    tenant_id=tenant_id,
                                    name=fwp['name'],
                                    description=fwp['description'],
                                    audited=fwp['audited'])
                                    #firewall_rules=fwp['firewall_rules_list'])
            context.session.add(fwp_db)
            for fwrule_id in fwp['firewall_rules_list']:
                try:
                    qry = context.session.query(FirewallRule)
                    rule = qry.filter_by(id=fwrule_id).one()
                except exc.NoResultFound:
                    raise firewall.FirewallRuleNotFound(firewall_rule_id=
                                                        fwrule_id)

                assoc = FirewallPolicyRuleAssociation(firewall_rule_id=
                                                      fwrule_id,
                                                      firewall_policy_id=
                                                      fwp_db['id'])
                context.session.add(assoc)
        qry = context.session.query(FirewallPolicy)
        fwp_db = qry.filter_by(id=fwp_db['id']).one()
        return self._make_firewall_policy_dict(fwp_db)

    def update_firewall_policy(self, context, id, firewall_policy):
        fwp = firewall_policy['firewall_policy']
        with context.session.begin(subtransactions=True):
            fwp_db = self._get_firewall_policy(context, id)
            if 'firewall_rules_list' in fwp.keys():
                # Ensure we actually have something to update
                for fwrule_id in fwp['firewall_rules_list']:
                    try:
                        qry = context.session.query(FirewallRule)
                        rule = qry.filter_by(id=fwrule_id).one()
                    except exc.NoResultFound:
                        raise firewall.FirewallRuleNotFound(pool_id=fwrule_id)

                    try:
                        session = context.session
                        qry = session.query(FirewallPolicyRuleAssociation)
                        row = qry.filter_by(firewall_rule_id=fwrule_id,
                                             firewall_policy_id=
                                             fwp_db['id']).one()
                    except exc.NoResultFound:
                        assoc = FirewallPolicyRuleAssociation(firewall_rule_id=
                                                          fwrule_id,
                                                          firewall_policy_id=
                                                          fwp_db['id'])
                        context.session.add(assoc)
                del fwp['firewall_rules_list']
            if fwp.keys():
                fwp_db.update(fwp)
        return self._make_firewall_policy_dict(fwp_db)

    def delete_firewall_policy(self, context, id):
        with context.session.begin(subtransactions=True):
            fwp = self._get_firewall_policy(context, id)

            # TODO (Sumit) Ensure that the firewall_policy  is not
            # being used

            context.session.delete(fwp)

    def get_firewall_policy(self, context, id, fields=None):
        fwp = self._get_firewall_policy(context, id)
        return self._make_firewall_policy_dict(fwp, fields)

    def get_firewall_policies(self, context, filters=None, fields=None):
        return self._get_collection(context, FirewallPolicy,
                                    self._make_firewall_policy_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_policies_count(self, context, filters=None):
        return self._get_collection_count(context, FirewallPolicy,
                                          filters=filters)

    def create_firewall_rule(self, context, firewall_rule):
        fwr = firewall_rule['firewall_rule']
        tenant_id = self._get_tenant_id_for_create(context, fwr)
        with context.session.begin(subtransactions=True):
            fwr_db = FirewallRule(id=uuidutils.generate_uuid(),
                                  tenant_id=tenant_id,
                                  description=fwr['description'],
                                  direction=fwr['direction'],
                                  protocol=fwr['protocol'],
                                  source_ip_address=fwr['source_ip_address'],
                                  destination_ip_address=
                                  fwr['destination_ip_address'],
                                  port_range_min=fwr['port_range_min'],
                                  port_range_max=fwr['port_range_max'],
                                  application=fwr['application'],
                                  action=fwr['action'],
                                  dynamic_attributes=
                                  fwr['dynamic_attributes'])
            context.session.add(fwr_db)
        return self._make_firewall_rule_dict(fwr_db)

    def update_firewall_rule(self, context, id, firewall_rule):
        fwr = firewall_rule['firewall_rule']
        with context.session.begin(subtransactions=True):
            fwr_db = self._get_firewall_rule(context, id)
            # Ensure we actually have something to update
            if fwr.keys():
                fwr_db.update(fwr)
        return self._make_firewall_rule_dict(fwr_db)

    def delete_firewall_rule(self, context, id):
        with context.session.begin(subtransactions=True):
            fwr = self._get_firewall_rule(context, id)

            # TODO (Sumit) Ensure that the firewall_rule  is not
            # being used

            context.session.delete(fwr)

    def get_firewall_rule(self, context, id, fields=None):
        fwr = self._get_firewall_rule(context, id)
        return self._make_firewall_rule_dict(fwr, fields)

    def get_firewall_rules(self, context, filters=None, fields=None):
        return self._get_collection(context, FirewallRule,
                                    self._make_firewall_rule_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_rules_count(self, context, filters=None):
        return self._get_collection_count(context, FirewallRule,
                                          filters=filters)
