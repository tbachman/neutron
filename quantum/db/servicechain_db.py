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
from quantum.extensions import servicechain
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils


LOG = logging.getLogger(__name__)


class ServiceChainTemplate(model_base.BASEV2, models_v2.HasId,
                           models_v2.HasTenant):
    """Represents a Service Chain Template resource"""
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    services_types = sa.Column(sa.VARCHAR(2048))
    shared = sa.Column(sa.Boolean)


class ServiceChain(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a service chain resource"""
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    service_chain_template_id = sa.Column(sa.String(36), sa.ForeignKey(
                                          'servicechaintemplates.id'))
    source_network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id"))
    destination_network_id = sa.Column(sa.String(36),
                                       sa.ForeignKey("networks.id"))
    services_chain = sa.Column(sa.VARCHAR(2048))


class ServiceChain_db_mixin(servicechain.ServiceChainPluginBase):
    """Mixin class to add Service Chain methods to db_plugin_base_v2"""

    def _get_service_chain_template(self, context, id):
        try:
            sct = self._get_by_id(context, ServiceChainTemplate, id)
        except exc.NoResultFound:
            raise servicechain.ServiceChainTemplateNotFound(template_id=id)
        except exc.MultipleResultsFound:
            LOG.error(_('Multiple service chain templates match for %s'), id)
            raise servicechain.ServiceChainTemplateNotFound(template_id=id)
        return sct

    def _get_service_chain(self, context, id):
        try:
            sc = self._get_by_id(context, ServiceChain, id)
        except exc.NoResultFound:
            raise servicechain.ServiceChainNotFound(service_chain_id=id)
        except exc.MultipleResultsFound:
            LOG.error(_('Multiple service chains match for %s'), id)
            raise servicechain.ServiceChainNotFound(service_chain_id=id)
        return sc

    def _make_service_chain_template_dict(self, sct, fields=None):
        types_list = sct['services_types'].split(',')
        res = {'id': sct['id'],
               'name': sct['name'],
               'description': sct['description'],
               'tenant_id': sct['tenant_id'],
               'shared': sct['shared'],
               'services_types_list': types_list}
        return self._fields(res, fields)

    def _make_service_chain_dict(self, sc, fields=None):
        services_list = sc['services_chain'].split(',')
        res = {'id': sc['id'],
               'name': sc['name'],
               'description': sc['description'],
               'tenant_id': sc['tenant_id'],
               'service_chain_template_id': sc['service_chain_template_id'],
               'source_network_id': sc['source_network_id'],
               'destination_network_id': sc['destination_network_id'],
               'services_list': services_list}
        return self._fields(res, fields)

    def create_service_chain(self, context, service_chain):
        sc = service_chain['service_chain']
        if not sc['source_network_id'] and not sc['destination_network_id']:
            raise servicechain.ServiceChainNoNetworks()
        tenant_id = self._get_tenant_id_for_create(context, sc)
        services_list_str = ','.join(sc['services_list'])
        with context.session.begin(subtransactions=True):
            sc_db = ServiceChain(id=uuidutils.generate_uuid(),
                                 tenant_id=tenant_id,
                                 name=sc['name'],
                                 description=sc['description'],
                                 service_chain_template_id=
                                 sc['template_id'],
                                 source_network_id=
                                 sc['source_network_id'],
                                 destination_network_id=
                                 sc['destination_network_id'],
                                 services_chain=services_list_str)
            context.session.add(sc_db)
        return self._make_service_chain_dict(sc_db)

    def update_service_chain(self, context, id, service_chain):
        sc = service_chain['service_chain']
        with context.session.begin(subtransactions=True):
            sc_db = self._get_service_chain(context, id)
            # Ensure we actually have something to update
            if sc.keys():
                sc_db.update(sc)
        return self._make_service_chain_dict(sc_db)

    def delete_service_chain(self, context, id):
        with context.session.begin(subtransactions=True):
            sc = self._get_service_chain(context, id)
            # TODO (Sumit) Ensure that the service_chain  is not
            # being used
            context.session.delete(sc)

    def get_service_chain(self, context, id, fields=None):
        sc = self._get_service_chain(context, id)
        return self._make_service_chain_dict(sc, fields)

    def get_service_chains(self, context, filters=None, fields=None):
        return self._get_collection(context, ServiceChain,
                                    self._make_service_chain_dict,
                                    filters=filters, fields=fields)

    def get_service_chains_count(self, context, filters=None):
        return self._get_collection_count(context, ServiceChain,
                                          filters=filters)

    def create_service_chain_template(self, context, service_chain_template):
        sct = service_chain_template['service_chain_template']
        tenant_id = self._get_tenant_id_for_create(context, sct)
        types_list_str = ','.join(sct['services_types_list'])
        with context.session.begin(subtransactions=True):
            sct_db = ServiceChainTemplate(id=uuidutils.generate_uuid(),
                                          tenant_id=tenant_id,
                                          name=sct['name'],
                                          description=sct['description'],
                                          shared=sct['shared'],
                                          services_types=types_list_str)
            context.session.add(sct_db)
        return self._make_service_chain_template_dict(sct_db)

    def update_service_chain_template(self, context, id,
                                      service_chain_template):
        sct = service_chain_template['service_chain_template']
        with context.session.begin(subtransactions=True):
            sct_db = self._get_service_chain_template(context, id)
            # Ensure we actually have something to update
            if sct.keys():
                sct_db.update(sct)
        return self._make_service_chain_template_dict(sct_db)

    def delete_service_chain_template(self, context, id):
        with context.session.begin(subtransactions=True):
            sct = self._get_service_chain_template(context, id)
            # TODO (Sumit) Ensure that the service_chain_template  is not
            # being used
            context.session.delete(sct)

    def get_service_chain_template(self, context, id, fields=None):
        sct = self._get_service_chain_template(context, id)
        return self._make_service_chain_template_dict(sct, fields)

    def get_service_chain_templates(self, context, filters=None, fields=None):
        return self._get_collection(context, ServiceChainTemplate,
                                    self._make_service_chain_template_dict,
                                    filters=filters, fields=fields)

    def get_service_chain_templates_count(self, context, filters=None):
        return self._get_collection_count(context, ServiceChainTemplate,
                                          filters=filters)
