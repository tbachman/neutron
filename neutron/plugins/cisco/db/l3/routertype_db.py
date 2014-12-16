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


from oslo.db import exception as db_exc
from oslo.utils import excutils
from sqlalchemy import exc as sql_exc
from sqlalchemy.orm import exc

from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.db.l3 import l3_models
import neutron.plugins.cisco.extensions.routertype as routertype

LOG = logging.getLogger(__name__)


class RoutertypeDbMixin(routertype.RoutertypePluginBase):
    """Mixin class for Router types."""

    def create_routertype(self, context, routertype):
        """Creates a router type.

        Also binds it to the specified hosting device template.
        """
        LOG.debug("create_routertype() called. Contents %s", routertype)
        rt = routertype['routertype']
        tenant_id = self._get_tenant_id_for_create(context, rt)
        with context.session.begin(subtransactions=True):
            routertype_db = l3_models.RouterType(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=rt['name'],
                description=rt['description'],
                template_id=rt['template_id'],
                shared=rt['shared'],
                slot_need=rt['slot_need'],
                scheduler=rt['scheduler'],
                cfg_agent_driver=rt['cfg_agent_driver'])
            context.session.add(routertype_db)
        return self._make_routertype_dict(routertype_db)

    def update_routertype(self, context, id, routertype):
        LOG.debug("update_routertype() called")
        rt = routertype['routertype']
        with context.session.begin(subtransactions=True):
            rt_query = context.session.query(l3_models.RouterType)
            if not rt_query.filter_by(id=id).update(rt):
                raise routertype.RouterTypeNotFound(id=id)
        return self.get_routertype(context, id)

    def delete_routertype(self, context, id):
        LOG.debug("delete_routertype() called")
        try:
            with context.session.begin(subtransactions=True):
                routertype_query = context.session.query(l3_models.RouterType)
                if not routertype_query.filter_by(id=id).delete():
                    raise routertype.RouterTypeNotFound(id=id)
        except db_exc.DBError as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if isinstance(e.inner_exception, sql_exc.IntegrityError):
                    ctxt.reraise = False
                    raise routertype.RouterTypeInUse(id=id)

    def get_routertype(self, context, id, fields=None):
        LOG.debug("get_routertype() called")
        rtd = self._get_routertype(context, id)
        return self._make_routertype_dict(rtd, fields)

    def get_routertypes(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        LOG.debug("get_routertypes() called")
        return self._get_collection(context, l3_models.RouterType,
                                    self._make_routertype_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker,
                                    page_reverse=page_reverse)

    def _get_routertype(self, context, id):
        try:
            return self._get_by_id(context, l3_models.RouterType, id)
        except exc.NoResultFound:
            raise routertype.RouterTypeNotFound(id=id)

    def _make_routertype_dict(self, routertype, fields=None):
        res = {'id': routertype['id'],
               'tenant_id': routertype['tenant_id'],
               'name': routertype['name'],
               'description': routertype['description'],
               'template_id': routertype['template_id'],
               'shared': routertype['shared'],
               'slot_need': routertype['slot_need'],
               'scheduler': routertype['scheduler'],
               'cfg_agent_driver': routertype['cfg_agent_driver']}
        return self._fields(res, fields)