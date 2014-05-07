__author__ = 'nalle'

from sqlalchemy.orm import exc
from neutron.plugins.cisco.db.scheduler.filter_chain_model import FilterChain
from neutron.db import db_base_plugin_v2 as base_db


class FilterChainManager(base_db.CommonDbMixin):

    def create_filter_chain(self, context, chain_name, filters):

        filters_string = ', '.join(filters)
        with context.session.begin(subtransactions=True):
            filter_chain_db = FilterChain(filter_name=chain_name,
                                          filter_list=filters_string)
            context.session.add(filter_chain_db)

    def get_filter_chain(self, context, chain_name):
        try:
            query = self._model_query(context, FilterChain)
            filter_string = query.filter(FilterChain.filter_name == chain_name).one()
            filters = filter_string.filter_list.split()
            return filters
        except exc.NoResultFound:
            pass

    def update_filter_chain(self, context, filter_id, new_filter_chain):
        filters_string = ', '.join(new_filter_chain)
        with context.session.begin(subtransactions=True):
            query = context.session.query(
                FilterChain).with_lockmode('update')
            db = query.filter_by(id=filter_id).one()
            db.update(filters_string)

    def delete_filter_chain(self, context, filter_id):

        with context.session.begin(subtransactions=True):
            query = context.session.query(
                FilterChain).with_lockmode('update')
            db = query.filter_by(id=filter_id).one()
            context.session.delete(db)