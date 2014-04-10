__author__ = 'nalle'

from sqlalchemy.orm import exc
from neutron.plugins.cisco.l3.db.filter_chain_model import FilterChain
from neutron.db import db_base_plugin_v2 as base_db


class FilterChainManager(base_db.CommonDbMixin):

    def create_filter_chain(self, context, filters):

        filters_string = ', '.join(filters)
        with context.session.begin(subtransactions=True):
            filter_chain_db = FilterChain(filter_list=filters_string)
            context.session.add(filter_chain_db)

    def get_filter_chain(self, context, filter_id):
        try:
            query = self._model_query(context, FilterChain)
            filter_string = query.filter(FilterChain.id == filter_id).one()
            filters = filter_string.split()
            return filters
        except exc.NoResultFound:
            pass