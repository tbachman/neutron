__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler.filters import filters_base
from nova.db.sqlalchemy.models import Instance
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import db_base_plugin_v2 as base_db
import sqlalchemy as sa

class Neighbor(model_base.BASEV2, models_v2.HasId):

    physical_host = sa.Column(sa.String(255), nullable=False)
    neighbor = sa.Column(sa.String(255), nullable=False)


class NeighborsFilter(filters_base.BaseHostFilter, base_db.CommonDbMixin):

    def get_physical_host(self, context, vm):
        query = self._model_query(context, Instance)
        rt = query.filter(Instance.id == vm).one()
        hostname = rt['hostname']

        return hostname

    def get_neighbors(self, context, physical_host):
        self._get_collection(context, Neighbor,
                                    filters={'physical_host': [physical_host]},
                                    fields=['neighbor'])

    def host_passes(self, host, resource, context=None):

        physical_host = self.get_physical_host(context, resource)

        neighbors = self.get_neighbors(context, physical_host)

        if host in neighbors:
            return True
        else:
            return False

    def get_description(self):
        ""