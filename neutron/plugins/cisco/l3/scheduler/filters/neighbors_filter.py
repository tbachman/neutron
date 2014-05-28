__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler import filters
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import db_base_plugin_v2 as base_db
import sqlalchemy as sa


class Neighbor(model_base.BASEV2, models_v2.HasId):

    __tablename__ = 'neighbors'

    physical_host = sa.Column(sa.TEXT, nullable=False)
    neighbor = sa.Column(sa.TEXT, nullable=False)


class NeighborsFilter(filters.BaseHostFilter, base_db.CommonDbMixin):

    def get_neighbors(self, context, physical_host):
        query = self._model_query(context, Neighbor)
        neighbors = query.filter(Neighbor.physical_host == physical_host)

        apa = neighbors.all()

        return apa

    def _make_neighbor_dict(self, neighbor, fields=None):
        res = {'physical_host': neighbor['physical_host'],
               'neighbor': neighbor['neighbor']}
        return self._fields(res, fields)

    def filter_all(self, context, host_list, resource, **kwargs):
        neighbor_physical_host = kwargs.get('neighbor_physical_host')

        physical_neighbors = self.get_neighbors(context, neighbor_physical_host)

        neighbors = []
        for neighbor in physical_neighbors:
            for host in host_list:
                if host['host'] == neighbor.neighbor:
                    neighbors.append(host)

        return neighbors

    def get_description(self):
        ""
