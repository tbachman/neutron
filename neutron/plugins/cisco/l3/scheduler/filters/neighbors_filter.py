__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler import filters
from neutron.plugins.cisco.db.scheduler.filter_model import Neighbor
from neutron.db import db_base_plugin_v2 as base_db

class NeighborsFilter(filters.BaseHostFilter, base_db.CommonDbMixin):

    def get_neighbors(self, context, physical_host):
        query = self._model_query(context, Neighbor)
        neighbors = query.filter(Neighbor.physical_host == physical_host).all()

        return neighbors

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
