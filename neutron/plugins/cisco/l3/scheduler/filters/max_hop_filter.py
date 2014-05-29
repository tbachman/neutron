__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler import filters
from neutron.plugins.cisco.l3.scheduler.filters.neighbors_filter import Neighbor
from neutron.db import db_base_plugin_v2 as base_db
import copy


class MaxHopFilter(filters.BaseHostFilter, base_db.CommonDbMixin):

    def get_neighbors_list(self, context):
        neighbors = self._get_collection(context, Neighbor,
                                         self._make_neighbor_dict)

        return neighbors

    def _make_neighbor_dict(self, neighbor, fields=None):
        res = {neighbor['physical_host']: neighbor['neighbor']}
        return self._fields(res, fields)

    def constructNeighDict(self, context):

        db_dicts = self.get_neighbors_list(context)
        neighbor_dict = {}
        for d in db_dicts:
            for k, v in d.iteritems():
                l=neighbor_dict.setdefault(k,[])
                if v not in l:
                    l.append(v)
        return neighbor_dict

    def getHopCount(self, dictNeigh, node1, node2):

        hop_count = 0
        listNodes = copy.deepcopy(dictNeigh[node1])
        listNodeParsed = copy.deepcopy(dictNeigh[node1])
        listNodeParsed.append(node1)
        listPrevNodes = copy.deepcopy(dictNeigh[node1])

        for i in range (0, len(dictNeigh.keys())):

            if node2 in listNodes:
                hop_count = i +1
                return hop_count

            else:
                for node in listPrevNodes:
                    listNodes = copy.deepcopy(list(set(listNodes) | set(dictNeigh[node])))

                listNodes = copy.deepcopy(list(set(listNodes) - set(listNodeParsed)))
                listNodeParsed = copy.deepcopy(list(set(listNodeParsed) | set(listNodes)))
                listPrevNodes = copy.deepcopy(listNodes)

        return 0

    def getNeighborWithinHop(self, dic, vm, count=0):
        li = dic.keys()
        nearby_neighbor = []
        for i in range(len(li)-1):
            if self.getHopCount(dic, vm, (li[i+1])) <= count:
                nearby_neighbor.append(li[i+1])
        return nearby_neighbor

    def filter_all(self, context, host_list, resource, **kwargs):
        neighbor_physical_host = kwargs.get('neighbor_physical_host')
        no_hops = kwargs.get('no_hops')

        neighbor_dict = self.constructNeighDict(context)

        within_hop_neigh = self.getNeighborWithinHop(neighbor_dict, neighbor_physical_host, no_hops)

        neighbors = []
        for whn in within_hop_neigh:
            for host in host_list:
                if host['host'] == whn:
                    neighbors.append(host)
        return neighbors


    def get_description(self):
        ""
