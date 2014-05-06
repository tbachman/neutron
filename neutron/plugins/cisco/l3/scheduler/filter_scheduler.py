__author__ = 'nalle'

'''Does not iterate over multiple instances in a request.
Assumes that the plugins forwards a list of hosts'''

from oslo.config import cfg
from neutron.common import exceptions
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.l3.scheduler.filters import filters_base as filters
from neutron.plugins.cisco.l3.scheduler.weights import weights_base
from neutron.plugins.cisco.l3.db.filter_chain_db import FilterChainManager as Fc

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

filter_scheduler_opts = [
    cfg.MultiStrOpt('scheduler_available_filters',
                    default=['neutron.plugins.cisco.l3.scheduler.filters.filters_base.all_filters'],
                    help='Filter classes available to the scheduler'),

    cfg.ListOpt('scheduler_weight_classes',
                default=['neutron.plugins.cisco.l3.scheduler.weights.weights_base.all_weighers'],
                help='Which weight class names to use for weighing hosts')
]

CONF.register_opts(filter_scheduler_opts)


class FilterScheduler(object):
    def __init__(self):

        self.filter_handler = filters.HostFilterHandler()
        self.filter_classes = self.filter_handler.get_matching_classes(
            CONF.scheduler_available_filters)

        self.weight_handler = weights_base.HostWeightHandler()
        self.weight_classes = self.weight_handler.get_matching_classes(
            CONF.weight_classes)
        self.chain_dic = {}

    def schedule_instance(self, context, resource, hosts, chain_name, weight_functions, rpc, **kwargs):

        #Check cache, if not, check db.

        filter_chain = self.chain_dic.get(chain_name)

        if filter_chain is None:
            filter_chain = Fc.get_filter_chain(context, chain_name)
            if filter_chain is None:
                filter_chain = Fc.create_filter_chain(context, chain_name, ['AllHostsFilter'])
                self.chain_dic[chain_name] = self._choose_host_filters(filter_chain)
                filter_chain = self.chain_dic.get(chain_name)
                if filter_chain is None:
                    raise exceptions.NoFilterChainFound()

        try:
            return self._schedule(resource,
                                  hosts, weight_functions, filter_chain, rpc, **kwargs)
        except:
            raise exceptions.NoValidHost(reason="")

    def _schedule(self, resource, hosts,
                  weight_functions, filter_chain=None, rpc=False, **kwargs):

        filtered_hosts = self.get_filtered_hosts(resource, hosts,
                                                 filter_chain, **kwargs)
        if not filtered_hosts:
            raise exceptions.NoValidHost(reason="")

        if rpc:
            return filtered_hosts

        weighted_hosts = self.get_weighed_hosts(filtered_hosts,
                                                weight_functions, **kwargs)

        return weighted_hosts

    def get_filtered_hosts(self, resource, hosts, filter_chain, **kwargs):
        """Filter hosts and return only ones passing all filters."""
        return self.filter_handler.get_filtered_objects(resource, hosts, filter_chain, **kwargs)

    def get_weighed_hosts(self, hosts, weight_functions, **kwargs):
        """Weigh the hosts."""

        if weight_functions is None:
            weight_functions = self.weight_classes

        return self.weight_handler.get_weighed_objects(hosts, weight_functions, **kwargs)

    def _choose_host_filters(self, filter_cls_names):
        """Remove any bad filters in the filter chain"""

        if filter_cls_names is None:
            filter_cls_names = CONF.scheduler_default_filters
        if not isinstance(filter_cls_names, (list, tuple)):
            filter_cls_names = [filter_cls_names]
        cls_map = dict((cls.__name__, cls) for cls in self.filter_classes)
        good_filters = []
        for filter_name in filter_cls_names:
            if filter_name not in cls_map:
                continue
            good_filters.append(cls_map[filter_name])

        return good_filters