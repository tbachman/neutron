__author__ = 'nalle'

'''Does not iterate over multiple instances in a request.
Assumes that the plugins forwards a list of hosts'''

from oslo.config import cfg
from neutron.common import exceptions
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.l3.scheduler import filters
from neutron.plugins.cisco.l3.scheduler import weights
from neutron.plugins.cisco.db.scheduler.filter_chain_db import FilterChainManager

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

filter_scheduler_opts = [
    cfg.MultiStrOpt('scheduler_available_filters',
                    default=['neutron.plugins.cisco.l3.scheduler.filters.all_filters'],
                    help='Filter classes available to the scheduler'),

    cfg.ListOpt('scheduler_weight_classes',
                default=['neutron.plugins.cisco.l3.scheduler.weights.all_weighers'],
                help='Which weight class names to use for weighing hosts')
]

CONF.register_opts(filter_scheduler_opts)

#TEST

class FilterScheduler(object):
    def __init__(self):

        self.filter_handler = filters.HostFilterHandler()
        self.filter_classes = self.filter_handler.get_matching_classes(
            CONF.scheduler_available_filters)

        self.weight_handler = weights.HostWeightHandler()
        self.weight_classes = self.weight_handler.get_matching_classes(
            CONF.scheduler_weight_classes)
        self.chain_dic = {}
        self.filter_db_handler = FilterChainManager()

    def schedule_instance(self, context, instance, hosts, chain_name, weight_functions, rpc, **kwargs):

        #Check cache, if not, check db.

        # HARD CODED FILTER CHAINS - IN THE FUTURE USE CLI COMMANDS TO CREATE, UPDATE, DELETE FILTER CHAINS

        filter_chain = self.chain_dic.get(chain_name)

        if filter_chain is None:
            filter_chain = self.filter_db_handler.get_filter_chain(context, chain_name)
            if filter_chain is None:
                if chain_name == 'all_filter':
                    filter_name_class = 'AllHostsFilter'
                elif chain_name == 'no_filter':
                    filter_name_class = 'NoHostsFilter'
                else:
                    raise exceptions.NoFilterChainFound()

                self.filter_db_handler.create_filter_chain(context, chain_name, [filter_name_class])
                filter_chain = self.filter_db_handler.get_filter_chain(context, chain_name)
            self.chain_dic[chain_name] = self._choose_host_filters(filter_chain)
            filter_chain = self.chain_dic.get(chain_name)
            if not filter_chain:
                raise exceptions.NoFilterChainFound()

        # END OF HARD CODE

        try:
            return self._schedule(instance,
                                  hosts, weight_functions, filter_chain, rpc, **kwargs)
        except:
            raise exceptions.NoValidHost(reason="")

    def _schedule(self, instance, hosts,
                  weight_functions, filter_chain=None, rpc=False, **kwargs):

        filtered_hosts = self.get_filtered_hosts(instance, hosts,
                                                 filter_chain, **kwargs)
        if not filtered_hosts:
            if rpc:
                return 'No valid host'
            raise exceptions.NoValidHost(reason="")

        if rpc:
            return filtered_hosts

        weighted_hosts = self.get_weighed_hosts(filtered_hosts,
                                                weight_functions, **kwargs)

        return weighted_hosts

    def get_filtered_hosts(self, instance, hosts, filter_chain, **kwargs):
        """Filter hosts and return only ones passing all filters."""
        return self.filter_handler.get_filtered_objects(instance, hosts, filter_chain, **kwargs)

    def get_weighed_hosts(self, hosts, weight_functions, **kwargs):
        """Weigh the hosts."""

        if weight_functions is None:
            weight_functions = self.weight_classes

        return self.weight_handler.get_weighed_objects(hosts, weight_functions, **kwargs)

    def _choose_host_filters(self, filter_cls_names):
        """Remove any bad filters in the filter chain"""

        if not isinstance(filter_cls_names, (list, tuple)):
            filter_cls_names = [filter_cls_names]
        cls_map = dict((cls.__name__, cls) for cls in self.filter_classes)
        good_filters = []
        for filter_name in filter_cls_names:
            if filter_name not in cls_map:
                continue
            good_filters.append(cls_map[filter_name])

        return good_filters