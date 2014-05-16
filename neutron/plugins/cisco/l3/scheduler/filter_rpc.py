__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler.filter_scheduler import FilterScheduler


class FilterSchedulerCallback(object):

    def neutron_filter_scheduler(self, context, **kwargs):

        instance = kwargs.pop('instance')
        hosts = kwargs.pop('hosts')
        chain_name = kwargs.pop('chain_name')
        weight_functions = kwargs.pop('weight_functions')
        ns = FilterScheduler()

        weighted_hosts = ns.schedule_instance(context, instance, hosts, chain_name, weight_functions, True,
                                                           **kwargs)

        return weighted_hosts