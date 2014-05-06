__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler.filter_scheduler import FilterScheduler


class FilterSchedulerCallback(object):

    def neutron_filter_scheduler(self, context, **kwargs):

        resource = kwargs.pop('resource')
        hosts = kwargs.pop('hosts')
        chain_name = kwargs.pop('chain_name')
        weight_functions = kwargs.pop('weight_functions')

        weighted_hosts = FilterScheduler.schedule_instance(context, resource, hosts, chain_name, weight_functions, True,
                                                           **kwargs)

        return weighted_hosts