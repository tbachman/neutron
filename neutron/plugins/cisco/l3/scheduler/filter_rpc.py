__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler.filter_scheduler import FilterScheduler


class FilterSchedulerCallback(object):

    def neutron_filter_scheduler(self, context, **kwargs):

        resource = kwargs.get('resource.id')
        hosts = kwargs.get('hosts')
        chain_id = kwargs.get('chain_id')
        weight_functions = kwargs.get('weight_functions')

        weighted_hosts = FilterScheduler.schedule_instance(context, resource, hosts, chain_id, weight_functions)

        return weighted_hosts