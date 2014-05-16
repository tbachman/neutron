from neutron.plugins.cisco.l3.scheduler.filters import filters_base

__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler import filters

class AllHostsFilter(filters.BaseHostFilter):

    run_filter_once_per_request = True

    def host_passes(self, host, resource, **kwargs):
        return True

    def get_description(self):
        ""