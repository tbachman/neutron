from neutron.plugins.cisco.l3.scheduler.filters import filters_base

__author__ = 'nalle'


class NoHostsFilter(filters_base.BaseHostFilter):

    run_filter_once_per_request = True

    def host_passes(self, host, resource):
        return False

    def get_description(self):
        ""