__author__ = 'nalle'


from neutron.plugins.cisco.l3.scheduler.filters import filters


class AllHostsFilter(filters.BaseHostFilter):

    run_filter_once_per_request = True

    def host_passes(self, host_state, filter_properties):
        return True
