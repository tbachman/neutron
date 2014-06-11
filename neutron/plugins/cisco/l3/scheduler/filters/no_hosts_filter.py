from neutron.plugins.cisco.l3.scheduler.filters import filters_base

__author__ = 'nalle'


from neutron.plugins.cisco.l3.scheduler import filters


class NoHostsFilter(filters.BaseHostFilter):

    def host_passes(self, host, resource, **kwargs):
        return False

    def get_description(self):
        ""