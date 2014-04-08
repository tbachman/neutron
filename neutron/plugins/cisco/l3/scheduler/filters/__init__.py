
__author__ = 'nalle'


"""
Scheduler host filters
"""

from neutron.plugins.cisco.l3.scheduler.filters import filters

class BaseHostFilter(filters.BaseFilter):
    """Skeleton for filters"""
    def _filter_one(self, obj, filter_properties):
        return self.host_passes(obj, filter_properties)

    def host_passes(self, host_state, filter_properties):

        raise NotImplementedError()


class HostFilterHandler(filters.BaseFilterHandler):
    def __init__(self):
        super(HostFilterHandler, self).__init__(BaseHostFilter)

def all_filters():
    """Return a list of filter classes found in this directory.

    This method is used as the default for available scheduler filters
    and should return a list of all filter classes available.
    """
    return HostFilterHandler().get_all_classes()
