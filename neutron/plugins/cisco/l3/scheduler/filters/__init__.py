__author__ = 'nalle'

from neutron import filters_base

class BaseHostFilter(filters_base.BaseFilter):
    """Skeleton for filters"""
    def _filter_one(self, host, resource, **kwargs):
        return self.host_passes(host, resource, **kwargs)

    def host_passes(self, host, resource, **kwargs):

        raise NotImplementedError()

    def get_description(self):

        raise NotImplementedError()


class HostFilterHandler(filters_base.BaseFilterHandler):
    def __init__(self):
        super(HostFilterHandler, self).__init__(BaseHostFilter)


def all_filters():

    return HostFilterHandler().get_all_classes()