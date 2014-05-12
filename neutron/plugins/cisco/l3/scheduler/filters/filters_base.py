__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler import loadables
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class BaseFilter(object):
    """Skeleton"""
    def _filter_one(self, host, resource, **kwargs):
        return True

    def filter_all(self, host_list, resource, **kwargs):

        for host in host_list:
            if self._filter_one(host, resource, **kwargs):
                yield host

    run_filter_once_per_request = False


class BaseFilterHandler(loadables.BaseLoader):

    def get_filtered_objects(self, resource, hosts, filters, **kwargs):
        filtered_hosts = list(hosts)
        for filter_cls in filters:
            current_filter = filter_cls()

            hosts = current_filter.filter_all(filtered_hosts,
                                              resource, **kwargs)
            if hosts is None:
                return
            filtered_hosts = list(hosts)
            if not filtered_hosts:
                break
        return filtered_hosts


class BaseHostFilter(BaseFilter):
    """Skeleton for filters"""
    def _filter_one(self, host, resource, **kwargs):
        return self.host_passes(host, resource, **kwargs)

    def host_passes(self, host, resource, **kwargs):

        raise NotImplementedError()

    def get_description(self):

        raise NotImplementedError()


class HostFilterHandler(BaseFilterHandler):
    def __init__(self):
        super(HostFilterHandler, self).__init__(BaseHostFilter)


def all_filters():

    return HostFilterHandler().get_all_classes()