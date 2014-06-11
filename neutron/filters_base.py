__author__ = 'nalle'

from neutron import loadables
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class BaseFilter(object):
    """Skeleton"""
    def _filter_one(self, host, resource, **kwargs):
        return True

    def filter_all(self, context, host_list, resource, **kwargs):

        for host in host_list:
            if self._filter_one(host, resource, **kwargs):
                yield host


class BaseFilterHandler(loadables.BaseLoader):

    def get_filtered_objects(self, context, resource, hosts, filters, **kwargs):
        filtered_hosts = list(hosts)
        for filter_cls in filters:
            current_filter = filter_cls()

            hosts = current_filter.filter_all(context, filtered_hosts,
                                              resource, **kwargs)
            if hosts is None:
                return
            filtered_hosts = list(hosts)
            if not filtered_hosts:
                break
        return filtered_hosts
