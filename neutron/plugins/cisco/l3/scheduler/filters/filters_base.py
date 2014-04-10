__author__ = 'nalle'

from neutron.plugins.cisco.l3.scheduler import loadables
from neutron.openstack.common.gettextutils import _
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class BaseFilter(object):
    """Skeleton"""
    def _filter_one(self, obj, filter_properties):
        return True

    def filter_all(self, filter_obj_list, filter_properties):

        for obj in filter_obj_list:
            if self._filter_one(obj, filter_properties):
                yield obj

    run_filter_once_per_request = False


class BaseFilterHandler(loadables.BaseLoader):

    def get_filtered_objects(self, resource, hosts, filters, index=0):
        filtered_hosts = list(hosts)
        LOG.debug(_("Starting with %d host(s)"), len(filtered_hosts))
        for filter_cls in filters:
            cls_name = filter_cls.__name__
            current_filter = filter_cls()

            hosts = current_filter.filter_all(filtered_hosts,
                                              resource)
            if hosts is None:
                LOG.debug(_("Filter %(cls_name)s says to stop filtering"),
                          {'cls_name': cls_name})
                return
            filtered_hosts = list(hosts)
            if not filtered_hosts:
                LOG.info(_("Filter %s returned 0 hosts"), cls_name)
                break
            LOG.debug(_("Filter %(cls_name)s returned "
                        "%(obj_len)d host(s)"),
                      {'cls_name': cls_name, 'obj_len': len(filtered_hosts)})
        return filtered_hosts


class BaseHostFilter(BaseFilter):
    """Skeleton for filters"""
    def _filter_one(self, obj, filter_properties):
        return self.host_passes(obj, filter_properties)

    def host_passes(self, host_state, filter_properties):

        raise NotImplementedError()


class HostFilterHandler(BaseFilterHandler):
    def __init__(self):
        super(HostFilterHandler, self).__init__(BaseHostFilter)


def all_filters():
    """Return a list of filter classes found in this directory.

    This method is used as the default for available scheduler filters
    and should return a list of all filter classes available.
    """
    return HostFilterHandler().get_all_classes()