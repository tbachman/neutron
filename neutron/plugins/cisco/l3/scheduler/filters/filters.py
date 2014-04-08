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

    def get_filtered_objects(self, filter_classes, objs,
            filter_properties, index=0):
        list_objs = list(objs)
        LOG.debug(_("Starting with %d host(s)"), len(list_objs))
        for filter_cls in filter_classes:
            cls_name = filter_cls.__name__
            filter = filter_cls()

            if filter.run_filter_for_index(index):
                objs = filter.filter_all(list_objs,
                                               filter_properties)
                if objs is None:
                    LOG.debug(_("Filter %(cls_name)s says to stop filtering"),
                          {'cls_name': cls_name})
                    return
                list_objs = list(objs)
                if not list_objs:
                    LOG.info(_("Filter %s returned 0 hosts"), cls_name)
                    break
                LOG.debug(_("Filter %(cls_name)s returned "
                            "%(obj_len)d host(s)"),
                          {'cls_name': cls_name, 'obj_len': len(list_objs)})
        return list_objs
