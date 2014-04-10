__author__ = 'nalle'

from oslo.config import cfg

from neutron.openstack.common.gettextutils import _
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.l3.scheduler.filters import filters_base as filters

LOG = logging.getLogger(__name__)

disk_allocation_ratio_opt = cfg.FloatOpt("disk_allocation_ratio", default=1.0,
                                         help="Virtual disk to physical disk allocation ratio")

CONF = cfg.CONF
CONF.register_opt(disk_allocation_ratio_opt)


class DiskFilter(filters.BaseHostFilter):

    def host_passes(self, host_state, resource):
        """Filter based on disk usage."""
        instance_type = resource.get('instance_type')
        requested_disk = (1024 * (instance_type['root_gb'] +
                                  instance_type['ephemeral_gb']) +
                          instance_type['swap'])

        free_disk_mb = host_state.free_disk_mb
        total_usable_disk_mb = host_state.total_usable_disk_gb * 1024

        disk_mb_limit = total_usable_disk_mb * CONF.disk_allocation_ratio
        used_disk_mb = total_usable_disk_mb - free_disk_mb
        usable_disk_mb = disk_mb_limit - used_disk_mb

        if not usable_disk_mb >= requested_disk:
            LOG.debug(_("%(host_state)s does not have %(requested_disk)s MB "
                        "usable disk, it only has %(usable_disk_mb)s MB usable "
                        "disk."), {'host_state': host_state,
                                   'requested_disk': requested_disk,
                                   'usable_disk_mb': usable_disk_mb})
            return False

        disk_gb_limit = disk_mb_limit / 1024
        host_state.limits['disk_gb'] = disk_gb_limit
        return True
