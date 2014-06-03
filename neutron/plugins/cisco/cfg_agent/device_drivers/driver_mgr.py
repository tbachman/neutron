# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Hareesh Puthalath, Cisco Systems, Inc.

from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.cfg_agent import cfg_exceptions

LOG = logging.getLogger(__name__)


class DeviceDriverManager(object):
    """This class acts as a manager for device drivers.

    The device driver manager  maintains the relationship between the
    different neutron logical resource (eg: routers, firewalls, vpns etc.) and
    where they are hosted. For configuring these logical resources in a
    hosting device, a set of device driver objects are used. Device drivers
    encapsulate the necessary configuration information to configure a
    logical resource (eg: routers, firewalls, vpns etc.) on a
    hosting device (eg: CSR1kv).

    The device driver class loads one driver object per hosting device.
    The loaded drivers are cached in memory, so when a request is made to
    get a driver object for the same hosting device and service,
    the driver object is reused.

    This class is used by the service helper classes.
    """

    def __init__(self):
        self._drivers = {}
        self.router_id_hosting_devices = {}

    #ToDo(Hareesh): Change the signature of this function, as it is closely
    # tied to routers now.
    def get_driver(self, router_info):
        router_id = router_info.router_id
        hosting_device = self.router_id_hosting_devices.get(router_id, None)
        if hosting_device is not None:
            driver = self._drivers.get(hosting_device['id'], None)
            if driver is None:
                driver = self._set_driver(router_info)
        else:
            driver = self._set_driver(router_info)
        return driver

    def _set_driver(self, router_info):
        try:
            _driver = None
            router_id = router_info.router_id
            router = router_info.router

            hosting_device = router['hosting_device']
            _hd_id = hosting_device['id']
            driver_class = router['router_type']['cfg_agent_driver']

            try:
                _driver = importutils.import_object(
                    driver_class,
                    **hosting_device)
            except ImportError:
                LOG.exception(_("Error loading cfg agent driver for routing "
                                "service %(driver)s for hosting device "
                                "template  %(t_name)s(%(t_id)s)"),
                              {'driver': driver_class,
                               't_name': hosting_device['name'],
                               't_id': _hd_id})
                raise cfg_exceptions.DriverNotFound(driver=driver_class)
            self.router_id_hosting_devices[router_id] = hosting_device
            self._drivers[_hd_id] = _driver
        except (AttributeError, KeyError) as e:
            LOG.error(_("Cannot set driver for router. Reason: %s"), e)
        return _driver

    def remove_driver(self, router_id):
        del self.router_id_hosting_devices[router_id]
        for hd_id in self._drivers.keys():
            if hd_id not in self.router_id_hosting_devices.values():
                del self._drivers[hd_id]

    def pop(self, hd_id):
        self._drivers.pop(hd_id, None)

