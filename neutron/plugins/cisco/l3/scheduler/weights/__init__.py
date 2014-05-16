__author__ = 'nalle'

from neutron import weights_base


class WeighedHost(weights_base.WeighedObject):
    def to_dict(self):
        x = dict(weight=self.weight)
        x['host'] = self.obj.host
        return x

    def __repr__(self):
        return "WeighedHost [host: %s, weight: %s]" % (
                self.obj.host, self.weight)


class BaseHostWeigher(weights_base.BaseWeigher):
    """Base class for host weights."""
    pass


class HostWeightHandler(weights_base.BaseWeightHandler):
    object_class = WeighedHost

    def __init__(self):
        super(HostWeightHandler, self).__init__(BaseHostWeigher)


def all_weighers():
    """Return a list of weight plugin classes found in this directory."""
    return HostWeightHandler().get_all_classes()