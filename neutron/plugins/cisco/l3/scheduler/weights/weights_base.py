
import abc

import six

from neutron.plugins.cisco.l3.scheduler import loadables

from oslo.config import cfg

CONF = cfg.CONF

def normalize(weight_list, minval=None, maxval=None):

    if not weight_list:
        return ()

    if maxval is None:
        maxval = max(weight_list)

    if minval is None:
        minval = min(weight_list)

    maxval = float(maxval)
    minval = float(minval)

    if minval == maxval:
        return [0] * len(weight_list)

    range_ = maxval - minval
    return ((i - minval) / range_ for i in weight_list)


class WeighedObject(object):

    def __init__(self, obj, weight):
        self.obj = obj
        self.weight = weight

    def __repr__(self):
        return "<WeighedObject '%s': %s>" % (self.obj, self.weight)


@six.add_metaclass(abc.ABCMeta)
class BaseWeigher(object):

    minval = None
    maxval = None

    def weight_multiplier(self):

        return 1.0

    @abc.abstractmethod
    def _weigh_object(self, obj):
        """Weigh an specific object."""

    def weigh_objects(self, weighed_obj_list):

        weights = []
        for obj in weighed_obj_list:
            weight = self._weigh_object(obj.obj)

            # Record the min and max values if they are None. If they anything
            # but none we assume that the weigher has set them
            if self.minval is None:
                self.minval = weight
            if self.maxval is None:
                self.maxval = weight

            if weight < self.minval:
                self.minval = weight
            elif weight > self.maxval:
                self.maxval = weight

            weights.append(weight)

        return weights


class BaseWeightHandler(loadables.BaseLoader):
    object_class = WeighedObject

    def get_weighed_objects(self, hosts, weight_functions):
        """Return a sorted (descending), normalized list of WeighedObjects."""

        if not hosts:
            return []

        weighed_objs = [self.object_class(host, 0.0) for host in hosts]
        for weigher_cls in weight_functions:
            weigher = weigher_cls()
            weights = weigher.weigh_objects(weighed_objs)

            # Normalize the weights
            weights = normalize(weights,
                                minval=weigher.minval,
                                maxval=weigher.maxval)

            for i, weight in enumerate(weights):
                obj = weighed_objs[i]
                obj.weight += weigher.weight_multiplier() * weight

        return sorted(weighed_objs, key=lambda x: x.weight, reverse=True)


class WeighedHost(WeighedObject):
    def to_dict(self):
        x = dict(weight=self.weight)
        x['host'] = self.obj.host
        return x

    def __repr__(self):
        return "WeighedHost [host: %s, weight: %s]" % (
                self.obj.host, self.weight)


class BaseHostWeigher(BaseWeigher):
    """Base class for host weights."""
    pass


class HostWeightHandler(BaseWeightHandler):
    object_class = WeighedHost

    def __init__(self):
        super(HostWeightHandler, self).__init__(BaseHostWeigher)


def all_weighers():
    """Return a list of weight plugin classes found in this directory."""
    return HostWeightHandler().get_all_classes()