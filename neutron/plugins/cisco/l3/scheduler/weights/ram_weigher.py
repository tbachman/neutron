from oslo.config import cfg
from neutron.plugins.cisco.l3.scheduler import weights

ram_weight_opts = [
        cfg.FloatOpt('ram_weight_multiplier',
                     default=1.0,
                     help='Multiplier used for weighing ram.  Negative '
                          'numbers mean to stack vs spread.'),
]

CONF = cfg.CONF
CONF.register_opts(ram_weight_opts)


class RAMWeigher(weights.BaseHostWeigher):
    minval = 0

    def weight_multiplier(self):
        return CONF.ram_weight_multiplier

    def _weigh_object(self, host):
        return host.free_ram_mb
