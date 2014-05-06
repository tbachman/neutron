__author__ = 'nalle'


import sqlalchemy as sa

from neutron.db import model_base
from neutron.db import models_v2


class FilterChain(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):

    __tablename__ = 'filterchain'

    filter_name = sa.Column(sa.String(255))
    filter_list = sa.Column(sa.String(1023))

