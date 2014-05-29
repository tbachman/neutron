__author__ = 'nalle'


import sqlalchemy as sa

from neutron.db import model_base
from neutron.db import models_v2


class FilterChain(model_base.BASEV2, models_v2.HasId):

    __tablename__ = 'filterchain'

    filter_name = sa.Column(sa.String(255), primary_key=True)
    filter_list = sa.Column(sa.String(1023))


class Neighbor(model_base.BASEV2, models_v2.HasId):

    __tablename__ = 'neighbors'

    physical_host = sa.Column(sa.TEXT, nullable=False)
    neighbor = sa.Column(sa.TEXT, nullable=False)