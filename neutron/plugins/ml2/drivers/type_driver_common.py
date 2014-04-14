from neutron.api.v2 import attributes
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import providernet as provider
from neutron.plugins.ml2 import driver_api as api

class TypeDriverMixin(object):
    def _process_provider_segment(self, segment):
        network_type = segment.get(provider.NETWORK_TYPE)
        physical_network = segment.get(provider.PHYSICAL_NETWORK)
        segmentation_id = segment.get(provider.SEGMENTATION_ID)

        if attributes.is_attr_set(network_type):
            segment = {api.NETWORK_TYPE: network_type,
                       api.PHYSICAL_NETWORK: physical_network,
                       api.SEGMENTATION_ID: segmentation_id}
            self.validate_provider_segment(segment)
            return segment

        msg = _("network_type required")
        raise exc.InvalidInput(error_message=msg)

    def _process_provider_create(self, network):
        segments = []

        if any(attributes.is_attr_set(network.get(f))
               for f in (provider.NETWORK_TYPE, provider.PHYSICAL_NETWORK,
                         provider.SEGMENTATION_ID)):
            # Verify that multiprovider and provider attributes are not set
            # at the same time.
            if attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
                raise mpnet.SegmentsSetInConjunctionWithProviders()

            network_type = network.get(provider.NETWORK_TYPE)
            physical_network = network.get(provider.PHYSICAL_NETWORK)
            segmentation_id = network.get(provider.SEGMENTATION_ID)
            segments = [{provider.NETWORK_TYPE: network_type,
                         provider.PHYSICAL_NETWORK: physical_network,
                         provider.SEGMENTATION_ID: segmentation_id}]
        elif attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
            segments = network[mpnet.SEGMENTS]
        else:
            return

        return [self._process_provider_segment(s) for s in segments]
