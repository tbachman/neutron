__author__ = 'nalle'

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron import manager



class HelloWorld(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        """Returns Extended Resource Name."""
        return "Hello World"

    @classmethod
    def get_alias(cls):
        """Returns Extended Resource Alias."""
        return "helloworld"

    @classmethod
    def get_description(cls):
        """Returns Extended Resource Description."""
        return "Outputs Hello World"

    @classmethod
    def get_namespace(cls):
        pass

    @classmethod
    def get_updated(cls):
        """Returns Extended Resource Update Time."""
        return "2014-03-25"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resources."""
        resource_name = "helloworld"
        collection_name = resource_name + "s"
        plugin = manager.NeutronManager.get_plugin()
        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin)
        return [extensions.ResourceExtension(collection_name,
                                             controller)]
