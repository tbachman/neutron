__author__ = 'nalle'

import inspect
import os
import sys

from neutron.openstack.common import importutils

class BaseLoader(object):
    def __init__(self, loadable_cls_type):
        mod = sys.modules[self.__class__.__module__]
        self.path = os.path.abspath(mod.__path__[0])
        self.package = mod.__package__
        self.loadable_cls_type = loadable_cls_type

    def get_all_classes(self):
        classes = []
        for dirpath, dirnames, filenames in os.walk(self.path):
            relpath = os.path.relpath(dirpath, self.path)
            if relpath == '.':
                relpkg = ''
            else:
                relpkg = '.%s' % '.'.join(relpath.split(os.sep))
            for fname in filenames:
                root, ext = os.path.splitext(fname)
                if ext != '.py' or root == '__init__':
                    continue
                module_name = "%s%s.%s" % (self.package, relpkg, root)
                mod_classes = self._get_classes_from_module(module_name)
                classes.extend(mod_classes)
        return classes

    def get_matching_classes(self, loadable_class_names):
        """Get loadable classes from a list of names.  Each name can be
        a full module path or the full path to a method that returns
        classes to use.  The latter behavior is useful to specify a method
        that returns a list of classes to use in a default case.
        """
        classes = []
        for cls_name in loadable_class_names:
            obj = importutils.import_class(cls_name)
            if self._is_correct_class(obj):
                classes.append(obj)
            elif inspect.isfunction(obj):
                # Get list of classes from a function
                for cls in obj():
                    classes.append(cls)
            else:
                error_str = 'Not a class of the correct type'
               # raise exception.ClassNotFound(class_name=cls_name,
                                             # exception=error_str)
        return classes

