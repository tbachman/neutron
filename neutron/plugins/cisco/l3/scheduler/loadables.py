__author__ = 'nalle'

import os
import sys

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

