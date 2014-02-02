# vim: tabstop=10 shiftwidth=4 softtabstop=4
#
# Copyright 2014, Paul Michali, Cisco Systems, Inc.
# All Rights Reserved.
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


class BitArray(object):

    def __init__(self, size):
        self.size = size
        self.data = bytearray((size + 7) // 8)

    def __setitem__(self, index, value):
        if index >= self.size:
            raise IndexError("Too large, must be less than %d" % self.size)
        byte, bit = divmod(index, 8)
        if value:
            self.data[byte] |= (1 << bit)
        else:
            self.data[byte] &= ~(1 << bit)

    def __getitem__(self, index):
        byte, bit = divmod(index, 8)
        if index >= self.size:
            raise IndexError("Too large, must be less than %d" % self.size)
        return (self.data[byte] >> bit) & 1

    def __len__(self):
        return self.size

if __name__ == '__main__':
    ba = BitArray(40)
    import sys
    print "Size is", sys.getsizeof(ba)
    print dir(ba)
    ba[0] = 1
    ba[11] = 1
    ba[15] = 1
    ba[18] = 1
    print list(ba)
    print ba.reserve()
    print ba.reserve()
    print ba.reserve()
    print list(ba)
    for i in range(35):
        print ba.reserve()
