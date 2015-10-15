#!/usr/bin/env python
#
# Copyright (C) 2015 Jonathan Racicot
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http:#www.gnu.org/licenses/>.
#
# You are free to use and modify this code for your own software 
# as long as you retain information about the original author
# in your code as shown below.
#
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>
#
__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

#//////////////////////////////////////////////////////////
# Imports Statements
from enum import Enum
from bitstring import BitArray
#//////////////////////////////////////////////////////////

#//////////////////////////////////////////////////////////
# Global Variables
ABSENT  = 0x0
PRESENT = 0x1

DEFAULT_FPI = ABSENT
DEFAULT_FRI = 0
DEFAULT_GPI = ABSENT
DEFAULT_GRI = 0

CODE_GRP_HEADER     = "header"
CODE_GRP_ORIGIN_ADDR    = "G1"
CODE_GRP_RCPT_ADDR  = "G2"
CODE_GRP_INFO_ADDR  = "G3"
CODE_GRP_MSG_HAND   = "R3"
CODE_GRP_VMF_MSG_IDENT  = "G9"
CODE_GRP_ORIGIN_DTG = "G10"
CODE_GRP_PERISH_DTG = "G11"
CODE_GRP_ACK        = "G12"
CODE_GRP_RESPONSE   = "G13"
CODE_GRP_REF        = "G14"
CODE_GRP_MSG_SECURITY   = "G20"
CODE_GRP_KEYMAT     = "G21"
CODE_GRP_CRYPTO_INIT    = "G22"
CODE_GRP_KEY_TOKEN  = "G23"
CODE_GRP_AUTH_A     = "G24"
CODE_GRP_AUTH_B     = "G25"
CODE_GRP_SEC_PAD    = "G26"
#//////////////////////////////////////////////////////////

# =============================================================================
# Group Class
#
# Description:
#   Class to represent sets of fields with similar functions.
#
class Group(object):
    is_root = False
    is_repeatable = False
    max_repeat = 1
    name = ""
    parent_group = None
    index = 0

    def __init__(self, _name, _is_repeatable=False, _isroot=False, _parent=None, _max_repeat=1, _index=0):
        self.name = _name
        self.is_root = _isroot
        self.is_repeatable = _is_repeatable
        self.max_repeat = _max_repeat
        self.parent_group = _parent
        self.index = _index
        self.fields = []#*(6+15*ENABLE_FUTURE_GRP)
        self.gpi = DEFAULT_FPI
        self.gri = DEFAULT_GRI

    def __repr__(self):
        return "{:d}:{:s}".format(self.index, self.name)

    def __cmp__(self, _field):
        if (isinstance(_field, field)):
            return self.index.__cmp__(_field.index)
        elif (isinstance(_field, group)):
            return self.index.__cmp__(_field.index)
        else:
            raise Exception("Provided comparision item must be an integer.")

    def enable(self):
        self.gpi = PRESENT

    def set_gri(self, _value):
        self.gri = _value

    def append_field(self, _field):
        #TODO toggle GPI if field is indicator or FPI ==- present
        #doesn't work...
        if (_field.fpi == PRESENT):
            self.gpi = PRESENT
        self.fields.append(_field)

    def get_bit_array(self):
        b = BitArray()
        b.append("{:#03b}".format(self.gpi))
        if (self.gpi == ABSENT):
            return b
        if (self.is_repeatable):
            b.append("{:#03b}".format(self.gri))
        for f in self.fields:
            fbits = f.get_bit_array()
            b.append(fbits)
        return b


