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
# Global constants
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

class HeaderElement(object):

	def __init__(self, _name, _repeatable=False, _max_repeat=0, _index=0):
		
		self.pi	= ABSENT					# Presence indicator
		self.ri = ABSENT					# Recurrence indicator
		self.name = _name					# Name of the element
		self.is_repeatable = _repeatable	# Is the element repeatable?
		self.max_repeat = _max_repeat		# If so, maximum times it 
											# can repeated
		self.index = _index					# Index/order of the element
											# in the header/group
		
	def __repr__(self):
		return "<HeaderElement '{:s}'>".format(self.name)
		
	def __str__(self):
		return self.name
		
	def __cmp__(self, _object):
		pass