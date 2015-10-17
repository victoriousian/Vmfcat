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
import sys
from Fields import *
from Groups import *
from Message import *
from Logger import Logger
#//////////////////////////////////////////////////////////

# =============================================================================
# Factory Class
#
# Description: Defines the fields required to build a VMF message and
#       creates those fields based on user-provides values via
#       the command line.
#
class Factory(object):

	def __init__(self, _logger = None):
		self.logger = _logger
		if (self.logger == None):
			self.logger = Logger(sys.stdout)

	def new_message(self, _args):
		"""
			Generates a new VMF messages based on the attributes
			given.
			
			This function generates a new VMF message by creating
			a Message object based on the parameters passed to this
			function. 
			
			A namespace created by argparse can be provided as dictionary
			as long as the name of the arguments and keys match.
			
			Args:
				_args: dictionary of parameters describing the settings
						of the VMF message. 
						
			Returns:
				A message object containing fields and groups
		"""	
		new_message = Message()
	
		# Iterate thru the parameters provided by the user to
		# create the message object.
		for field_name, field_value in _args.__dict__.items():
			# Validate the field given
			if (field_value != None and field_name in new_message.header.elements.keys()):
				# Get the field to create, and create a copy
				# from the dictionary.
				vmf_field_name = new_message.header.elements[field_name].name
				vmf_field_group = new_message.header.elements[field_name].grp_code
				new_field = new_message.header.elements[field_name]
				# Set the FPI/GPI of the field/group
				new_field.enable_and_set(field_value)
				new_message.header.elements[vmf_field_name] = new_field
				# Add the field to group
				vmf_group = new_message.header.elements[vmf_field_group]
				vmf_group.append_field(new_field)
				
		# Structure the fields and groups
		for (code, group) in new_message.header.groups().iteritems():
			parent_group = group.parent_group
			if (not parent_group is None):
				new_message.header.elements[parent_group].fields.append(group)
				
		# Sort the fields and groups according to index
		new_message.header.sort()
		return new_message
