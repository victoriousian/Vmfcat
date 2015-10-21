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
from bitstring import *
#//////////////////////////////////////////////////////////

# =============================================================================
# Factory Class
#
# Description: Defines the fields required to build a VMF message and
#       creates those fields based on user-provides values via
#       the command line.
#
class Factory(object):

	elements_sorted_pos = [
		CODE_FLD_VERSION,
		CODE_FLD_COMPRESS,
		CODE_GRP_ORIGIN_ADDR
	]

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

	def read_message2(self, _bitstream):
		#Check if bitstring is valid
		if (_bitstream != None):
			#Creates a new VMF message object
			new_message = Message()

			# Iterate thru the parameters provided by the user to
			# create the message object.
			for (field_name, field_obj) in new_message.header.fields().iteritems():
				vmf_field_group = field_obj.grp_code
				vmf_group_obj = new_message.header.elements[vmf_field_group]
				vmf_group_obj.append_field(field_obj)	
				
			# Structure the fields and groups
			for (code, group) in new_message.header.groups().iteritems():
				parent_group = group.parent_group
				if (not parent_group is None):
					new_message.header.elements[parent_group].fields.append(group)

			new_message.header.sort()
			root_grp = new_message.header.elements[CODE_GRP_HEADER]
			self.logger.print_debug("Creating message from stream:\n{:s}".format(_bitstream.hex))
			self.read_message3(root_grp, _bitstream)

	def read_message3(self, _element, _bitstream):
		#TODO: Manage repeatable fields
		if (isinstance(_element, Field)):
			# If field has a FPI bit indicator, read
			# the next bit as the FPI
			if (not _element.is_indicator):
				_element.pi = _bitstream.read('uint:1')
				# If the field is repeatable and is present
				# read the next bit as the FRI
				if (_element.pi == PRESENT):
					if (_element.is_repeatable):
						_element.ri = _bitstream.read('uint:1')
					# Finally, read the value
					_element.value = _bitstream.read(_element.size)
			# If this field has not FPI/FRI, e.g. flags, version,
			# simply read the value.
			else:
				#TODO: Manage strings /448 or TERMINATOR
				_element.value = _bitstream.read('uint:{:d}'.format(_element.size))

			self.logger.print_debug("Processing field '{:s}': FPI={:d}, FRI={:d}, value={}".format(
				_element.name, _element.pi, _element.ri, _element.value))
		# If the element is a group, only consider the GPI/GRI and
		# if present, start processing all contained fields and subgroups.
		elif (isinstance(_element, Group)):
			self.logger.print_debug("Processing group '{:s}'...".format(_element.name))
			if (not _element.is_root):
				# Read the GPI
				_element.pi = _bitstream.read('uint:1')
				# If the field is repeatable and is present
				# read the next bit as the GRI
				if (_element.pi == PRESENT and 
					_element.is_repeatable):
					_element.ri = _bitstream.read('uint:1')
			# For all fields/groups in the header or if the current group
			# is present, process all sub elements
			if (_element.is_root or
				_element.pi == PRESENT):
				for sub_elem in _element.fields:
					self.read_message3(sub_elem, _bitstream)			
		else:
			raise Exception("Unknown/Unsupported object type: {:s}".format(type(_element)))

	def read_message(self, _bitstream):
		"""
		In Construction
		"""
		#Check if bitstring is valid
		if (_bitstream):
			self.logger.print_debug("Reading new VMF message...")
			#Creates a new VMF message object
			new_message = Message()
			
			#We first check the version of the VMF message
			field_version = new_message.header.elements[CODE_FLD_VERSION]
			field_size = field_version.size
			version_value = _bitstream.read('uint:{:d}'.format(field_size))
			# Depending on the version, we will need to consider
			# Future fields added in version D/CHANGE
			#TODO: enable future fields				
			if (version_value >= version.std47001d_change):
				self.logger.print_warning("Future fields is not supported at the moment.")				
			field_version.value = version_value
			self.logger.print_info("VMF Message version 0x{:x} received.".format(version_value))

			read_stream = True
			
			try:
				elem_index = 1
				elem_parent = CODE_GRP_HEADER

				while (read_stream):
					elem_name = self.elements_sorted_pos[elem_index]
					elem_obj = new_message.header.elements[elem_name]
					elem_is_field = True
					if (isinstance(elem_obj, Group)):
						elem_is_field = False
					field_value = 0

					#TODO: Manage repeatable fields.

					# If field has a FPI/GPI bit indicator, read
					# the next bit as the FPI
					if not elem_is_field or not elem_obj.is_indicator:
						elem_obj.pi = _bitstream.read('uint:1')
						# If the field is repeatable and is present
						# read the next bit as the FRI/GRI
						if (elem_obj.pi == PRESENT and 
							elem_obj.is_repeatable):
							elem_obj.ri = _bitstream.read('uint:1')
						# Otherwise, if the field is present, but not
						# repeatable, just read the value
						if (elem_obj.pi == PRESENT):
							if (elem_is_field):
								elem_obj.value = _bitstream.read(elem_obj.size)
							else:
								elem_parent = elem_name
							elem_obj.grp_code = elem_parent
					else:
						if (elem_is_field):
							elem_obj.value = _bitstream.read(elem_obj.size)
						else:
							elem_parent = elem_name
						elem_obj.grp_code = elem_parent
					if (elem_obj.pi == PRESENT):
						self.logger.print_debug("Field/Group '{:s}' in group '{:s}' found with value {	}'.".format(elem_name, elem_parent, elem_obj.value))
					else:
						self.logger.print_debug("Field/Group '{:s}' not found.".format(elem_name))
					elem_index += 1
			except ReadError as re:
				read_stream = False
			
		else:
			raise Exception("Null bitstring received.")
