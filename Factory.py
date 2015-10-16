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
from Fields import *
from Groups import *

#//////////////////////////////////////////////////////////

MSG_SUCCESS = 0x0
MSG_ERROR   = 0x1
MSG_WARN    = 0x2
MSG_INFO    = 0x3
MSG_DEBUG    = 0x4

# =============================================================================
# Factory Class
#
# Description: Defines the fields required to build a VMF message and
#       creates those fields based on user-provides values via
#       the command line.
#
class Factory(object):

	vmf_fields = {
		"vmfversion"    : [Field(
						_name="Version",
						_size=4,
						_enumerator=version,
						_groupcode=CODE_GRP_HEADER,
						_indicator=True,
						_index=0)],
		"compress"      : [Field(
						_name="Data Compression",
						_size=2,
						_enumerator=data_compression,
						_groupcode=CODE_GRP_HEADER,
						_index=1)],
		"originator_urn"    : [Field(
						_name="Originator URN",
						_size=24, 
						_groupcode=CODE_GRP_ORIGIN_ADDR,
						_index=0)],
		"originator_unitname"   : [Field(
						_name="Originator Unit Name", 
						_size=448, 
						_groupcode=CODE_GRP_ORIGIN_ADDR,
						_index=0)],
		"rcpt_urns"     : [Field(
						_name="Recipient URN", 
						_size=24, 
						_groupcode=CODE_GRP_RCPT_ADDR,
						_index=0)],
		"rcpt_unitnames"    : [Field(
						_name="Recipient Unit Name", 
						_size=448, 
						_groupcode=CODE_GRP_RCPT_ADDR,
						_index=0)],
		"info_urns"     : [Field(
						_name="Information URN", 
						_size=24, 
						_groupcode=CODE_GRP_INFO_ADDR,
						_index=0)],
		"info_unitnames"    : [Field(
						_name="Information Unit Name", 
						_size=448, 
						_groupcode=CODE_GRP_INFO_ADDR,
						_index=0)],
		"umf"           : [Field(
						_name="UMF", 
						_size=4, 
						_enumerator=umf,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=0)],
		"messagevers"       : [Field(
						_name="Message Standard Version", 
						_size=4, 
						_groupcode=CODE_GRP_MSG_HAND,
						_index=1)],
		"fad"           : [Field(
						_name="FAD", 
						_size=4,
						_enumerator=fad_codes, 
						_groupcode=CODE_GRP_VMF_MSG_IDENT,
						_index=0)],
		"msgnumber"     : [Field(
						_name="Message Number",
						_size=7,
						_groupcode=CODE_GRP_VMF_MSG_IDENT,
						_index=1)],
		"msgsubtype"        : [Field(
						_name="Message Subtype",
						_size=7,
						_groupcode=CODE_GRP_VMF_MSG_IDENT,
						_index=2)],
		"filename"      : [Field(
						_name="File name",
						_size=448,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=3)],
		"msgsize"       : [Field(
						_name="Message Size",
						_size=20,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=4)],
		"opind"         : [Field(
						_name="Operation Indicator",
						_size=2,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=5)],
		"retransmission"    : [Field(
						_name="Retransmit Indicator",
						_size=1,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=6)],
		"msgprecedence"     : [Field(
						_name="Message Precedence Code",
						_size=3,
						_enumerator=precedence,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=7)],
		"classification"    : [Field(
						_name="Security Classification",
						_size=2,
						_enumerator=classification,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=8)],
		"releasemark"       : [Field(
						_name="Control/Release Marking",
						_size=9,
						_repeatable=True,
						_groupcode=CODE_GRP_MSG_HAND,
						_index=9)],
		"originatordtg"     : [dtg_field(
						_name="Originator DTG",
						_groupcode=CODE_GRP_ORIGIN_DTG,
						_index=10)],
		"perishdtg"     : [dtg_field(
						_name="Perishability DTG",
						_groupcode=CODE_GRP_PERISH_DTG,
						_extension=False,
						_index=11)],
		"ackmachine"    : [Field(
						_name="Machine Acknowledge",
						_size=1,
						_groupcode=CODE_GRP_ACK,
						_indicator=True,
						_index=1)],
		"ackop"         : [Field(
						_name="Operator Acknowledge",
						_size=1,
						_groupcode=CODE_GRP_ACK,
						_indicator=True,
						_index=2)],
		"reply"         : [Field(
						_name="Operator Reply Request",
						_size=1,
						_groupcode=CODE_GRP_ACK,
						_indicator=True,
						_index=3)],
		"ackdtg"        : [dtg_field(
						_name="DTG of Ack'd Msg.",
						_groupcode=CODE_GRP_RESPONSE,
						_index=12)],
		"rccode"        : [Field(
						_name="R/C",
						_size=3,
						_enumerator=rc_codes,
						_groupcode=CODE_GRP_RESPONSE,
						_indicator=True,
						_index=13)],
		"cantco"        : [Field(
						_name="Cantco Reason Code",
						_size=3,
						_enumerator=cantco_reasons,
						_groupcode=CODE_GRP_RESPONSE,
						_index=14)],
		"cantpro"       : [Field(
						_name="Cantpro Reason Code",
						_size=6,
						_enumerator=cantpro_reasons,
						_groupcode=CODE_GRP_RESPONSE,
						_index=15)],
		"replyamp"      : [Field(
						_name="Reply Amplification",
						_size=350,
						_groupcode=CODE_GRP_RESPONSE,
						_index=16)],
		"ref_urn"       : [Field(
						_name="Reference Message URN",
						_size=24,
						_groupcode=CODE_GRP_REF,
						_index=0)],
		"ref_unitname"      : [Field(
						_name="Reference Message Unit Name",
						_size=448,
						_groupcode=CODE_GRP_REF,
						_index=0)],
		"refdtg"        : [dtg_field(
						_name="Reference Message DTG",
						_groupcode=CODE_GRP_REF,
						_index=1)],
		"secparam"      : [Field(
						_name="Security Parameters",
						_size=4,
						_groupcode=CODE_GRP_MSG_SECURITY,
						_indicator=True,
						_index=0)],
		"keymatlen"     : [Field(
						_name="Keying Material Id Length",
						_size=3,
						_groupcode=CODE_GRP_KEYMAT,
						_indicator=True,
						_index=0)],
		"keymatid"      : [Field(
						_name="Keying Material Id",
						_size=64,
						_groupcode=CODE_GRP_KEYMAT,
						_indicator=True,
						_index=1)],
		"crypto_init_len"   : [Field(
						_name="Crypto Initialization Length",
						_size=4,
						_groupcode=CODE_GRP_CRYPTO_INIT,
						_indicator=True,
						_index=0)],
		"crypto_init"       : [Field(
						_name="Crypto Initialization",
						_size=1024,
						_groupcode=CODE_GRP_CRYPTO_INIT,
						_indicator=True,
						_index=1)],
		"keytok_len"        : [Field(
						_name="Key Token Length",
						_size=8,
						_groupcode=CODE_GRP_KEY_TOKEN,
						_indicator=True,
						_index=0)],
		"keytok"        : [Field(
						_name="Key Token",
						_size=16384,
						_groupcode=CODE_GRP_KEY_TOKEN,
						_indicator=True,
						_repeatable=True,
						_index=1)],
		"autha_len"     : [Field(
						_name="Auth. Data Length (A)",
						_size=7,
						_groupcode=CODE_GRP_AUTH_A,
						_indicator=True,
						_index=0)],
		"autha"         : [Field(
						_name="Auth Data (A)",
						_size=8192,
						_groupcode=CODE_GRP_AUTH_A,
						_indicator=True,
						_index=1)],
		"authb_len"     : [Field(
						_name="Auth. Data Length (B)",
						_size=7,
						_groupcode=CODE_GRP_AUTH_B,
						_indicator=True,
						_index=0)],
		"authb"         : [Field(
						_name="Auth Data (B)",
						_size=8192,
						_groupcode=CODE_GRP_AUTH_B,
						_indicator=True,
						_index=1)],
		"acksigned"     : [Field(
						_name="Signed Acknowledge Indicator",
						_size=1,
						_groupcode=CODE_GRP_MSG_SECURITY,
						_indicator=True,
						_index=6)],
		"pad_len"       : [Field(
						_name="Message Security Padding Length",
						_size=8,
						_groupcode=CODE_GRP_SEC_PAD,
						_indicator=True,
						_index=0)],
		"padding"       : [Field(
						_name="Message Security Padding",
						_size=2040,
						_groupcode=CODE_GRP_SEC_PAD,
						_index=1)]
	}

	vmf_groups = {
		CODE_GRP_HEADER     : [Group(
						_name="Application Header",
						_isroot=True)],
		CODE_GRP_ORIGIN_ADDR    : [Group(
						_name="Originator Address",
						_parent=CODE_GRP_HEADER,
						_index=2)],
		CODE_GRP_RCPT_ADDR  : [Group(
						_name="Recipient Address Group",
						_is_repeatable=True,
						_max_repeat=16,
						_parent=CODE_GRP_HEADER,
						_index=3)],
		CODE_GRP_INFO_ADDR  : [Group(
						_name="Information Address Group",
						_is_repeatable=True,
						_max_repeat=16,
						_parent=CODE_GRP_HEADER,
						_index=4)],
		CODE_GRP_MSG_HAND   : [Group(
						_name="Message Handling Group",
						_is_repeatable=True,
						_max_repeat=16,
						_parent=CODE_GRP_HEADER,
						_index=5+5*ENABLE_FUTURE_GRP)],

		CODE_GRP_VMF_MSG_IDENT  : [Group(
						_name="VMF Message Identification",
						_parent=CODE_GRP_MSG_HAND,
						_index=2)],
		CODE_GRP_ORIGIN_DTG : [Group(
						_name="Originator DTG",
						_parent=CODE_GRP_MSG_HAND,
						_index=10)],
		CODE_GRP_PERISH_DTG : [Group(
						_name="Perishability DTG",
						_parent=CODE_GRP_MSG_HAND,
						_index=11)],
		CODE_GRP_ACK        : [Group(
						_name="Acknowledgement Req. Group",
						_parent=CODE_GRP_MSG_HAND,
						_index=12)],
		CODE_GRP_RESPONSE   : [Group(
						_name="Response Data Group",
						_parent=CODE_GRP_MSG_HAND,
						_index=13)],
		CODE_GRP_REF        : [Group(
						_name="Reference Message Data Group",
						_is_repeatable=True,
						_max_repeat=4,
						_parent=CODE_GRP_MSG_HAND,
						_index=14)],
		CODE_GRP_MSG_SECURITY   : [Group(
						_name="Message Security Group",
						_parent=CODE_GRP_MSG_HAND,
						_index=15+5*ENABLE_FUTURE_GRP)],
		CODE_GRP_KEYMAT     : [Group(
						_name="Keying Material Group",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=1)],
		CODE_GRP_CRYPTO_INIT    : [Group(
						_name="Crypto. Initialization Group",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=2)],
		CODE_GRP_KEY_TOKEN  : [Group(
						_name="Key Token Group",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=3)],
		CODE_GRP_AUTH_A     : [Group(
						_name="Authentication Group (A)",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=4)],
		CODE_GRP_AUTH_B     : [Group(
						_name="Authentication Group (B)",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=5)],
		CODE_GRP_SEC_PAD    : [Group(
						_name="Message Security Padding",
						_parent=CODE_GRP_MSG_SECURITY,
						_index=7)]
	}

	def __init__(self, _args):
		self.print_msg(MSG_INFO, "Building VMF factory...")
		for field_name, field_value in _args.__dict__.items():
			if (field_value != None and field_name in self.vmf_fields.keys()):
				vmf_field_name = self.vmf_fields[field_name][0].name
				if (isinstance(field_value, list)):
					template = self.vmf_fields[field_name][0]
					nb_items = len(field_value)
					self.vmf_fields[field_name] = [template]*nb_items
					for field_idx in range(0, len(self.vmf_fields[field_name])):
						self.vmf_fields[field_name][field_idx].enable_and_set(field_value[field_idx])

						if (isinstance(field_value[field_idx], int)):
							self.print_setting(1, vmf_field_name, "0x{:02x}".format(field_value[field_idx]))
						else:
							self.print_setting(1, vmf_field_name, "{:s}".format(field_value[field_idx]))

				else:
					self.vmf_fields[field_name][0].enable_and_set(field_value)
					if (isinstance(field_value, int)):
						self.print_setting(1, vmf_field_name, "0x{:02x}".format(field_value))
					else:
						self.print_setting(1, vmf_field_name, "{:s}".format(field_value))

	def print_msg(self, _type, _msg):
		if (_type == MSG_ERROR):
			exc_type, exc_obj, exc_tb = sys.exc_info()
			if (exc_tb):
				print("[-] " + _msg + "[{:d}]".format(exc_tb.tb_lineno))
			else:
				print("[-] " + _msg )
		elif (_type == MSG_WARN):
			print("[!] " + _msg)
		elif (_type == MSG_INFO):
			print("[*] " + _msg)
		elif (_type == MSG_DEBUG):
			print("[>] " + _msg)
		elif (_type == MSG_SUCCESS):
			print("[+] " + _msg)
		else:
			print("    " + _msg)
				
	def print_setting(self, _prefixtabs, _setting, _value):
		linesize = 59
		setting_len = len(_setting)
		value_len = len(_value)
		tabs_len = 3+4*_prefixtabs

		if (setting_len + value_len + tabs_len >= linesize):
			indent = 3
			line1 = ('\t' * _prefixtabs) + _setting
			self.print_msg(MSG_SUCCESS, line1)
			lines_len = int(math.ceil(value_len / (linesize-tabs_len-indent)))
			cut_start = 0
			cut_end = 0
			for i in range(0, lines_len):
				prefix = ('\t' * _prefixtabs) + (' ' * indent)
				cut_end = cut_start+linesize - (len(prefix)+3)
				substr = _value[cut_start:cut_end]
				self.print_msg(-1, prefix + substr)
				cut_start = cut_end + 1
		else:
			space_len = linesize - value_len - (tabs_len + setting_len)
			line = ('\t' * _prefixtabs) + _setting + (' ' * space_len) + _value
			self.print_msg(MSG_SUCCESS, line)
				
	@staticmethod
	def get_value_from_dict(_key, _dict):
		for key, value in _dict.__dict__.items():
			if (key.lower() == _key.lower()):
				return value
		return None

	def get_vmf_msg(self):
		self.print_msg(MSG_DEBUG, "Creating VMF message object...")
		self.print_msg(MSG_DEBUG, "Adding fields to groups...")
		for (f_name, f_array) in self.vmf_fields.iteritems():
			i = 0
			group_code = f_array[i].grp_code
			if (not group_code in self.vmf_groups):
				raise Exception("Undefined group code: {:s}.".format(group_code))
			group_name = self.vmf_groups[group_code][i].name
			self.vmf_groups[group_code][i].append_field(f_array[i])
			self.print_msg(MSG_DEBUG, "Added field '{:s}' to group '{:s}'.".format(f_array[i].name, group_name))
		self.print_msg(MSG_DEBUG, "Creating group structure...")
		root_grp = self.vmf_groups[CODE_GRP_HEADER]
		for (g_code, g_array) in self.vmf_groups.iteritems():
			i = 0
			parent_group = g_array[i].parent_group
			if (not parent_group is None):
				self.vmf_groups[parent_group][i].fields.append(g_array[i])
				self.print_msg(MSG_DEBUG, "Added '{:s}' child group to '{:s}'.".format(g_array[i].name, parent_group))
		return root_grp

	def print_structure(self):
		print("="*60)
		self.print_msg(MSG_DEBUG, "Printing VMF Message Structure")
		header = self.vmf_groups[CODE_GRP_HEADER][0]
		header.fields.sort()
		self.print_msg(MSG_SUCCESS, "\t{:s}".format(header.name))
		for i in range(0, len(header.fields)):
			header_field = header.fields[i]
			if (isinstance(header_field, field)):
				self.print_msg(MSG_ERROR, "\t      {:s}".format(header_field.name))
			elif (isinstance(header_field, group)):
				self.print_struct_rec(3, header_field)
			else:
				raise Exception("Unknown header element type: {:s}.".format(header_field))

	def print_struct_rec(self, _tabs, _elem):
		if (isinstance(_elem, field)):
			self.print_msg(MSG_ERROR, "\t   " + " "*_tabs + "{:s}".format(_elem.name))
		elif(isinstance(_elem, group)):
			self.print_msg(MSG_SUCCESS, "\t   " + " "*_tabs + "{:s}".format(_elem.name))
			_elem.fields.sort()
			for f in _elem.fields:
				self.print_struct_rec(_tabs+4, f)
		else:
			raise Exception("Unknown element type: {:s}.".format(_elem))

	def print_header_binary(self):
		print("="*60)
		print_msg(MSG_INFO, "VMF Message Binary Fields")
		header = self.vmf_groups[CODE_GRP_HEADER][0]
		for i in range(0, len(header.fields)):
			f = header.fields[i]
			ba = f.get_bit_array()
			if (isinstance(f, field)):
				self.print_setting(1, f.name, ba.bin)
			elif(isinstance(f, group)):
				print_setting(1, f.name, ba.bin[0])
				self.print_header_binary_rec(1, f)

	def print_header_binary_rec(self, _tabs, _elem):
		for i in range(0, len(_elem.fields)):
			f = _elem.fields[i]
			if (isinstance(f, field)):
				ba = f.get_bit_array()
				self.print_setting(_tabs, f.name, ba.bin)
			elif(isinstance(f, group)):
				ba = f.get_bit_array()
				self.print_setting(1, f.name, ba.bin[0])
				self.print_header_binary_rec(_tabs, f)				
				
	@staticmethod
	def string_to_bitarray(_string, _maxsize=448):
		b = BitArray()
		pos = 0
		if (_string):
			for c in _string:
				c_str = "{:#09b}".format(ord(c))
				b.insert(c_str, pos)
				pos += 7
		if (len(b.bin) < _maxsize):
			b.insert(TERMINATOR, pos)
		if (len(b.bin) > _maxsize):
			raise ("Size of bit array exceeds the maximum size allowed ({:d}).".format(_maxsize))
		return b

