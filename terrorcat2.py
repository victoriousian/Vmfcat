#!/usr/bin/env python

__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

import sys
import time
import argparse
import collections
import datetime
from enum import Enum
from bitstring import BitArray

usage = "%(prog)s [options] data"
parser = argparse.ArgumentParser(usage=usage, 
	prog="terrorcat", 
	version="%(prog)s "+__version__, 
	description="Allows crafting of Variable Message Format (VMF) messages.")

io_options = parser.add_argument_group(
	"Input/Output Options", "Types of I/O supported.")
io_options.add_argument("-of", "--ofile",
 	dest="outputfile", 
	nargs="?", 
	type=argparse.FileType('w'),
        default=sys.stdout,
        help="File to output the results. STDOUT by default.")

# =============================================================================
# Application Header Arguments
header_options = parser.add_argument_group(
	"Application Header", "Flags and Fields of the application header.")
header_options.add_argument("--vmf-version", 
	dest="vmfversion", 
	action="store", 
	choices=["47001", "47001B","47001C","47001D","47001D_CHANGE"],
        default="47001C",
        help="Specifies the version of the application header to use.")
header_options.add_argument("--compress", 
	dest="compress", 
	action="store", 
	choices=["UNIX", "GZIP"],
        help="Specifies the data compression algorithm to use if any.")
header_options.add_argument("--header-size", 
	dest="headersize",
	action="store", 
	type=int, 
	help="Specifies the size of the header.")		

# =============================================================================
# Originator Address Group Arguments
orig_addr_options = parser.add_argument_group(
	"Originator Address Group", "Fields of the originator address group.")
orig_addr_options.add_argument("--orig-urn", 
	dest="originator_urn", 
	metavar="URN", 
	type=int, 
	action="store", 
	help="Specify the URN of the originator of the message.")
orig_addr_options.add_argument("--orig-unit", 
	dest="originator_unitname", 
	metavar="STRING",
	action="store", 
	help="Specify the name of the unit sending the message.")
# =============================================================================

# =============================================================================
# Recipient Address Group Arguments
recp_addr_options = parser.add_argument_group(
	"Recipient Address Group", "Fields of the recipient address group.")
recp_addr_options.add_argument("--rcpt-urns", 
	nargs="+", 
	dest='rcpt_urns', 
	metavar="URNs", 
	help="List of 24-bit codes used to uniquely identify friendly units.")
recp_addr_options.add_argument("--rcpt-unitnames", 
	nargs="+", 
	dest='rcpt_unitnames', 
	metavar="UNITNAMES", 
	help=
	"""
		List of variable size fields of character-coded identifiers 
		for friendly units.
	""")
# =============================================================================

# =============================================================================
# Information Address Group Arguments
info_addr_options = parser.add_argument_group(
	"Information Address Group", "Fields of the information address group.")
info_addr_options.add_argument("--info-urns", 
	dest="info_urns", 
	metavar="URNs", 
	nargs="+",
	action="store", 
	help="Specify the URN of the reference message.")
info_addr_options.add_argument("--info-units", 
	dest="info_unitnames", 
	metavar="UNITNAMES",
	action="store", 
	help="Specify the name of the unit of the reference message.")
# =============================================================================

# =============================================================================
# Message Handling Group Arguments
msg_handling_options = parser.add_argument_group(
	"Message Handling Group", "Fields of the message handling group.")
msg_handling_options.add_argument("--umf", 
	dest="umf", 
	action="store",
	choices=[
		"link16", "binary", "vmf", 
		"nitfs", "rdm", "usmtf", 
		"doi103", "xml-mtf", "xml-vmf"
	],
	help=
	"""
		Indicates the format of the message contained in the 
		user data field.
	""")
msg_handling_options.add_argument("--msg-version", 
	dest="messagevers", 
	action="store", 
	metavar="VERSION", 
	type=int, 
	help=
	"""
		Represents the version of the message standard contained in 
		the user data field.
	""")
msg_handling_options.add_argument("--fad", 
	dest="fad", 
	action="store",
	choices=[
		"netcon", "infoex", "firesupport", 
		"airops", "int", "land", 
		"navy", "css", "special", 
		"jtfops", "airdef"
	],
	help="Identifies the functional area of a specific VMF message using code words.")
msg_handling_options.add_argument("--msg-number", 
	dest="msgnumber", 
	action="store", 
	type=int, 
	metavar="1-127",
	help=
	"""
		Represents the number that identifies a specific VMF message 
		within a functional area.
	""")
msg_handling_options.add_argument("--msg-subtype", 
	dest="msgsubtype", 
	action="store", 
	type=int, 
	metavar="1-127",
	help=
	"""
		Represents a specific case within a VMF message, which depends on
		the UMF, FAD and message number.
	""")
msg_handling_options.add_argument("--filename", 
	dest="filename", 
	action="store",
	help=
	"""
		Indicates the name of the computer file or data block contained 
		in the User Data portion of the application PDU.
	""")
msg_handling_options.add_argument("--msg-size", 
	dest="msgsize", 
	action="store", 
	type=int, 
	metavar="SIZE",
	help=
	"""
		Indicates the size (in bytes) of the associated message within
		the User Data field.
	""")

msg_handling_options.add_argument("--opind", 
	dest="opind", 
	action="store",
	choices=["op", "ex", "sim", "test"],
	help="Indicates the operational function of the message.")

msg_handling_options.add_argument("--retrans", 
	dest="retransmission", 
	action="store_true", 
	help="Indicates whether a message is a retransmission.")

msg_handling_options.add_argument("--msg-prec", 
	dest="msgprecedence", 
	action="store",
	choices=[
		"reserved", "critic", "flashover", 
		"flash", "imm", "pri", "routine"
	],
	help="Indicates relative precedence of a message.")

msg_handling_options.add_argument("--class", 
	dest="classification", 
	action="store",
	nargs="+",
	choices=["unclass", "conf", "secret", "topsecret"],
	help="Security classification of the message.")

msg_handling_options.add_argument("--release", 
	dest="releasemark", 
	action="store", 
	metavar="COUNTRIES",
	help=
	"""
		Support the exchange of a list of up to 16 country codes 
		with which the message can be release.
	""")
msg_handling_options.add_argument("--orig-dtg", 
	dest="originatordtg", 
	action="store", 
	metavar="YYYY-MM-DD HH:mm[:ss] [extension]", 
	help=
	"""
		Contains the date and time in Zulu Time that the 
		message was prepared.
	""")
msg_handling_options.add_argument("--perish-dtg", 
	dest="perishdtg", 
	action="store", 
	metavar="YYYY-MM-DD HH:mm[:ss]", 
	help="Provides the latest time the message is still of value.")


# =====================================================================================



ref_msg_options = parser.add_argument_group(
	"Reference Message Data Group", "Fields of the reference message data group.")
ref_msg_options.add_argument("--ref-urn", 
	dest="ref_urn", 
	metavar="URN", 
	action="store", 
	help="Specify the URN of the reference message.")
ref_msg_options.add_argument("--ref-unit", 
	dest="ref_unitname", 
	metavar="STRING",
	action="store", 
	help="Specify the name of the unit of the reference message.")
ref_msg_options.add_argument("--ref-dtg", 
	dest="refdtg", 
	action="store", 
	metavar="YYYY-MM-DD HH:mm[:ss] [extension]", 
	help="Date time group of the reference message.")


msg_sec_grp = parser.add_argument_group(
	"Message Security Group", "Fields of the message security group.")
msg_sec_grp.add_argument("--keymat-len", 
	dest="keymatlen", 
	action="store", 
	type=int,
	help="Defines the size in octets of the Keying Material ID field.")	
msg_sec_grp.add_argument("--keymat-id", 
	dest="keymatid", 
	action="store", 
	type=int,
	help="Identifies the key which was used for encryption.")
msg_sec_grp.add_argument("--crypto-init-len", 
	dest="crypto_init_len", 
	action="store", 
	type=int,
	help=
	"""
		Defines the size, in 64-bit blocks, of the Crypto 
		Initialization field.
	""")
msg_sec_grp.add_argument("--crypto-init", dest="crypto_init", action="store", type=int,
	help="Sequence of bits used by the originator and recipient to initialize the encryption/decryption process.")
msg_sec_grp.add_argument("--keytok-len", dest="keytok_len", action="store", type=int,
	help="Defines the size, in 64-bit blocks, of the Key Token field.")
msg_sec_grp.add_argument("--keytok", dest="keytok", action="store", type=int,
	help="Contains information enabling each member of each address group to decrypt the user data associated with this message header.")
msg_sec_grp.add_argument("--autha-len", dest="autha-len", action="store", type=int, metavar="LENGTH",
	help="Defines the size, in 64-bit blocks, of the Authentification Data (A) field.")
msg_sec_grp.add_argument("--authb-len", dest="authb-len", action="store", type=int, metavar="LENGTH",
	help="Defines the size, in 64-bit blocks, of the Authentification Data (B) field.")
msg_sec_grp.add_argument("--autha", dest="autha", action="store", type=int,
	help="Data created by the originator to provide both connectionless integrity and data origin authentication (A).")
msg_sec_grp.add_argument("--authb", dest="authb", action="store", type=int,
	help="Data created by the originator to provide both connectionless integrity and data origin authentication (B).")
msg_sec_grp.add_argument("--ack-signed", dest="acksigned", action="store_true", 
	help="Indicates whether the originator of a message requires a signed response from the recipient.")
msg_sec_grp.add_argument("--pad-len", dest="pad-len", action="store", type=int, metavar="LENGTH",
	help="Defines the size, in octets, of the message security padding field.")
msg_sec_grp.add_argument("--padding", dest="padding", action="store", type=int,
	help="Necessary for a block encryption algorithm so the content of the message is a multiple of the encryption block length.")


	
ack_options = parser.add_argument_group(
	"Acknowledgement Request Group", "Options to request acknowledgement and replies.")
ack_options.add_argument("--ack-machine", 
	dest="ackmachine", 
	action="store_true", 
	help=
	"""
		Indicates whether the originator of a machine requires a machine 
		acknowledgement for the message.
	""")
ack_options.add_argument("--ack-op", dest="ackop", action="store_true",
	help="Indicates whether the originator of the message requires an acknowledgement for the message from the recipient.")
ack_options.add_argument("--reply", dest="reply", action="store_true",
	help="Indicates whether the originator of the message requires an operator reply to the message.")

resp_options = parser.add_argument_group("Response Data Options", "Fields for the response data group.")
resp_options.add_argument("--ack-dtg", dest="ackdtg", action="store", metavar="YYYY-MM-DD HH:mm[:ss] [extension]", help="Provides the date and time of the original message that is being acknowledged.")
resp_options.add_argument("--rc", dest="rccode", action="store", 
	choices=["mr", "cantpro", "oprack", "wilco", "havco", "cantco", "undef"],
	help="Codeword representing the Receipt/Compliance answer to the acknowledgement request.")
resp_options.add_argument("--cantpro", dest="cantpro", action="store", type=int, metavar="1-32",
	help="Indicates the reason that a particular message cannot be processed by a recipient or information address.")
resp_options.add_argument("--cantco", dest="cantco", action="store", 
	choices=["comm", "ammo", "pers", "fuel", "env", "equip", "tac", "other"],
	help="Indicates the reason that a particular recipient cannot comply with a particular message.")
resp_options.add_argument("--reply-amp", dest="replyamp", action="store",
	help="Provide textual data an amplification of the recipient's reply to a message.")

# =============================================================================
# Global Variables
ABSENT  = 0x0
PRESENT = 0x1

DEFAULT_FPI = ABSENT
DEFAULT_FRI = 0
DEFAULT_GPI = ABSENT
DEFAULT_GRI = 0

TERMINATOR = 0x7E

CODE_GRP_ORIGIN_ADDR 	= "G1"
CODE_GRP_RCPT_ADDR	= "G2"
CODE_GRP_INFO_ADDR	= "G3"
CODE_GRP_MSG_HAND	= "R3"
CODE_GRP_VMF_MSG_IDENT 	= "G9"
CODE_GRP_ORIGIN_DTG	= "G10"

NO_STATEMENT		= 63

MSG_SUCCESS 	= 0x0
MSG_ERROR 	= 0x1
MSG_WARN 	= 0x2
MSG_INFO 	= 0x3

# =============================================================================

class group:
	gpi = DEFAULT_FPI
	gri = DEFAULT_GRI
	is_repeatable = False
	name = ""
	fields = []

	def __init__(self, _name, _is_repeatable=False):
		self.name = _name
		self.is_repeatale = _is_repeatable

	def enable(self):
		self.gpi = PRESENT

	def set_gri(self, _value):
		self.gri = _value

	def add_field(self, _field):
		self.fields.append(_field)

	def get_bit_array(self):
		b = BitArray(self.gpi)
		if (self.is_repeatable):
			b.append("{:#03b}".format(self.gri))
		for f in self.fields:
			fbits = f.get_bit_array
			b.append(fbits)

# =============================================================================
# Field Class
# Contains common properties to VMF fields 
class field(object):
	fpi = DEFAULT_FPI
 	fri = DEFAULT_FRI
	is_repeatable = False
	is_indicator = False
	size = 0
	name = ""
	value = 0
	format_str = ""
	grp_code = ""

	def __init__(self, _name, _size, _value=0, _groupcode = 0, _repeatable=False, _indicator=False):
		self.name = _name
		self.size = _size
		self.value = _value
		self.is_repeatable = _repeatable
		self.is_indicator = _indicator
		self.format = "{:#0" + str(self.size+2) + "b}"

	def enable_and_set(self, _value):
		self.fpi = PRESENT
		self.value = _value

	def get_bit_array(self):
		b = BitArray()
		if (not self.is_indicator):
			b.append(self.fpi)
		if (isinstance(self.value, int)):
			if (self.is_repeatable):
				b.append("{:#03b}".format(self.fri))
			if (self.fpi == PRESENT or self.is_indicator):
				b.append(self.format_str.format(self.value))
			return b
		#else:
			#TODO: Process strings

# =============================================================================

class dtg_field(field):
	has_extension = False

	fields = {
		"year" 	: field(
				_name="year", 
				_size=7, 
				_indicator=True),
		"month"	: field(
				_name="month", 
				_size=4, 
				_indicator=True),
		"day"	: field(
				_name="day", 
				_size=5, 
				_indicator=True),
		"hour"	: field(
				_name="hour", 
				_size=5, 
				_indicator=True),
		"minute": field(
				_name="minute", 
				_size=6, 
				_indicator=True),
		"second": field(
				_name="second", 
				_size=6, 
				_value=NO_STATEMENT,
				_indicator=True),
		"ext"	: field(
				_name="extension", 
				_size=12)
	}

	def __init__(self, _name, _size=46, _value=0, _groupcode = 0, _repeatable=False, _extension=True):
		super(dtg_field, self).__init__(_name, _size, _value, _groupcode, _repeatable)
		self.has_extension=_extension
		self.set_value(_value)

	def set_value(self, _value):
		#Expected format: YYYY-MM-DD HH:mm[:ss] [extension]"
		if (_value):
			self.fpi = PRESENT
			date_items = _value.split(' ')

			if (len(date_items) == 2 or len(date_items) == 3):
				format_str = "%Y-%m-%d %H:%M"
				#
				# Check if seconds are included.
				#
				if (date_items[1].count(":") > 1):
					format_str = "%Y-%m-%d %H:%M:%S"
				else:
					self.fields["second"].enable_and_set(NO_STATEMENT)
				
				date_obj = datetime.strptime(date_items[0] + ' ' + date_items[1], format_str)
				self.fields["year"].enable_and_set(date_obj.strftime('%Y'))
				self.fields["month"].enable_and_set(date_obj.strftime('%m'))
				self.fields["day"].enable_and_set(date_obj.strftime('%d'))
				self.fields["hour"].enable_and_set(date_obj.strftime('%H'))
				self.fields["minute"].enable_and_set(date_obj.strftime('%M'))
	
				#				
				# Check if extension has been included
				#
				if (len(date_items) == 3):
					self.fields["ext"].set_value(date_items[2])
			else:
				raise Exception("Unknown datetime group format: {:s}.".format(_value))

		#else:
		#	raise Exception("Datetime group provided is null or empty.")
		
	def get_bit_array(self):
		b = BitArray()
		for f in self.fields:
			if (f.name == "ext"):
				if (self.has_extension):
					fbits = f.get_bit_array()
					b.append(fbits)
			else:
				fbits = f.get_bit_array()
				b.append(fbits)
		return b

class factory:

	vmf_fields = {
		"vmfversion" 		: [field("Version", 4)],
		"compress" 		: [field("Data Compression", 2)],
		"originator_urn"	: [field(
						_name="Originator URN", 
						_size=24, 
						_groupcode=CODE_GRP_ORIGIN_ADDR)],
		"originator_unitname"	: [field(
						_name="Originator Unit Name", 
						_size=448, 
						_groupcode=CODE_GRP_ORIGIN_ADDR)],
		"rcpt_urns"		: [field(
						_name="Recipient URN", 
						_size=24, 
						_groupcode=CODE_GRP_RCPT_ADDR)],
		"rcpt_unitnames"	: [field(
						_name="Recipient Unit Name", 
						_size=448, 
						_groupcode=CODE_GRP_RCPT_ADDR)],
		"info_urns"		: [field(
						_name="Information URN", 
						_size=24, 
						_groupcode=CODE_GRP_INFO_ADDR)],
		"info_unitnames"	: [field(
						_name="Information Unit Name", 
						_size=448, 
						_groupcode=CODE_GRP_INFO_ADDR)],
		"umf"			: [field(
						_name="UMF", 
						_size=4, 
						_groupcode=CODE_GRP_MSG_HAND)],
		"messagevers"		: [field(
						_name="Message Standard Version", 
						_size=4, 
						_groupcode=CODE_GRP_MSG_HAND)],
		"fad"			: [field(
						_name="FAD", 
						_size=4, 
						_groupcode=CODE_GRP_VMF_MSG_IDENT)],
		"msgnumber"		: [field(
						_name="Message Number",
						_size=7,
						_groupcode=CODE_GRP_VMF_MSG_IDENT)],
		"msgsubtype"		: [field(
						_name="Message Subtype",
						_size=7,
						_groupcode=CODE_GRP_VMF_MSG_IDENT)],
		"filename"		: [field(
						_name="File name",
						_size=448,
						_groupcode=CODE_GRP_MSG_HAND)],
		"msgsize"		: [field(
						_name="Message Size",
						_size=20,
						_groupcode=CODE_GRP_MSG_HAND)],
		"opind"			: [field(
						_name="Operation Indicator",
						_size=2,
						_groupcode=CODE_GRP_MSG_HAND)],
		"retransmission"	: [field(
						_name="Retransmit Indicator",
						_size=1,
						_groupcode=CODE_GRP_MSG_HAND)],
		"msgprecedence"		: [field(
						_name="Message Precedence Code",
						_size=3,
						_groupcode=CODE_GRP_MSG_HAND)],
		"classification"	: [field(
						_name="Security Classification",
						_size=2,
						_groupcode=CODE_GRP_MSG_HAND)],
		"releasemark"		: [field(
						_name="Control/Release Marking",
						_size=9,
						_repeatable=True,
						_groupcode=CODE_GRP_MSG_HAND)],
		"originatordtg"		: [dtg_field(
						_name="Originator DTG",
						_groupcode=CODE_GRP_ORIGIN_DTG)]
	}

	def __init__(self, _args):
		print_msg(MSG_INFO, "Building VMF factory...")
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
							print_msg(MSG_SUCCESS, "\t{:s}:\t\t0x{:02x}".format(vmf_field_name, field_value[field_idx]))
						else:
							print_msg(MSG_SUCCESS, "\t{:s}:\t\t{:s}".format(vmf_field_name, field_value[field_idx]))

				else:
					self.vmf_fields[field_name][0].enable_and_set(field_value)
					if (isinstance(field_value, int)):
						print_msg(MSG_SUCCESS, "\t{:s}:\t\t0x{:02x}".format(vmf_field_name, field_value))
					else:
						print_msg(MSG_SUCCESS, "\t{:s}:\t\t'{:s}'".format(vmf_field_name, field_value))

	def get_value_from_dict(self, _key, _dict):
		for key, value in _dict.__dict__.items():
			if (key.lower() == _key.lower()):
				return value
		return None

	def string_to_bitarray(self, _string, _maxsize=448):
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

def banner():
    print("Copyright (C) 2015  Jonathan Racicot <jonathan.racicot@rmc.ca>")
    print("This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it under certain conditions.")

	
def print_msg(_type, _msg):
	if (_type == MSG_ERROR):
		print("[-] " + _msg)
	elif (_type == MSG_WARN):
		print("[!] " + _msg)
	elif (_type == MSG_INFO):
		print("[*] " + _msg)
	elif (_type == MSG_SUCCESS):
		print("[+] " + _msg)
	else:
		print("[>] " + _msg)
		

def main(args):
	try:
		vmf_factory = factory(args)
	except Exception as e:
		print(e.message)		

if __name__ == "__main__":
	banner()
	main(parser.parse_args())
