#!/usr/bin/env python

__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

import sys
import time
import argparse
from enum import Enum

usage = "%(prog)s [options] data"
parser = argparse.ArgumentParser(usage=usage, prog="terrorcat", version="%(prog)s "+__version__, description="Converts a VMF message into hexadecimal form.")

io_options = parser.add_argument_group("Input/Output Options", "Types of I/O supported.")
header_options = parser.add_argument_group("Application Header", "Flags and Fields of the application header.")
header_options.add_argument("--vmf-version", dest="vmfversion", 
	action="store", choice=["47001", "47001B","47001C","47001D","47001D_CHG1"],
        default="47001C",
        help="Specifies the version of the application header to use.")
header_options.add_argument("--compress", dest="compress", 
	action="store", choice=["UNIX", "GZIP"],
        default="UNIX",
        help="Specifies the data compression algorithm to use if any.")
		
orig_addr_options = parser.add_argument_group("Originator Address Group", "Fields of the originator address group.")
orig_addr_options.add_argument("--orig-urn", dest="originator_urn", 
	action="store", help="Specify the URN of the originator of the message.")
orig_addr_options.add_argument("--orig-unit", dest="originator_unitname", 
	action="store", help="Specify the name of the unit sending the message.")
	
recp_addr_options = parser.add_argument_group("Recipient Address Group", "Fields of the recipient address group.")

io_options.add_argument("-of", "--ofile", dest="outputfile", nargs="?", type=argparse.FileType('w'),
        default=sys.stdout,
        help="File to output the results. STDOUT by default.")

parser.add_argument_group(io_options)
parser.add_argument_group(header_options)
parser.add_argument_group(orig_addr_options)
parser.add_argument_group(recp_addr_options)

ABSENT = 0x0
PRESENT = 0x1

RECIPIENT_GRP_MIN = 0
RECIPIENT_GRP_MAX = 16

class version(Enum):
	mil_std_2504_47001  = 0x0
	mil_std_2504_47001b = 0x1
	mil_std_2504_47001c = 0x2
	mil_std_2504_47001d = 0x3
	mil_std_2504_47001d_change = 0x4
	undefined1 = 0x5
	undefined2 = 0x6
	undefined3 = 0x7
	undefined4 = 0x8
	undefined5 = 0x9
	undefined6 = 0xa
	undefined7 = 0xb
	undefined8 = 0xc
	undefined9 = 0xd
	undefined10 = 0xe
	not_implemented = 0xf
	
class data_compression(Enum):
	unix = 0x0
	gzip = 0x1
	undefined1 = 0x2
	undefined2 = 0x3
	
class umf(Enum):
	link16 = 0x0
	binary = 0x1
	vmf = 0x2
	nitfs = 0x3
	rdm = 0x4
	usmtf = 0x5
	doi103 = 0x6
	xml_mtf = 0x7
	xml_vmf = 0x8
	undefined1 = 0x9
	undefined2 = 0xA
	undefined3 = 0xB
	undefined4 = 0xC
	undefined5 = 0xD
	undefined6 = 0xE
	undefined7 = 0xF	
	
class operation(Enum):
	operation = 0x0
	exercise = 0x1
	simulation = 0x2
	test = 0x3
	
class precedence(Enum):
	reserved1 = 0x7
	reserved2 = 0x6
	critic = 0x5
	flash_override = 0x4
	flash = 0x3
	immediate = 0x2
	priority = 0x1
	routine = 0x0
	
class classification(Enum):
	unclassified = 0x0
	confidential = 0x1
	secret = 0x2
	top_secret = 0x3
	
"""
 Default version for new VMF messages generated.
"""
DEFAULT_FPI = ABSENT
DEFAULT_GPI = ABSENT
DEFAULT_VERSION = version.mil_std_2504_47001c
DEFAULT_COMPRESS = data_compression.unix

TERMINATOR = 0x7E

class dtg:
	year = 0
	month = 0
	day = 0
	hour = 0
	minute = 0
	second = 0 
	
	NO_STATEMENT = 63
	
	def __init__(self, year, month, day, hour, minute, second=NO_STATEMENT):
		self.year = year
		self.month = month
		self.day = day 
		self.hour = hour
		self.minute = minute
		self.second = second
	
class rc(Enum):
	undefined1 = 0x0
	machine_receipt = 0x1
	cantpro = 0x2
	oprack = 0x3
	wilco = 0x4
	havco = 0x5
	cantco = 0x6
	undefined2 = 0x7
	
class security_param(Enum):
	auth = 0x0
	
'''
Address Group
'''
class addr_grp:
	gpi = DEFAULT_GPI
	fpi_urn = DEFAULT_FPI
	urn = 0
	size_urn = 24
	fpi_unitname = DEFAULT_FPI
	unit_name = ''
	size_unitname = 448
	
	def __init__(self, _gpi=0, _fpi_urn=0, _urn=0, _fpi_unitname=0, _unitname=''):
		self.gpi = _gpi
		self.fpi_urn = _fpi_urn
		self.urn = _urn
		self.fpi_unitname = _fpi_unitname
		self.unit_name = _unitname
	
class future_group:
	gpi = DEFAULT_GPI
	size = 0
	
'''
VMF Identification Group
'''
class vmf_id_grp:
	gpi = DEFAULT_GPI
	fad = 0
	msg_num = 0
	fpi_subtype = DEFAULT_FPI
	msg_subtype = 0x0
	
'''
Acknowledgement Request Group
'''
class ack_grp:
	machine = 0x0
	operator = 0x0
	op_reply = 0x0
	
	def __init__(self, _machine_ack=0x0, _operator_ack=0x0, _operator_reply=0x0):
		self.machine = _machine_ack
		self.operator = _operator_ack
		self.op_reply = _operator_reply
	
'''
Response Data Group
'''
class resp_grp:
	gpi = DEFAULT_GPI
	dtg = 0x0
	fpi_dtg_ext = DEFAULT_FPI
	dtg_ext = 0x0
	rc_code = 0x0
	fpi_cantco_reason = DEFAULT_FPI
	cantco_code = 0x0
	fpi_cantpro_reason = DEFAULT_FPI
	cantpro_reason = 0x0
	fpi_reply_amp = DEFAULT_FPI
	reply_amp = 0x0

'''
Reference Message Data Group
'''	
class ref_msg_grp:
	gpi = DEFAULT_GPI
	dtg = None
	fpi_dtg_ext = DEFAULT_FPI
	dtg_ext = 0x0
	future_grp = [0]*5
	
	def __init__(self, _gpi=0x0, _dtg=0x0, _fpi_dtg_extension=0x0, _dtg_extension=0x0):
		self.gpi = _gpi
		self.dtg = _dtg
		self.fpi_dtg_ext = _fpi_dtg_extension
		self.dtg_ext = _dtg_extension
	
'''
Key Material Group
'''
class keymat_grp:
	gpi = DEFAULT_GPI
	keymat_id_len = 0x0
	keymat_id = 0x0

	def __init__(self, _gpi=0x0, keymat_id_length=0x0, keymat_ident=0x0):
		self.gpi = _gpi
		self.keymat_id_len = keymat_id_length
		self.keymat_id = keymat_ident

'''
Cryptographic Initialization Group
'''	
class crypto_init_grp:
	gpi = DEFAULT_GPI
	init_len = 0x0
	init = 0x0

	def __init__(self, _gpi=0x0, _initial_length=0x0, _initial=0x0):
		self.gpi = _gpi
		self.init_len = _initial_length
		self.init = _initial
	
'''
Key Token Group
'''
class token_key_grp:
	gpi = DEFAULT_GPI
	keytok_len = 0x0
	fri_keytok = 0x0
	keytok = 0x0
	
	def __init__(self, _gpi=0x0, _keytoken_length=0x0, _fri_keytoken=0x0, _keytoken=0x0):
		self.gpi = _gpi
		self.keytok_len = _keytoken_length
		self.fri_keytok = _fri_keytoken
		self.keytok = _keytoken
	
'''
Authentication Group
'''
class auth_grp:
	gpi = DEFAULT_GPI
	length = 0x0
	data = 0x0
	
	def __init__(self, _gpi=0x0, _length=0x0, _data=0x0):
		self.gpi = _gpi
		self.length = _length
		self.data = _data		
	
class sec_add_grp:
	gpi = DEFAULT_GPI
	length = 0x0
	fpi_sec_pad = DEFAULT_FPI
	sec_pad = 0x0
	future_groups = [0]*5
	
	def __init__(self, _gpi=0x0, _length=0x0, _fpi_securitypad=0x0, _security_padding=0x0):
		self.gpi = _gpi
		self.length = _length
		self.fpi_sec_pad = _fpi_securitypad
		self.sec_pad = _security_padding
	
class sec_grp:
	param_info = 0x0
	keymat = 0x0
	crypto_init = 0x0
	keytok = 0x0
	auth_a = 0x0
	auth_b = 0x0
	signed_ack_req = 0x0
	
class msg_handling_grp:
	umf = 0
	fpi_msg_std_vers = 0
	msg_id_grp = 0x0
	fpi_filename = 0x0
	filename = ''
	fpi_msg_size = 0x0
	msg_size = 0x0
	op_ind = 0x0
	retx_ind = 0x0
	msg_prec_code = 0x0
	sec_classification = 0x0
	fpi_release = 0x0
	fri_release = 0x0
	release_mark = 0x0
	origin_dtg = 0x0
	fpi_origin_dtg_ext = 0x0
	origin_dtg_ext = 0x0
	perish_dtg = 0x0
	acknowledge_grp = 0x0
	
	
	
class vmf_message:
	version = DEFAULT_VERSION
	size_version = 4
	
	fpi_compress = DEFAULT_FPI
	data_compress = DEFAULT_COMPRESS
	size_compress = 2
	
	origin_addr = None
	
	gri_recipient_addr = 0
	recipient_addr = None
	
	gri_info_addr = 0
	info_addr = None
	
	fpi_header_size = DEFAULT_FPI
	header_size = 0
	
	future_groups = [0]*15
	
	gri_msg_handling = 0
	
	umf = 0
	fpi_msg_std_vers = DEFAULT_FPI
	msg_std_vers = 0 
	gpi_msg_id_grp = DEFAULT_GPI
	fad = 0
	msg_number = 0
	fpi_msg_subtype = DEFAULT_FPI
	msg_subtype = 0
	fpi_filename = DEFAULT_FPI
	filename = ''
	fpi_msg_size = DEFAULT_FPI
	msg_size = 0
	op_indicator = 0
	retransmit_indicator = 0
	msg_prec_codes = 0
	sec_class = 0
	fpi_control_rel = DEFAULT_FPI
	fri_control_rel = 0
	control_rel = 0
	gpi_orig_dtg = 0
	orig_dtg = time.strftime("%c")
	fpi_dtg_ext = 0
	dtg_extension = 0
	gpi_ack_req_indicator = 0
	
	def bitstream():
		return None
	
class vmf_factory:
	vmf_message = None
	
	def __init__(self):
		self.vmf_message = new vmf_message()
	
	def set_version(self, _version):
		self.vmf_message.version = _version
	
	def set_data_compression(self, _compression):
		self.vmf_message.fpi_compress = PRESENT
		self.vmf_message.data_compress = _compression
	
	def get_address_group_by_urn(self, _urn):
		valid_urn = _urn
		new_addr_grp = addr_grp(_gpi=PRESENT, _fpi_urn=PRESENT, _urn=valid_urn)
		return new_addr_grp
		
	def get_address_group_by_unit(self, _unit):
		valid_unitname = _unit
		new_addr_grp = addr_grp(_gpi=PRESENT, _fpi_unitname=PRESENT, _unitname=valid_unitname)
		return new_addr_grp	
	
	def set_originator_urn(self, _urn):
		valid_urn = _urn
		originator = addr_grp(_gpi=PRESENT, _fpi_urn=PRESENT, _urn=valid_urn)
		self.vmf_message.origin_addr = originator
		
	def set_originator_unitname(self, _unitname):
		valid_unitname = _unitname
		originator = addr_grp(_gpi=PRESENT, _fpi_unitname=PRESENT,  _unitname=valid_unitname)	
		self.vmf_message.origin_addr = originator
	
	def set_nb_recipients(self, _nb_recipients):
		if (_nb_recipients >= 0 and _nb_recipients < RECIPIENT_GRP_MAX):
			self.vmf_message.gri_recipient_addr = _nb_recipients
			self.vmf_message.recipient_addr = [addr_grp()]*_nb_recipients
		else:
			raise Exception("Invalid number of recipients. Must be between 0 and {:d}".format(RECIPIENT_GRP_MAX))

	def set_recipients(self, _recipients):
		nb_recipients = len(_recipients)
		if (nb_recipients >= 0 and nb_recipients < RECIPIENT_GRP_MAX):
			self.vmf_message.gri_recipient_addr = nb_recipients
			self.vmf_message.recipient_addr = _recipients
		else:
			raise Exception("Invalid number of recipients. Must be between 0 and {:d}".format(RECIPIENT_GRP_MAX))
						
	def set_recipient(self, _index, _addrgrp):
		if (_index >=0 and _index < len(self.recipient_addr)-1):
			self.vmf_message.recipient_addr[_index] = _addrgrp
		else:
			raise Exception("Out of bound index. Must be between 0 and {:d}".format(len(self.recipient_addr)-1))		
	
	def set_info_addresses(self, _addresses):
		self.vmf_message.gri_info_addr = RECIPIENT_GRP_MAX-self.vmf_message.gri_recipient_addr
		if (len(_addresses) != nb_info_addr):
			raise Exception("Invalid number of information addresses. Expected {:d} addresses.".format(self.vmf_message.gri_info_addr))
		else:
			self.vmf_message.info_addr = _addresses
	
	def set_header_size(self, _header_size):
		self.vmf_message.fpi_header_size = PRESENT
		self.vmf_message.header_size = _header_size
	
	def get_vmf_header():
		return self.vmf_message
	
def banner():
    print("Copyright (C) 2015  Jonathan Racicot <jonathan.racicot@rmc.ca>")
    print("This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it under certain conditions.")

MSG_SUCCESS = 0x0
MSG_ERROR = 0x1
MSG_WARN = 0x2
MSG_INFO = 0x3
	
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
		print_msg(MSG_INFO, "Creating VMF factory...")
		factory = vmf_factory()
		
		print_msg(MSG_INFO, "Setting version...")
		factory.set_version(args.vmfversion)
		
		if (args.compress):
			print_msg(MSG_INFO, "Data compression enabled.")
			factory.set_data_compression(args.compression)
		
		if (args.orig-unit):
			print_msg(MSG_INFO, "Unit name of the originator is provided.")
			factory.set_originator_unitname(args.orig-unit)
		
		if (args.orig-urn):
			print_msg(MSG_INFO, "URN name of the originator is provided.")
			factory.set_originator_urn(args.orig-urn)
		
		app_header = factory.get_vmf_header()
	except Exception a e:
		print_msg(MSG_ERROR, e.message)
	

if __name__ == "__main__":
	banner()
	main(parser.parse_args())