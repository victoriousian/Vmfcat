#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
# </copyright>
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>

#//////////////////////////////////////////////////////////////////////////////
# Import Statements

#//////////////////////////////////////////////////////////////////////////////
# Logger class
# 
class Logger(object):

	MSG_INFO = 0
	MSG_WARN = 1
	MSG_SUCCESS = 2
	MSG_ERROR = 3
	MSG_DEBUG = 4
	MSG_INPUT = 5

	def __init__(self, _output, _debug=False):
		self.output = _output
		self.debug = _debug

	def print_info(self, _message):
		self.print_msg(Logger.MSG_INFO, _message)

	def print_warning(self, _message):
		self.print_msg(Logger.MSG_WARN, _message)

	def print_success(self, _message):
		self.print_msg(Logger.MSG_SUCCESS, _message)

	def print_error(self, _message):
		self.print_msg(Logger.MSG_ERROR, _message)

	def print_debug(self, _message):
		self.print_msg(Logger.MSG_DEBUG, _message)

	def get_input(self, _message):
		uinput = raw_input("[?] {:s}".format(_message))
		return uinput

	def print_msg(self, _type, _msg):
	    """
		Display program execution information.

		Display an application-generated message with error-level
		information using an ASCII character; !,*,+,>,?.

		Args:
		    _type: Error-level of the message
		    _msg: Message to display at the console
		Returns:
		    None
		Raise:
		    None
	    """
	    #Error-type message
	    if (_type == Logger.MSG_ERROR):
		exc_type, exc_obj, exc_tb = sys.exc_info()
		if (exc_tb):
		    self.output.write("[-] " + _msg + "[{:d}]\n".format(exc_tb.tb_lineno))
		else:
		    self.output.write("[-] " + _msg + "\n")
	    # Warning-type message
	    elif (_type == Logger.MSG_WARN):
		self.output.write("[!] " + _msg + "\n")
	    #Information-type message
	    elif (_type == Logger.MSG_INFO):
		self.output.write("[*] " + _msg + "\n")
	    #Successful operation message
	    elif (_type == Logger.MSG_SUCCESS):
		self.output.write("[+] " + _msg + "\n")
	    #Debugging information
	    elif (_type == Logger.MSG_DEBUG):
		if (self.debug):
			self.output.write("[>] " + _msg + "\n")
	    #User-input request
	    elif (_type == Logger.MSG_INPUT):
		self.output.write("[?] " + _msg)
	    else:
		self.output.write("    " + _msg + "\n")

