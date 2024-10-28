# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 01 - 02/02/2019**

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

"""

# libraries
import logging
from contextlib import closing
from datetime import datetime
from abuse_automation.module_exceptions import GeneralError


class ModuleLog:

	def __init__(self, module_configuration, daemon):
		"""
		Define values for create log instance
		:param module_configuration:  Instance of the module_configuration class
		:type module_configuration: object
		"""
		try:
			self.module_configuration = module_configuration
			self.daemon = daemon
			# configuration logging
			self.log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
			self.log_file = None
			self.log_handler = None
			self.log_level = None
			self.log = None
			self.log_formatter = None
			# check type daemon
			if self.daemon == 1:
				self.log_file = str(self.module_configuration.log_file_main) + "_" + str(datetime.now().strftime('%d_%m_%Y')) + ".log"
			elif self.daemon == 2:
				self.log_file = str(self.module_configuration.log_file_analyze) + "_" + str(datetime.now().strftime('%d_%m_%Y')) + ".log"
			elif self.daemon == 3:
				self.log_file = str(self.module_configuration.log_file_vt) + "_" + str(datetime.now().strftime('%d_%m_%Y')) + ".log"
			elif self.daemon == 4:
				self.log_file = str(self.module_configuration.log_file_ia) + "_" + str(datetime.now().strftime('%d_%m_%Y')) + ".log"
			elif self.daemon == 5:
				self.log_file = str(self.module_configuration.log_file_zenapply) + "_" + str(datetime.now().strftime('%d_%m_%Y')) + ".log"
			# get log level
			self.log_level = self.module_configuration.log_level
			#configuration log
			self.log = logging.getLogger(__name__)
			self.log.setLevel(self.log_level)
			with closing(logging.FileHandler(self.log_file)) as self.log_handler:
				self.log_handler.setLevel(self.log_level)
				self.log_formatter = logging.Formatter(self.log_format)
				self.log_handler.setFormatter(self.log_formatter)
				self.log.addHandler(self.log_handler)

		except Exception as er:
			print("{} - {}".format(self.__class__.__name__, er))
			raise GeneralError
