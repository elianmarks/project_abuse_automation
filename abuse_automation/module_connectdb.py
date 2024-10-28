# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 01 - 03/02/2019**

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

"""

# libraries
import mysql.connector
from abuse_automation.module_exceptions import DatabaseFailed


class ModuleConnectDB:

    def __init__(self, module_log, module_configuration):
        """
        Define values for connection with database.
        :param moduleLog: Instance of the log class
        :type moduleLog: object
        """
        self.module_configuration = module_configuration
        self._log = module_log
        self._ip_db = self.module_configuration.ip_db
        self._user_db = self.module_configuration.user_db
        self._pass_db = self.module_configuration.pass_db
        self._database = self.module_configuration.database
        self._database_vps_dedi = self.module_configuration.database_vps_dedi

    @property
    def connection(self):
        """
        Realize the connection with database.
        :return: Object of the connection on success, False on failure
        :rtype: object or bool
        """
        try:
            # create object with connection in database
            connection_db = mysql.connector.connect(host=self._ip_db, user=self._user_db, password=self._pass_db,
                                                       database=self._database)
            # return a object of connection in database
            return connection_db

        except Exception as er:
            # generate a error log
            self._log.error("{} - {}".format(self.__class__.__name__, er))
            raise DatabaseFailed

    @property
    def connection_vps_dedi(self):
        """
        Realize the connection with database.
        :return: Object of the connection on success, False on failure
        :rtype: object or bool
        """
        try:
            # create object with connection in database
            connection_db = mysql.connector.connect(host=self._ip_db, user=self._user_db, password=self._pass_db,
                                                       database=self._database_vps_dedi)
            # return a object of connection in database
            return connection_db

        except Exception as er:
            # generate a error log
            self._log.error("{} - {}".format(self.__class__.__name__, er))
            raise DatabaseFailed
