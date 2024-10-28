# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 01 - 03/02/2019**

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

"""

# libraries
from abuse_automation.module_connectdb import ModuleConnectDB
from abuse_automation.module_exceptions import DatabaseUpdateFailed, DatabaseInsertFailed, \
    DatabaseFailed, DatabaseSelectFailed
from contextlib import closing
from datetime import datetime


class ModuleDatabase:

    def __init__(self, module_log, module_configuration):
        """
        Create instance of the ModuleConnectDB class.
        :param module_log: Instance of the log class
        :type module_log: object
        """
        self.module_configuration = module_configuration
        self._log = module_log
        # create instance with connection for database
        self._module_connectdb = ModuleConnectDB(module_log, self.module_configuration)

    def duplicated_domain(self, domain):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select ticket_id from analyzing where main_domain = '{}' and execution_start > now() + interval - 5 day order by id desc limit 1".format(domain)
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    # check if a line has been found
                    if conn_cursor.rowcount > 0:
                        return True
                    else:
                        return False

        except Exception as er:
            # generate a error log
            self._log.error("duplicated_domain - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseSelectFailed

    def check_thread_id(self, thread_id):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select ticket_id from analyzing where thread_id = '{}'".format(thread_id)
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    # check if a line has been found
                    if conn_cursor.rowcount == 1:
                        return True
                    else:
                        return False

        except Exception as er:
            # generate a error log
            self._log.error("check_thread_id - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseSelectFailed

    def check_ip(self, value_check_ip):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection_vps_dedi) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select id from servers where ip = '{}'".format(value_check_ip)
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    # check if a line has been found
                    if conn_cursor.rowcount > 0:
                        return True
                    else:
                        return False

        except Exception as er:
            # generate a error log
            self._log.error("check_ip - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseSelectFailed

    def get_start_handle(self, thread_id):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select execution_start from analyzing where thread_id = '{}'".format(thread_id)
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    # check if a line has been found
                    if conn_cursor.rowcount == 1:
                        return result[0]
                    else:
                        return None

        except Exception as er:
            # generate a error log
            self._log.error("get_start_handle - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseSelectFailed

    def get_result_type(self, thread_id):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select result_type from analyzing where thread_id = '{}'".format(thread_id)
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    # check if a line has been found
                    if conn_cursor.rowcount == 1:
                        return str(result[0])
                    else:
                        return None

        except Exception as er:
            # generate a error log
            self._log.error("get_result_type - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseSelectFailed

    def get_value(self, column, thread_id):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select {} from analyzing where thread_id = '{}'".format(column, thread_id)
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    # check if a line has been found
                    if conn_cursor.rowcount == 1:
                        return str(result[0])
                    else:
                        return None

        except Exception as er:
            # generate a error log
            self._log.error("get_value - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseSelectFailed

    def result_vt(self, thread_id):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select positives_vt from analyzing where thread_id = '{}' and status_vt = 1 order by id desc limit 1".format(thread_id)
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    # check if a line has been found
                    if conn_cursor.rowcount == 1:
                        return int(result[0])
                    else:
                        return 0

        except Exception as er:
            # generate a error log
            self._log.error("result_vt - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseSelectFailed

    def get_scan_vt(self, thread_id):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select scan_vt from analyzing where thread_id = '{}' and status_vt = 1 order by id desc limit 1".format(thread_id)
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    # check if a line has been found
                    if conn_cursor.rowcount == 1:
                        if result[0] is not None:
                            return result[0]
                        else:
                            return False
                    else:
                        return False

        except Exception as er:
            # generate a error log
            self._log.error("get_scan_vt - {} - {}".format(self.__class__.__name__, er))
            return False

    def result_clamav(self, thread_id):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select result_scan from analyzing where thread_id = '{}' order by id desc limit 1".format(thread_id)
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    # check if a line has been found
                    if conn_cursor.rowcount > 0:
                        if result[0] is not None and int(result[0]) == 1:
                            return True
                        else:
                            return False
                    else:
                        return False

        except Exception as er:
            # generate a error log
            self._log.error("result_clamav - {} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def last_update_tld(self):
        """
        Check in the database the last execution recorded of the update of TLDs list.
        :return: Value of the last execution recorded in the database on success, False on failure
        :rtype: datetime or bool
        """
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "select execution from update_date_tld order by id desc limit 1"
                    conn_cursor.execute(sql)
                    result = conn_cursor.fetchone()
                    if conn_cursor.rowcount > 0:
                        # return the value of the last execution TLD update
                        return result[0]
                    else:
                        raise DatabaseSelectFailed

        except Exception as er:
            # generate a error log
            self._log.error("last_update_tld - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseSelectFailed

    def update_date_tld(self):
        """
        Execute a insert in update_date_tld table with current datetime.
        :return: True on success, False on failure
        :rtype: bool
        """
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "insert into update_date_tld() values()"
                    conn_cursor.execute(sql)
                    conn.commit()
                    return True

        except Exception as er:
            # generate a error log
            self._log.error("update_date_tld - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseInsertFailed

    def update_analyzing(self, column, value, thread_id):
        try:
            if value is True:
                value = 1
            elif value is False or value is None:
                value = 0
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # sql for insert of the data
                    sql = "update analyzing set {} = '{}' where thread_id = '{}'".format(column, value, thread_id)
                    conn_cursor.execute(sql)
                    conn.commit()
                    return True

        except Exception as er:
            # generate a error log
            self._log.error("update_analyzing - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseUpdateFailed

    def insert_analyzing(self, ticket_id, thread_id, main_check, status, handled, main_user=None, main_domain=None, main_ip=None):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "insert into analyzing(ticket_id, thread_id, main_check, main_user, main_domain, main_ip, status, handled) " \
                                "values('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(
                        ticket_id, thread_id, main_check, main_user, main_domain, main_ip, status, handled)
                    conn_cursor.execute(sql)
                    conn.commit()
                    return True

        except Exception as er:
            # generate a error log
            self._log.error("insert_analyzing - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseInsertFailed

    def insert_analyzing_error(self, ticket_id, thread_id, status, handled):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "insert into analyzing(ticket_id, thread_id, status, handled) " \
                                "values('{}', '{}', '{}', '{}')".format(
                        ticket_id, thread_id, status, handled)
                    conn_cursor.execute(sql)
                    conn.commit()
                    return True

        except Exception as er:
            # generate a error log
            self._log.error("insert_analyzing_error -{} - {}".format(self.__class__.__name__, er))
            raise DatabaseInsertFailed

    def insert_check_false(self, ticket_id):
        """
        Make insert in database of the ticket_id data when the complaint server is not hosted on the company
        :param ticket_id: ID of the ticket_id
        :type ticket_id: int
        :return: True on success, False on failure
        :rtype: bool
        """
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "insert into check_false(ticket_id) values('{}')".format(ticket_id)
                    conn_cursor.execute(sql)
                    conn.commit()
                    return True

        except Exception as er:
            # generate a error log
            self._log.error("insert_check_false - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseInsertFailed

    def insert_check_duplicated(self, ticket_id, main_domain):
        try:
            # initialize connection with database
            with closing(self._module_connectdb.connection) as conn:
                # get cursor of the connection
                with closing(conn.cursor()) as conn_cursor:
                    # check if duplicated is set
                    # sql for insert of the data
                    sql = "insert into check_duplicated(ticket_id, main_domain) values('{}', '{}')".format(ticket_id, main_domain)
                    conn_cursor.execute(sql)
                    conn.commit()
                    return True

        except Exception as er:
            # generate a error log
            self._log.error("insert_check_duplicated - {} - {}".format(self.__class__.__name__, er))
            raise DatabaseInsertFailed
