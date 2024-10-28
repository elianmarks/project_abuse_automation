# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 01 - 02/02/2019**

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

"""

# libraries
import configparser
from abuse_automation.module_exceptions import GeneralError


class ModuleConfiguration:

    def __init__(self):
        try:
            self.environment_config = None
            self.environment_log = None
            self._configuration = None
            self._configuration_file = None
            # create instance of ConfigParser
            self._configuration = configparser.ConfigParser()
            # path of the configuration file
            self._configuration_file = "/opt/abuse/files/abuse.conf"
            # load configuration file
            self._configuration.read(self._configuration_file)
            self.application = self._configuration.get("environment", "application")
            if self.application is False:
                raise GeneralError
            else:
                self.environment_config = "config_" + self.application
                self.environment_log = "logger"

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    @property
    def environment(self):
        """
        Get log file in configuration file.
        :return: Log file on success, False on failure
        :rtype: string or bool
        """
        try:
            # return o path of the log file
            return self._configuration.get("environment", "application")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def log_level(self):
        """
        Get log level in configuration file.
        :return: Value log level on success, False on failure
        :rtype: int or bool
        """
        try:
            # check string of log level configured and return ID corresponding to the level
            if str(self._configuration.get(self.environment_log, "loglevel")) == "logging.CRITICAL":
                # 50 is critical level
                return 50
            elif str(self._configuration.get(self.environment_log, "loglevel")) == "logging.ERROR":
                # 40 is error level
                return 40
            elif str(self._configuration.get(self.environment_log, "loglevel")) == "logging.WARNING":
                # 30 is warning level
                return 30
            elif str(self._configuration.get(self.environment_log, "loglevel")) == "logging.INFO":
                # 20 is info level
                return 20
            elif str(self._configuration.get(self.environment_log, "loglevel")) == "logging.DEBUG":
                # 10 is debug level
                return 10
            else:
                # default value for log level
                return 40

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def log_file_main(self):
        """
        Get log file in configuration file.
        :return: Log file on success, False on failure
        :rtype: string or bool
        """
        try:
            # return o path of the log file
            return self._configuration.get(self.environment_log, "logfilemain")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def log_file_analyze(self):
        """
        Get log file in configuration file.
        :return: Log file on success, False on failure
        :rtype: string or bool
        """
        try:
            # return o path of the log file
            return self._configuration.get(self.environment_log, "logfileanalyze")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def log_file_vt(self):
        """
        Get log file in configuration file.
        :return: Log file on success, False on failure
        :rtype: string or bool
        """
        try:
            # return o path of the log file
            return self._configuration.get(self.environment_log, "logfilevt")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def log_file_ia(self):
        """
        Get log file in configuration file.
        :return: Log file on success, False on failure
        :rtype: string or bool
        """
        try:
            # return o path of the log file
            return self._configuration.get(self.environment_log, "logfileia")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def log_file_zenapply(self):
        """
        Get log file in configuration file.
        :return: Log file on success, False on failure
        :rtype: string or bool
        """
        try:
            # return o path of the log file
            return self._configuration.get(self.environment_log, "logfilezenapply")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def file_generate_model(self):
        try:
            return self._configuration.get(self.environment_config, "filegeneratemodel")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def file_result_model(self):
        try:
            return self._configuration.get(self.environment_config, "fileresultmodel")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def timeout_report(self):
        """
        Get timeout of the report virus total in configuration file.
        :return: Time on success, False on failure
        :rtype: int or bool
        """
        try:
            # return value of timeout that is used in wait for virustotal finish a scan
            return self._configuration.get(self.environment_config, "timeoutreport")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def host_queue(self):
        try:
            return self._configuration.get(self.environment_config, "hostqueue")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def report_dir(self):
        try:
            return self._configuration.get(self.environment_config, "reportdir")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def report_prints(self):
        try:
            return self._configuration.get(self.environment_config, "reportprints")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def report_backups(self):
        try:
            return self._configuration.get(self.environment_config, "reportbackups")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def playbook_check(self):
        try:
            return self._configuration.get(self.environment_config, "playbookcheck")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def playbook_scan(self):
        try:
            return self._configuration.get(self.environment_config, "playbookscan")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def playbook_abuse(self):
        try:
            return self._configuration.get(self.environment_config, "playbookabuse")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def playbook_block(self):
        try:
            return self._configuration.get(self.environment_config, "playbookblock")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def playbook_backup(self):
        try:
            return self._configuration.get(self.environment_config, "playbookbackup")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def private_key_path_abuse(self):
        try:
            return self._configuration.get(self.environment_config, "privatekeypathabuse")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def api_example(self):
        try:
            return self._configuration.get(self.environment_config, "apiexample")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def report_action_dir(self):
        try:
            return self._configuration.get(self.environment_config, "reportactiondir")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def private_key_path_all(self):
        try:
            return self._configuration.get(self.environment_config, "privatekeypathall")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def inventory_path(self):
        try:
            return self._configuration.get(self.environment_config, "inventorypath")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def ansible_roles(self):
        try:
            return self._configuration.get(self.environment_config, "ansibleroles")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def mIA(self):
        try:
            return self._configuration.get(self.environment_config, "modelmia")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def ip_db(self):
        try:
            return self._configuration.get(self.environment_config, "ipdb")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def user_db(self):
        try:
            return self._configuration.get(self.environment_config, "userdb")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def pass_db(self):
        try:
            return self._configuration.get(self.environment_config, "passdb")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def database(self):
        try:
            return self._configuration.get(self.environment_config, "database")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def database_vps_dedi(self):
        try:
            return self._configuration.get(self.environment_config, "databasevpsdedi")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def regex_file(self):
        try:
            return self._configuration.get(self.environment_config, "regexfile")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def network_file(self):
        try:
            return self._configuration.get(self.environment_config, "networkfile")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def abuse_server(self):
        try:
            return self._configuration.get(self.environment_config, "abuseserver")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def abuse_port(self):
        try:
            return self._configuration.get(self.environment_config, "abuseport")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def token(self):
        try:
            return self._configuration.get(self.environment_config, "token")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def token_es(self):
        try:
            return self._configuration.get(self.environment_config, "tokenes")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def domain(self):
        try:
            return self._configuration.get(self.environment_config, "domain")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def domain_es(self):
        try:
            return self._configuration.get(self.environment_config, "domaines")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def whmcs_user_info(self):
        try:
            return self._configuration.get(self.environment_config, "whmcsuserinfo")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def whmcs_cpanel_password(self):
        try:
            return self._configuration.get(self.environment_config, "whmcscpanelpasssword")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def user_queue(self):
        try:
            return self._configuration.get(self.environment_config, "userqueue")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def password_queue(self):
        try:
            return self._configuration.get(self.environment_config, "passwordqueue")

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False

    def key(self, queue):
        try:
            if queue == "vt":
                return self._configuration.get(self.environment_config, "keyvt")
            elif queue == "analyze":
                return self._configuration.get(self.environment_config, "keyanalyze")
            elif queue == "ia":
                return self._configuration.get(self.environment_config, "keyia")
            elif queue == "zenapply":
                return self._configuration.get(self.environment_config, "keyzenapply")
            else:
                return False

        except Exception as er:
            # only print the error, since moduleLog there isn't instance in ModuleConfiguration class
            print("{} - {}".format(self.__class__.__name__, er))
            return False
