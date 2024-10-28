# -*- coding: utf-8 -*-
"""
- Contributors
Elliann Marks <elian.markes@gmail.com>

"""

# libraries
import requests
import time
from abuse_automation.module_database import ModuleDatabase
from abuse_automation.module_exceptions import VTFailed, GeneralError, DatabaseUpdateFailed


class ModuleVT:

    def __init__(self, module_log, module_configuration):
        """

        :param module_log: object
        :param module_configuration: object
        """
        try:
            self._log = module_log
            self._module_configuration = module_configuration
            # instance of the ModuleDatabase
            self._module_database = ModuleDatabase(module_log, self._module_configuration)
            self.status_vt = "status_vt"
            self.positives_vt = "positives_vt"
            self.scan_vt = "scan_vt"
            # environment of prod
            self._api_key = "XXXXXXXXX"
            # URLs for checking
            self._scan_to_url = "https://www.virustotal.com/vtapi/v2/url/scan"
            self._scan_to_file = "https://www.virustotal.com/vtapi/v2/file/scan"
            self._report_to_url = "http://www.virustotal.com/vtapi/v2/url/report"
            self._report_to_file = "https://www.virustotal.com/vtapi/v2/file/report"
            # headers requires
            self._headers = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  Abuse Automation Check"
            }
            self._timeout_report = int(self._module_configuration.timeout_report)
            self.resource_file = None

        except Exception as er:
            self._log.error("VT - {} - {}".format(self.__class__.__name__, er))
            raise VTFailed

    def process(self, scan_type, scan_target, scan_ticket_id, thread_id):
        try:
            scan_type = scan_type
            scan_target = scan_target
            scan_ticket_id = scan_ticket_id
            thread_id = thread_id
            count_report = 0
            time.sleep(61)
            # check type of the scan
            if scan_type == 1:
                # scanID format is sha256-timestamp
                scan_id = self.scan_url(scan_target)
                if scan_id is not False and scan_id is not None:
                    time.sleep(10)
                    # insert scan data in database
                    self._module_database.update_analyzing(self.scan_vt, scan_id, thread_id)
                    # wait 5 seconds
                    time.sleep(5)
                    # while for check if occurrence a timeout report
                    while count_report <= self._timeout_report:
                        positives_count = self.report_url(scan_target)
                        if positives_count is not None and positives_count is not False:
                            # update scan data in database
                            self._module_database.update_analyzing(self.status_vt, 1, thread_id)
                            self._module_database.update_analyzing(self.positives_vt, positives_count, thread_id)
                        else:
                            self._log.debug("Wait result VT")
                            time.sleep(61)
                            # add timeout counter
                            count_report += 1
                self._log.info("Error in scan VT {} - {}".format(scan_ticket_id, scan_target))
                # update scan data in database with fail in get scan result
                self._module_database.update_analyzing(self.status_vt, 2, thread_id)
            # check type of the scan
            elif scan_type == 2:
                scan_id = self.scan_file(scan_target)
                if scan_id is not False and scan_id is not None:
                    time.sleep(10)
                    # insert scan data in database
                    self._module_database.update_analyzing(self.scan_vt, scan_id, thread_id)
                    # wait 5 seconds
                    time.sleep(5)
                    # while for check if occurrence a timeout report
                    while count_report <= self._timeout_report:
                        positives_count = self.report_file()
                        if positives_count is not None and positives_count is not False:
                            # update scan data in database
                            self._module_database.update_analyzing(self.status_vt, 1, thread_id)
                            self._module_database.update_analyzing(self.positives_vt, positives_count, thread_id)
                        else:
                            time.sleep(61)
                            # add timeout counter
                            count_report += 1
                # update scan data in database with fail in get scan result
                self._module_database.update_analyzing(self.status_vt, 2, thread_id)

        except DatabaseUpdateFailed:
            raise VTFailed

        except GeneralError:
            raise VTFailed

        except Exception as er:
            # generate a error log
            self._log.error("process - {} - {}".format(self.__class__.__name__, er))
            raise VTFailed

    def report_url(self, scan_target):
        """
        Get a report of a URL scan
        :return: number of positivies
        """
        try:
            # create and execute resquest
            params = {'apikey': self._api_key, 'resource': scan_target}
            result_temp = requests.post(self._report_to_url, params=params, headers=self._headers, verify=False)
            result = result_temp.json()
            return result.get('positives')

        except Exception as er:
            # generate a error log
            self._log.error("report_url - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def report_file(self):
        """
        Get a report of a file scan
        :return: number of positivies
        """
        try:
            # create and execute resquest
            params = {'apikey': self._api_key, 'resource': self.resource_file}
            result_temp = requests.post(self._report_to_file, params=params, headers=self._headers, verify=False)
            result = result_temp.json()
            return result.get('positives')

        except Exception as er:
            # generate a error log
            self._log.error("report_file - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def scan_url(self, scan_target):
        """
        Make a scan of an URL in virustotal API
        :return: ID of the scan on success, False on failure
        """
        try:
            # create header for POST request
            params = {'apikey': self._api_key, 'url': scan_target}
            # execute POST request
            result_temp = requests.post(self._scan_to_url, params=params, headers=self._headers, verify=False)
            # get result of the scan
            result = result_temp.json()
            # check if scan_id is not None
            if result.get('scan_id') is not None:
                # return id of the scan
                self._log.info("Success scan_url - {}".format(result.get('scan_id')))
                return result.get('scan_id')
            else:
                # return None for scanID
                self._log.info("Failed scan_url - {}".format(scan_target))
                return None

        except Exception as er:
            # generate a error log
            self._log.error("scan_url - {} - {} - {}".format(self.__class__.__name__, scan_target, er))
            return False

    def scan_file(self, scan_target):
        """
        Make a scan of a file in virustotal API
        :return: ID of the scan on success, False on failure
        """
        try:
            # create header for POST request
            params = {'apikey': self._api_key}
            # open file in binary mode
            files = {'file': (str(scan_target.split("/")[-1]), open(scan_target, 'rb'))}
            # execute POST request
            result_temp = requests.post(self._scan_to_file, files=files, params=params, verify=False)
            # get result of the scan
            result = result_temp.json()
            # check if scan_id and resource is not None
            if result.get('scan_id') is not None and result.get('resource') is not None:
                # store resource
                self.resource_file = str(result.get('resource'))
                # return id of the scan
                return result.get('scan_id')
            else:
                # return None for scanID
                self._log.info("Failed scan_file - {}".format(scan_target))
                return None

        except Exception as er:
            # generate a error log
            self._log.error("scan_file - {} - {} - {}".format(self.__class__.__name__, scan_target, er))
            raise GeneralError
