# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 01 - 03/02/2019**

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

"""

# libraries
from datetime import datetime
from dateutil import relativedelta
import time


class ModuleDates:

    def __init__(self, module_log):
        """
        :param module_log: Instance of the log class
        :type module_log: object
        """
        self._log = module_log
        self.value_date = None
        self.value_hour = None
        self.value_now_date = None
        self.value_old_date = None
        self.value_convert = None

    @property
    def hour(self):
        """
        :return: current time in "%H:%M:%S" format on success, False on failure
        :rtype: string or bool
        """
        try:
            return str(time.strftime("%H:%M:%S"))

        except Exception as er:
            self._log.error("hour - {} - {}".format(self.__class__.__name__, er))
            return False

    @property
    def date(self):
        """
        :return: current date in "%Y-%m-%d" format on success, False on failure
        :rtype: string or bool
        """
        try:
            return str(time.strftime("%Y-%m-%d"))

        except Exception as er:
            self._log.error("date - {} - {}".format(self.__class__.__name__, er))
            return False

    def date_complete(self, value_date = False, value_hour = False):
        """
        Joins date and hour for datetime object with "%Y-%m-%d %H:%M:%S" format.
        :param value_date: If set, will use for date. If not set, will use current date
        :type value_date: string
        :param value_hour: If set, will use for time. If not set, will use current date
        :type value_hour: string
        :return: Datetime object with values of the params or current datetime in system on success,
                False on failure
        :rtype: datetime or bool
        """
        try:
            if value_date is False:
                self.value_date = self.date
            else:
                self.value_date = value_date

            if value_hour is False:
                self.value_hour = self.hour
            else:
                self.value_hour = value_hour

            return datetime.strptime(str(self.value_date + " " + self.value_hour), "%Y-%m-%d %H:%M:%S")

        except Exception as er:
            self._log.error("date_complete -{} - {}".format(self.__class__.__name__, er))
            return False

    def calculate_dates(self, value_old_date, value_now_date = False):
        """
        Make the calcule between two dates.
        :param value_old_date: Use for calculate difference between dates, this is required
        :type value_old_date: datetime
        :param value_now_date: If set, will use for calculate difference between dates.
            If not set, will use current datetime of the system
        :type value_now_date: datetime
        :return: Relativedelta object with difference between params datetime received on success,
            False on failure
        :rtype: object or bool
        """
        try:
            if value_now_date is False:
                self.value_now_date = self.date_complete()
            else:
                self.value_now_date = value_now_date

            self.value_old_date = value_old_date
            return relativedelta.relativedelta(self.value_now_date, self.value_old_date)

        except Exception as er:
            self._log.error("calculate_dates - {} - {}".format(self.__class__.__name__, er))
            return False

    def convert_date(self, value_convert):
        """
        Make the convertion of a string in format "%Y%m%d" to "%Y-%m-%d %H:%M:%S" in datetime object
        :param value_convert: date in string format "%Y%m%d"
        :type value_convert: string
        :return: Datetime object with value of the date received on success, False on failure
        :rtype: datetime or bool
        """
        try:
            self.value_convert = value_convert
            return datetime.strptime(str(datetime.strptime(self.value_convert, "%Y%m%d").strftime("%Y-%m-%d %H:%M:%S")), "%Y-%m-%d %H:%M:%S")

        except Exception as er:
            self._log.error("convert_date - {} - {}".format(self.__class__.__name__, er))
            return False
