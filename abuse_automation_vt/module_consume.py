# -*- coding: utf-8 -*-
"""
- Contributors
Elliann Marks <elian.markes@gmail.com>

"""

# libraries
import pika
import json
import time
from abuse_automation.module_log import ModuleLog
from abuse_automation.module_configuration import ModuleConfiguration
from abuse_automation_vt.module_vt import ModuleVT
from abuse_automation.module_exceptions import GeneralError, VTFailed


class ModuleConsume:

    def __init__(self, queue):
        """
        Responsible for initiating the consumption of a specific queue and calling the callback function when a message is received.
        **host** - IP or DNS of the broker
        **user** - user for authentication in broker
        **password** - password for authentication in broker
        **key** - this key validates the authenticity of sender
        :param queue: queue name
        :type queue: String
        :return: error code
        :rtype: integer
        """
        try:
            # call configInit and check return
            self.module_configuration = None
            self.module_log = None
            self.config_init()
            self._log = self.module_log.log
            self._queue = queue
            # get host, key, user and password of the broker
            self._host = self.module_configuration.host_queue
            self._user = self.module_configuration.user_queue
            self._password = self.module_configuration.password_queue
            self._key = self.module_configuration.key(self._queue)
            # create credentials object
            self._credentials = pika.PlainCredentials(self._user, self._password)
            # define none variables
            self._connection = None
            self._channel = None
            self._values = None
            self.module_vt = None

        except Exception as er:
            # generate a error log
            self._log.error("{} - {}".format(self.__class__.__name__, er))
            # exit the application with code 3
            exit(3)

    def config_init(self):
        try:
            # instance module configuration
            self.module_configuration = ModuleConfiguration()
            # instance the ModuleLog class to VT path log (4)
            self.module_log = ModuleLog(self.module_configuration, 3)

        except GeneralError:
            exit(2)

        except Exception as er:
            # only print the error, since moduleLog there isn't instance
            print("config_init - {} - {}".format(self.__class__.__name__, er))
            exit(2)

    def connection(self):
        """
        Responsible for create AMQP connection, define what queue will consume and parameters of the queue.
        **connection** - BlockingConnection instance
        **channel** - channel of the connection
        :return: True in success and False in error
        :rtype: bool
        """
        try:
            # create BlockingConnection instance using pika library
            self._connection = pika.BlockingConnection(pika.ConnectionParameters(host=self._host, credentials=self._credentials, heartbeat=900))
            # define channel variable and parameters of the queue
            self._channel = self._connection.channel()
            self._channel.queue_declare(queue=self._queue, durable=True)
            self._channel.basic_qos(prefetch_count=1)
            self._channel.basic_consume(queue=self._queue, on_message_callback=self.callback)
            return True

        except Exception as er:
            # generate a error log
            self._log.error("VT - {} - {}".format(self.__class__.__name__, er))
            return False

    def consume(self):
        """
        Run start_consuming in channel instance, this is a loop that in case of error, wait 60 seconds and return loop
        """
        while True:
            try:
                # check success in connection
                if self.connection() and self._connection is not None and \
                        self._connection is not False:
                    # run start consuming
                    self._channel.start_consuming()
                else:
                    self._log.info("VT connection failed.")
                    time.sleep(60)

            except Exception as er:
                # generate a error log
                self._log.error("VT consume - {} - {}".format(self.__class__.__name__, er))
                # wait 60 seconds
                time.sleep(60)
                continue

    def callback(self, ch, method, properties, body):
        """
        Responsible for performing moduleVT functions.
        **values** - dict with message value
        """
        try:
            # send ack before treating message
            ch.basic_ack(delivery_tag=method.delivery_tag)
            # load json body in variable values
            self._values = json.loads(body)
            # debug log
            self._log.debug(self._values)
            # check key value in header of the message, this must be equal to the value set in the configuration
            if properties.headers.get("x-key") is not None and \
                    str(properties.headers.get("x-key")) == str(self.module_configuration.key(self._queue)):
                # define values to scan in VirusTotal
                scan_type = self._values.get("scan_type")
                scan_target = self._values.get("scan_target")
                scan_ticket_id = self._values.get("scan_ticket")
                thread_id = self._values.get("thread_id")
                # check if values exists
                if scan_type is not None and scan_target is not None and scan_ticket_id is not None and thread_id is not None:
                    # create ModuleVT instance
                    self.module_vt = ModuleVT(self._log, self.module_configuration)
                    # run process in analyze
                    self.module_vt.process(scan_type, scan_target, scan_ticket_id, thread_id)
                    # info log with values
                    self._log.info("Success in VT process - {}".format(self._values))
                else:
                    # error log with invalid data
                    self._log.error("Invalid data vt - {}".format(self._values))
            else:
                # error log with invalid key
                self._log.error("Invalid key vt - {}".format(self._values))

        except VTFailed:
            return False

        except Exception as er:
            # generate a error log
            self._log.error("VT - {} - {}".format(self.__class__.__name__, er))
            return False


