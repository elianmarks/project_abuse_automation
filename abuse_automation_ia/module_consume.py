# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 2.0 - 07/08/2019**
**Functions - config_init, connection, consume, callback**
**Libraries - pika, json, time, ModuleLog, ModuleConfiguration, ModuleIA and ModulePublish**
**Dependencies - no**
**Parameters - queue name**

"""

# libraries
import pika
import json
import time
import pickle
from abuse_automation.module_log import ModuleLog
from abuse_automation.module_configuration import ModuleConfiguration
from abuse_automation_ia.module_ia import ModuleIA
from abuse_automation.module_publish import ModulePublish
from abuse_automation.module_exceptions import GeneralError, IAFailed, PublishFailed


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
            self._log = self.module_log.log
            # define none variables
            self._connection = None
            self._channel = None
            self._values = None
            self.mIA = None
            self.mIA_scaler = None
            self.module_ia = None
            # create ModulePublish instance to IA queue
            self.queue_zenapply = ModulePublish(self.module_log.log, "zenapply", self.module_configuration.user_queue, self.module_configuration.password_queue,
                                                    self.module_configuration.host_queue, self.module_configuration.key("zenapply"))
            if self.module_configuration.application == "production" or \
                    self.module_configuration.application == "development":
                # instance model IA
                try:
                    self.file_mIA = open(self.module_configuration.mIA, "rb")
                    self.mIA, self.mIA_scaler = pickle.load(self.file_mIA)
                    self.file_mIA.close()

                except Exception as er:
                    # generate a error log
                    self._log.error("{} - {}".format(self.__class__.__name__, er))
                    # exit the application with code 4
                    exit(1)

        except Exception as er:
            # generate a error log
            self._log.error("{} - {}".format(self.__class__.__name__, er))
            # exit the application with code 3
            exit(3)

    def config_init(self):
        try:
            # instance module configuration
            self.module_configuration = ModuleConfiguration()
            # instance the ModuleLog class to IA path log (4)
            self.module_log = ModuleLog(self.module_configuration, 4)

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
            self._log.error("IA - {} - {}".format(self.__class__.__name__, er))
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
                    self._log.info("IA connection failed.")
                    time.sleep(60)

            except Exception as er:
                # generate a error log
                self._log.error("IA consume - {} - {}".format(self.__class__.__name__, er))
                # wait 60 seconds
                time.sleep(60)
                continue

    def callback(self, ch, method, properties, body):
        """
        Responsible for performing module_ia functions.
        **values** - dict with message value
        """
        try:
            self.queue_zenapply.check_send = False
            # send ack before treating message
            ch.basic_ack(delivery_tag=method.delivery_tag)
            # load json body in variable values
            self._values = json.loads(body)
            # debug log
            self._log.debug(self._values)
            # check key value in header of the message, this must be equal to the value set in the configuration
            if properties.headers.get("x-key") is not None and \
                    str(properties.headers.get("x-key")) == str(self.module_configuration.key(self._queue)):
                if self._values['general_error']:
                    self._log.info("General error is true - {}".format(self._values))
                    self.queue_zenapply.publish(dict(ticket_id=self._values.get('ticket_id'),
                                                     thread_id=self._values.get('thread_id'),
                                                     brand=self._values.get('brand'),
                                                     general_error=True))
                    return False
                else:
                    # create ModuleIA instance
                    self.module_ia = ModuleIA(self.module_log.log, self.module_configuration, self._values)
                    self.module_ia.process(self.mIA, self.mIA_scaler)
                    # publish result in queue Zenapply
                    self.queue_zenapply.publish(self.module_ia.result_dict)
                    # info log with message send to Zenapply
                    self._log.info("Send result in queue Zenapply - {}".format(self.module_ia.result_dict))
                    return True
            else:
                # error log with invalid key
                self._log.error("Invalid key IA - {}".format(self._values))
                return False

        except PublishFailed:
            self._log.error("IA Publish Failed - {}".format(self.module_ia.result_dict))
            return False

        except IAFailed:
            return False

        except Exception as er:
            # generate a error log
            self._log.error("IA callback - {} - {}".format(self.__class__.__name__, er))
            return False

        finally:
            if not self.queue_zenapply.check_send:
                self.queue_zenapply.publish(dict(ticket_id=self._values.get('ticket_id'),
                                                 thread_id=self._values.get('thread_id'),
                                                 brand=self._values.get('brand'),
                                                 general_error=True))
                self._log.info("IA send error message - {}".format(self._values.get('ticket_id')))
            return False
