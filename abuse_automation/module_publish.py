# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 02 - 28/07/2019**

**- Version 03 - 18/12/2019**

# Docker command environment production
docker run -d --hostname abusequeue --name abuse-rabbitmq -p 15672:15672 -p 5672:5672 -e RABBITMQ_DEFAULT_USER=abuse -e RABBITMQ_DEFAULT_PASS=XXX --restart always rabbitmq:3-management

"""

# libraries
import pika
import json
from abuse_automation.module_exceptions import PublishFailed


class ModulePublish:

    def __init__(self, module_log, queue, user, password, host, key):
        """
        """
        self._log = module_log
        self._key = key
        self._host = host
        self._user = user
        self._password = password
        self._queue = queue
        self._credentials = pika.PlainCredentials(self._user, self._password)
        self._connection = None
        self._channel = None
        self.message = None
        self.check_send = False

    @property
    def connection(self):
        try:
            self._connection = pika.BlockingConnection(pika.ConnectionParameters(host=self._host, credentials=self._credentials, heartbeat=900))
            self._channel = self._connection.channel()
            self._channel.queue_declare(queue=self._queue, durable=True)
            return True

        except Exception as er:
            # generate a error log
            self._log.error("{} - {}".format(self.__class__.__name__, er))
            return False

    def publish(self, message):
        try:
            if self.connection:
                self.message = json.dumps(message)
                self._channel.basic_publish(
                    exchange="",
                    routing_key=self._queue,
                    body=self.message,
                    properties=pika.BasicProperties(
                        delivery_mode=2,
                        headers={
                            "x-key": self._key
                        }
                    )
                )
                self.check_send = True
                return True
            else:
                raise PublishFailed

        except Exception as er:
            self._log.error("{} - {}".format(self.__class__.__name__, er))
            raise PublishFailed
