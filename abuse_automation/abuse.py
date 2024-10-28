#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 1.0 - 08/02/2019**

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

"""

# custom libraries
from abuse_automation.module_main import ModuleMain
import time


def main():
    """
    **Principal loop, instance moduleMain and enter in loop for execution of processTickets function.**
    Sleep for 600 seconds.
    Error generate a exit with code 1.
    """
    try:
        # create ModuleMain instance
        module_main = ModuleMain()
        # enter in loop
        while True:
            if module_main.module_configuration.application == "development" or \
                module_main.module_configuration.application == "production":
                # call processTickets function
                module_main.process_tickets(brand="br")
                module_main.process_tickets(brand="es")
                module_main.module_log.log.info("Entering in sleep for 10 minutes")
                # sleep for 600 seconds
                time.sleep(600)
            else:
                module_main.module_log.log.info("Invalid environment application.")
                exit(1)

    except Exception as er:
        # only print the error, since moduleLog there isn't instance in main function
        print("main - {} - {}".format(__name__, er))
        # sleep 10 seconds and exit the application
        exit(1)

if __name__ == '__main__':
    # call function main
    main()
