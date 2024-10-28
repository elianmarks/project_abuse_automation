#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 1.0 - 08/02/2019**

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

Format of the file generate model
ticket_id,thread_id,main_domain

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
        if module_main.module_configuration.application == "model":
            content_generate_model = open(module_main.module_configuration.file_generate_model, "r")
            # enter in loop
            for content_model in content_generate_model.read().splitlines():
                ticket_id = content_model.split(",")[0]
                thread_id = content_model.split(",")[1]
                main_domain = content_model.split(",")[2]
                # call processTickets function
                if not module_main.process_generate_model(ticket_id, thread_id, main_domain):
                    print("Failed in content - {} - {} - {}".format(ticket_id, thread_id, main_domain))
                    exit(2)
                # sleep for 3 seconds
                time.sleep(0.2)
            content_generate_model.close()
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
