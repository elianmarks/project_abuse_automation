#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 2.0 - 29/07/2019**

**- Version 3.0 - 18/12/2019**

"""

# custom libraries
from abuse_automation_analyze.module_consume import ModuleConsume


def main():
    """
    **Main function, this instance ModuleConsume class and call consume function.**
    Error generate a exit with code 1.
    """
    try:
        # create ModuleConsume instance
        module_consume = ModuleConsume("analyze")
        # call consume function
        module_consume.consume()

    except Exception as er:
        # only print the error, since moduleLog there isn't instance in main function
        print("{} - {}".format(__name__, er))
        # exit the application
        exit(1)

if __name__ == '__main__':
    # call function main
    main()
