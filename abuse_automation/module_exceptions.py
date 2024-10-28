# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 3.0 - 18/12/2019**

"""

class Error(Exception):
   pass

class DatabaseFailed(Error):
    pass

class DatabaseSelectFailed(Error):
    pass

class DatabaseUpdateFailed(Error):
    pass

class DatabaseInsertFailed(Error):
    pass

class GeneralError(Error):
    pass

class PublishFailed(Error):
    pass

class ZenFailed(Error):
    pass

class ZenConnectionFailed(Error):
    pass

class ZenRollback(Error):
    pass

class ContinueError(Error):
    pass

class BrandFailed(Error):
    pass

class AnalyzeFailed(Error):
    pass

class ResultFailed(Error):
    pass

class FileResultFailed(Error):
    pass

class GraphQLFailed(Error):
    pass

class IAFailed(Error):
    pass

class NormalizeFailed(Error):
    pass

class VTFailed(Error):
    pass

class TemplatesFailed(Error):
    pass

class ZenapplyFailed(Error):
    pass

class AnsibleScanFailed(Error):
    pass