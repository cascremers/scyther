#!/usr/bin/python
#
# Scyther interface error classes
#

#---------------------------------------------------------------------------

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class InputError(Error):
    """Exception raised for errors in the input.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, expression, message):
        self.expression = expression
        self.message = message

class BinaryError(Error):
    """Raised when the Scyther executable is not found.

    Attributes:
        file -- file location at which we should have been able to find it.
    """

    def __init__(self, file):
        self.file = file

    def __str__(self):
        return "Could not find Scyther executable at '%s'" % (self.file)


class UnknownPlatformError(Error):
    """Raised when the platform is not supported yet.

    Attributes:
        platform -- string describing the platform.
    """

    def __init__(self, platform):
        self.platform = platform

    def __str__(self):
        return "The %s platform is currently unsupported." % self.platform
