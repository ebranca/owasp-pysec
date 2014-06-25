# coding=utf-8
"""
Various PayPal API related exceptions.
"""

class PayPalError(Exception):
    """
    Used to denote some kind of generic error. This does not include errors
    returned from PayPal API responses. Those are handled by the more
    specific exception classes below.
    """
    def __init__(self, message, error_code=None):
        self.message = message
        self.error_code = error_code

    def __str__(self):
        if self.error_code:
            return "%s (Error Code: %s)" % (repr(self.message), self.error_code)
        else:
            return repr(self.message)
        
    def _get_message(self): 
        """
        get the message from error
        """
        return self._message

    def _set_message(self, message): 
        """
        set the message from error
        """
        self._message = message
        
    message = property(_get_message, _set_message)


class PayPalConfigError(PayPalError):
    """
    Raised when a configuration problem arises.
    """
    pass


class PayPalAPIResponseError(PayPalError):
    """
    Raised when there is an error coming back with a PayPal NVP API response.
    
    Pipe the error message from the API to the exception, along with
    the error code.
    """
    def __init__(self, response):
        self.response = response
        self.error_code = int(response.L_ERRORCODE0)
        self.message = response.L_LONGMESSAGE0
        self.short_message = response.L_SHORTMESSAGE0
        self.correlation_id = response.CORRELATIONID
