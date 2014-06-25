# coding=utf-8
"""
PayPalResponse parsing and processing.
"""
try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

import paypal.exceptions 

class PayPalResponse(object):
    """
    Parse and prepare the reponse from PayPal's API. Acts as somewhat of a
    glorified dictionary for API responses.
    
    NOTE: Don't access self.raw directly. Just do something like
    PayPalResponse.someattr, going through PayPalResponse.__getattr__().
    """
    def __init__(self, query_string, config):
        """
        query_string is the response from the API, in NVP format. This is
        parseable by urlparse.parse_qs(), which sticks it into the self.raw
        dict for retrieval by the user.
        """
        # A dict of NVP values. Don't access this directly, use
        # PayPalResponse.attribname instead. See self.__getattr__().
        self.raw = parse_qs(query_string)
        self.config = config

    def __str__(self):
        return str(self.raw)

    def __getattr__(self, key):
        """
        Handles the retrieval of attributes that don't exist on the object
        already. This is used to get API response values.
        """
        # PayPal response names are always uppercase.
        key = key.upper()
        try:
            value = self.raw[key]
            if len(value) == 1:
                return value[0]
            return value
        except KeyError:
            if self.config.KEY_ERROR:
                raise AttributeError(self)
            else:
                return None
                
    def success(self):
        """
        Checks for the presence of errors in the response. Returns True if
        all is well, False otherwise.
        """
        return self.ack.upper() in (self.config.ACK_SUCCESS, 
                                    self.config.ACK_SUCCESS_WITH_WARNING)
    success = property(success)
