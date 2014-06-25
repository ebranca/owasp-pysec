# coding=utf-8
"""
The end developer will do most of their work with the PayPalInterface class found
in this module. Configuration, querying, and manipulation can all be done
with it.
"""

import types
import socket
import urllib
import urllib2

from paypal.settings import PayPalConfig
from paypal.response import PayPalResponse
from paypal.exceptions import PayPalError, PayPalAPIResponseError
   
class PayPalInterface(object):
    """
    The end developers will do 95% of their work through this class. API
    queries, configuration, etc, all go through here. See the __init__ method
    for config related details.
    """
    def __init__(self , config=None, **kwargs):
        """
        Constructor, which passes all config directives to the config class
        via kwargs. For example:
        
            paypal = PayPalInterface(API_USERNAME='somevalue')
            
        Optionally, you may pass a 'config' kwarg to provide your own
        PayPalConfig object.
        """
        if config:
            # User provided their own PayPalConfig object.
            self.config = config
        else:
            # Take the kwargs and stuff them in a new PayPalConfig object.
            self.config = PayPalConfig(**kwargs)
        
    def _encode_utf8(self, **kwargs):
        """
        UTF8 encodes all of the NVP values.
        """
        unencoded_pairs = kwargs
        for i in unencoded_pairs.keys():
            if isinstance(unencoded_pairs[i], types.UnicodeType):
                unencoded_pairs[i] = unencoded_pairs[i].encode('utf-8')
        return unencoded_pairs
    
    def _check_required(self, requires, **kwargs):
        """
        Checks kwargs for the values specified in 'requires', which is a tuple
        of strings. These strings are the NVP names of the required values.
        """
        for req in requires:
            # PayPal api is never mixed-case.
            if req.lower() not in kwargs and req.upper() not in kwargs:
                raise PayPalError('missing required : %s' % req)
        
    def _call(self, method, **kwargs):
        """
        Wrapper method for executing all API commands over HTTP. This method is
        further used to implement wrapper methods listed here:
    
        https://www.x.com/docs/DOC-1374
    
        ``method`` must be a supported NVP method listed at the above address.
    
        ``kwargs`` will be a hash of
        """
        socket.setdefaulttimeout(self.config.HTTP_TIMEOUT)
    
        url_values = {
            'METHOD': method,
            'VERSION': self.config.API_VERSION
        }
    
        headers = {}
        if(self.config.API_AUTHENTICATION_MODE == "3TOKEN"):
            # headers['X-PAYPAL-SECURITY-USERID'] = API_USERNAME
            # headers['X-PAYPAL-SECURITY-PASSWORD'] = API_PASSWORD
            # headers['X-PAYPAL-SECURITY-SIGNATURE'] = API_SIGNATURE
            url_values['USER'] = self.config.API_USERNAME
            url_values['PWD'] = self.config.API_PASSWORD
            url_values['SIGNATURE'] = self.config.API_SIGNATURE
        elif(self.config.API_AUTHENTICATION_MODE == "UNIPAY"):
            # headers['X-PAYPAL-SECURITY-SUBJECT'] = SUBJECT
            url_values['SUBJECT'] = self.config.SUBJECT
        # headers['X-PAYPAL-REQUEST-DATA-FORMAT'] = 'NV'
        # headers['X-PAYPAL-RESPONSE-DATA-FORMAT'] = 'NV'
        # print(headers)

        for key, value in kwargs.iteritems():
            url_values[key.upper()] = value
        
        # When in DEBUG level 2 or greater, print out the NVP pairs.
        if self.config.DEBUG_LEVEL >= 2:
            k = url_values.keys()
            k.sort()
            for i in k:
                print " %-20s : %s" % (i , url_values[i])

        url = self._encode_utf8(**url_values)

        data = urllib.urlencode(url)
        req = urllib2.Request(self.config.API_ENDPOINT, data, headers)
        response = PayPalResponse(urllib2.urlopen(req).read(), self.config)

        if self.config.DEBUG_LEVEL >= 1:
            print " %-20s : %s" % ("ENDPOINT", self.config.API_ENDPOINT)
    
        if not response.success:
            if self.config.DEBUG_LEVEL >= 1:
                print response
            raise PayPalAPIResponseError(response)

        return response

    def address_verify(self, email, street, zip):
        """Shortcut for the AddressVerify method.
    
        ``email``::
            Email address of a PayPal member to verify.
            Maximum string length: 255 single-byte characters
            Input mask: ?@?.??
        ``street``::
            First line of the billing or shipping postal address to verify.
    
            To pass verification, the value of Street must match the first three
            single-byte characters of a postal address on file for the PayPal member.
    
            Maximum string length: 35 single-byte characters.
            Alphanumeric plus - , . ‘ # \
            Whitespace and case of input value are ignored.
        ``zip``::
            Postal code to verify.
    
            To pass verification, the value of Zip mustmatch the first five
            single-byte characters of the postal code of the verified postal
            address for the verified PayPal member.
    
            Maximumstring length: 16 single-byte characters.
            Whitespace and case of input value are ignored.
        """
        args = locals()
        del args['self']
        return self._call('AddressVerify', **args)

    def do_authorization(self, transactionid, amt):
        """Shortcut for the DoAuthorization method.
    
        Use the TRANSACTIONID from DoExpressCheckoutPayment for the
        ``transactionid``. The latest version of the API does not support the
        creation of an Order from `DoDirectPayment`.
    
        The `amt` should be the same as passed to `DoExpressCheckoutPayment`.
    
        Flow for a payment involving a `DoAuthorization` call::
    
             1. One or many calls to `SetExpressCheckout` with pertinent order
                details, returns `TOKEN`
             1. `DoExpressCheckoutPayment` with `TOKEN`, `PAYMENTACTION` set to
                Order, `AMT` set to the amount of the transaction, returns
                `TRANSACTIONID`
             1. `DoAuthorization` with `TRANSACTIONID` and `AMT` set to the
                amount of the transaction.
             1. `DoCapture` with the `AUTHORIZATIONID` (the `TRANSACTIONID`
                returned by `DoAuthorization`)
    
        """
        args = locals()
        del args['self']
        return self._call('DoAuthorization', **args)

    def do_capture(self, authorizationid, amt, completetype='Complete', **kwargs):
        """Shortcut for the DoCapture method.
    
        Use the TRANSACTIONID from DoAuthorization, DoDirectPayment or
        DoExpressCheckoutPayment for the ``authorizationid``.
    
        The `amt` should be the same as the authorized transaction.
        """
        kwargs.update(locals())
        del kwargs['self']
        return self._call('DoCapture', **kwargs)

    def do_direct_payment(self, paymentaction="Sale", **kwargs):
        """Shortcut for the DoDirectPayment method.
    
        ``paymentaction`` could be 'Authorization' or 'Sale'
    
        To issue a Sale immediately::
    
            charge = {
                'amt': '10.00',
                'creditcardtype': 'Visa',
                'acct': '4812177017895760',
                'expdate': '012010',
                'cvv2': '962',
                'firstname': 'John',
                'lastname': 'Doe',
                'street': '1 Main St',
                'city': 'San Jose',
                'state': 'CA',
                'zip': '95131',
                'countrycode': 'US',
                'currencycode': 'USD',
            }
            direct_payment("Sale", **charge)
    
        Or, since "Sale" is the default:
    
            direct_payment(**charge)
    
        To issue an Authorization, simply pass "Authorization" instead of "Sale".
    
        You may also explicitly set ``paymentaction`` as a keyword argument:
    
            ...
            direct_payment(paymentaction="Sale", **charge)
        """
        kwargs.update(locals())
        del kwargs['self']
        return self._call('DoDirectPayment', **kwargs)

    def do_void(self, authorizationid, note=''):
        """Shortcut for the DoVoid method.
    
        Use the TRANSACTIONID from DoAuthorization, DoDirectPayment or
        DoExpressCheckoutPayment for the ``authorizationid``.
        """
        args = locals()
        del args['self']
        return self._call('DoVoid', **args)

    def get_express_checkout_details(self, token):
        """Shortcut for the GetExpressCheckoutDetails method.
        """
        return self._call('GetExpressCheckoutDetails', token=token)
        
    def get_transaction_details(self, transactionid):
        """Shortcut for the GetTransactionDetails method.
    
        Use the TRANSACTIONID from DoAuthorization, DoDirectPayment or
        DoExpressCheckoutPayment for the ``transactionid``.
        """
        args = locals()
        del args['self']
        return self._call('GetTransactionDetails', **args)

    def set_express_checkout(self, token='', **kwargs):
        """Shortcut for the SetExpressCheckout method.
            JV did not like the original method. found it limiting.
        """
        kwargs.update(locals())
        del kwargs['self']
        self._check_required(('amt',), **kwargs)
        return self._call('SetExpressCheckout', **kwargs)

    def do_express_checkout_payment(self, token, **kwargs):
        """Shortcut for the DoExpressCheckoutPayment method.
        
            Required
                *TOKEN
                PAYMENTACTION
                PAYERID
                AMT
                
            Optional
                RETURNFMFDETAILS
                GIFTMESSAGE
                GIFTRECEIPTENABLE
                GIFTWRAPNAME
                GIFTWRAPAMOUNT
                BUYERMARKETINGEMAIL
                SURVEYQUESTION
                SURVEYCHOICESELECTED
                CURRENCYCODE
                ITEMAMT
                SHIPPINGAMT
                INSURANCEAMT
                HANDLINGAMT
                TAXAMT

            Optional + USEFUL
                INVNUM - invoice number
                
        """
        kwargs.update(locals())
        del kwargs['self']
        self._check_required(('paymentaction', 'payerid'), **kwargs)
        return self._call('DoExpressCheckoutPayment', **kwargs)
        
    def generate_express_checkout_redirect_url(self, token):
        """Submit token, get redirect url for client."""
        url_vars = (self.config.PAYPAL_URL_BASE, token)
        return "%s?cmd=_express-checkout&token=%s" % url_vars
    
    def generate_cart_upload_redirect_url(self, **kwargs):
        """https://www.sandbox.paypal.com/webscr 
            ?cmd=_cart
            &upload=1
        """
        required_vals = ('business', 'item_name_1', 'amount_1', 'quantity_1')
        self._check_required(required_vals, **kwargs)
        url = "%s?cmd=_cart&upload=1" % self.config.PAYPAL_URL_BASE
        additional = self._encode_utf8(**kwargs)
        additional = urllib.urlencode(additional)
        return url + "&" + additional
