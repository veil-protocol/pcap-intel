"""
AUTH ENGINE - Protocol Handlers

Each handler implements AuthProtocolHandler for a specific auth protocol.
Adding a new protocol = adding a new handler file here.

Current handlers:
    - ntlm.py: NTLMv1, NTLMv2, NTLM-over-HTTP
    - kerberos.py: AS-REQ/REP, TGS-REQ/REP, Kerberoasting
    - http.py: Basic, Digest, Bearer, OAuth
    - ldap.py: Simple bind, SASL
"""

from .ntlm import NTLMHandler
from .kerberos import KerberosHandler
from .http import HTTPAuthHandler
from .ldap import LDAPBindHandler

__all__ = [
    "NTLMHandler",
    "KerberosHandler",
    "HTTPAuthHandler",
    "LDAPBindHandler",
]
