"""
AUTH ENGINE - Protocol Handlers

Each handler implements AuthProtocolHandler for a specific auth protocol.
Adding a new protocol = adding a new handler file here.

COMPLETE COVERAGE: 38 protocols with extractable credentials.

=== ENTERPRISE PROTOCOLS ===
    - ntlm.py: NTLMv1, NTLMv2, NTLM-over-HTTP (hashcat 5600)
    - kerberos.py: AS-REQ/REP, TGS-REQ/REP, Kerberoasting (hashcat 18200)
    - http.py: Basic, Digest, Bearer, OAuth (hashcat 11400)
    - ldap.py: Simple bind, SASL (plaintext)
    - radius.py: RADIUS AAA (hashcat 16000)
    - tacacs.py: TACACS+ (hashcat 16100)
    - diameter.py: Diameter AAA (3GPP)
    - dcerpc.py: DCE/RPC NTLM (hashcat 5600)

=== EMAIL PROTOCOLS ===
    - pop3.py: POP3 USER/PASS, APOP (hashcat 10900)
    - smtp.py: SMTP AUTH PLAIN/LOGIN/CRAM-MD5 (hashcat 16400)
    - imap.py: IMAP LOGIN, AUTHENTICATE (hashcat 16400)
    - nntp.py: NNTP AUTHINFO (plaintext)

=== REMOTE ACCESS ===
    - rdp.py: RDP NLA/CredSSP (hashcat 5600)
    - vnc.py: VNC challenge/response (hashcat 14000)
    - telnet.py: Telnet (plaintext)
    - rcommands.py: rsh/rlogin/rexec (plaintext/trust)

=== DATABASE PROTOCOLS ===
    - mysql.py: MySQL auth (hashcat 300)
    - postgresql.py: PostgreSQL md5/SCRAM (hashcat 12000)
    - mssql.py: MSSQL/TDS (hashcat 1731)
    - mongodb.py: MongoDB SCRAM-SHA (hashcat 24100)
    - redis.py: Redis AUTH (plaintext)

=== NETWORK SERVICES ===
    - ftp.py: FTP USER/PASS (plaintext)
    - snmp.py: SNMPv1/v2c community, SNMPv3 USM (hashcat 25000)
    - socks.py: SOCKS5 proxy auth (plaintext)
    - nfs.py: NFS AUTH_SYS (trust-based)
    - afp.py: Apple Filing Protocol (DH-based)

=== WIRELESS/802.1X ===
    - wpa.py: WPA/WPA2 4-way handshake (hashcat 22000)
    - eap.py: EAP-MD5, EAP-LEAP, EAP-MSCHAPv2 (hashcat 4800/5500)
    - mschapv2.py: MS-CHAPv2/PPTP (hashcat 5500)
    - llmnr.py: LLMNR/NBT-NS poisoning captures (hashcat 5600)

=== VOIP/STREAMING ===
    - sip.py: SIP Digest auth (hashcat 11400)
    - rtsp.py: RTSP Digest auth (hashcat 11400)
    - xmpp.py: XMPP/Jabber SASL (plaintext/DIGEST-MD5)

=== IOT/INDUSTRIAL ===
    - mqtt.py: MQTT CONNECT (plaintext)
    - ipmi.py: IPMI 2.0 RAKP (hashcat 7300)
    - modbus.py: Modbus TCP (no auth - device access tracking)
    - dnp3.py: DNP3 Secure Auth v5 (HMAC-based)

=== CHAT/IRC ===
    - irc.py: IRC PASS, OPER, NickServ, SASL (plaintext)
"""

# Enterprise protocols
from .ntlm import NTLMHandler
from .kerberos import KerberosHandler
from .http import HTTPAuthHandler
from .ldap import LDAPBindHandler
from .radius import RADIUSAuthHandler
from .tacacs import TACACSAuthHandler
from .diameter import DiameterAuthHandler
from .dcerpc import DCERPCAuthHandler

# Email protocols
from .pop3 import POP3AuthHandler
from .smtp import SMTPAuthHandler
from .imap import IMAPAuthHandler
from .nntp import NNTPAuthHandler

# Remote access protocols
from .rdp import RDPAuthHandler
from .vnc import VNCAuthHandler
from .telnet import TelnetAuthHandler
from .rcommands import RCommandsAuthHandler

# Database protocols
from .mysql import MySQLAuthHandler
from .postgresql import PostgreSQLAuthHandler
from .mssql import MSSQLAuthHandler
from .mongodb import MongoDBAuthHandler
from .redis import RedisAuthHandler

# Network services
from .ftp import FTPAuthHandler
from .snmp import SNMPAuthHandler
from .socks import SOCKSAuthHandler
from .nfs import NFSAuthHandler
from .afp import AFPAuthHandler

# Wireless/802.1X
from .wpa import WPAAuthHandler
from .eap import EAPAuthHandler
from .mschapv2 import MSCHAPv2AuthHandler
from .llmnr import LLMNRAuthHandler

# VoIP/Streaming
from .sip import SIPAuthHandler
from .rtsp import RTSPAuthHandler
from .xmpp import XMPPAuthHandler

# IoT/Industrial
from .mqtt import MQTTAuthHandler
from .ipmi import IPMIAuthHandler
from .modbus import ModbusAuthHandler
from .dnp3 import DNP3AuthHandler

# Chat/IRC
from .irc import IRCAuthHandler

__all__ = [
    # Enterprise protocols
    "NTLMHandler",
    "KerberosHandler",
    "HTTPAuthHandler",
    "LDAPBindHandler",
    "RADIUSAuthHandler",
    "TACACSAuthHandler",
    "DiameterAuthHandler",
    "DCERPCAuthHandler",
    # Email protocols
    "POP3AuthHandler",
    "SMTPAuthHandler",
    "IMAPAuthHandler",
    "NNTPAuthHandler",
    # Remote access protocols
    "RDPAuthHandler",
    "VNCAuthHandler",
    "TelnetAuthHandler",
    "RCommandsAuthHandler",
    # Database protocols
    "MySQLAuthHandler",
    "PostgreSQLAuthHandler",
    "MSSQLAuthHandler",
    "MongoDBAuthHandler",
    "RedisAuthHandler",
    # Network services
    "FTPAuthHandler",
    "SNMPAuthHandler",
    "SOCKSAuthHandler",
    "NFSAuthHandler",
    "AFPAuthHandler",
    # Wireless/802.1X
    "WPAAuthHandler",
    "EAPAuthHandler",
    "MSCHAPv2AuthHandler",
    "LLMNRAuthHandler",
    # VoIP/Streaming
    "SIPAuthHandler",
    "RTSPAuthHandler",
    "XMPPAuthHandler",
    # IoT/Industrial
    "MQTTAuthHandler",
    "IPMIAuthHandler",
    "ModbusAuthHandler",
    "DNP3AuthHandler",
    # Chat/IRC
    "IRCAuthHandler",
]
