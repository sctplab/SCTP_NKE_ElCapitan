# SCTP_NKE_ElCapitan
A version of the SCTP NKE running on Mac OS X 10.11 (El Capitan).

The sources are based on the SCTP implementation of the FreeBSD kernel modified to work
within the Mac OS X kernel infrastructure as a network kernel extension. This supports
the dynamic load and unload of the module without rebooting the operating system.

The SCTP NKE supports:
* The base protocol as specified in [RFC4960](https://tools.ietf.org/html/rfc4960).
* The partial reliability extension as specified in [RFC3758](https://tools.ietf.org/html/rfc3758) and [RFC7496](https://tools.ietf.org/html/rfc7496).
* The authentication extension as specified in [RFC4895](https://tools.ietf.org/html/rfc4895).
* The dynamic address reconfiguration extension as specified in [RFC5061](https://tools.ietf.org/html/rfc5061).
* The stream reconfiguration extension as specified in [RFC6525](https://tools.ietf.org/html/rfc6525).
* The SACK immediately extension specified in [RFC7053](https://tools.ietf.org/html/rfc7053).

Starting with Mac OS X 10.11, you can't load unsinged kernel extensions anymore without
disabling the System Integrity Protection.
See [Apple's documentation](https://developer.apple.com/library/mac/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) on how to disable it.
I'm currently not providing an signed NKE, since I don't have the necessary certificate yet.

