# SCTP NKE for Mac OS X 10.11 (El Capitan)

The sources are based on the SCTP implementation of the FreeBSD kernel modified to work
within the Mac OS X kernel infrastructure as a network kernel extension. This allows
the dynamic loading and unloading of the module without rebooting the operating system.

## Supported Specifications
The FreeBSD kernel stack and the SCTP NKE for Mac OS X supports:
* The base protocol as specified in [RFC4960](https://tools.ietf.org/html/rfc4960).
* The partial reliability extension as specified in [RFC3758](https://tools.ietf.org/html/rfc3758) and [RFC7496](https://tools.ietf.org/html/rfc7496).
* The authentication extension as specified in [RFC4895](https://tools.ietf.org/html/rfc4895).
* The dynamic address reconfiguration extension as specified in [RFC5061](https://tools.ietf.org/html/rfc5061).
* The socket API for SCTP as specified in [RFC6458](https://tools.ietf.org/html/rfc6458).
* The stream reconfiguration extension as specified in [RFC6525](https://tools.ietf.org/html/rfc6525).
* The UDP encapsulation as specified in [RFC6951](https://tools.ietf.org/html/rfc6951).
* The SACK immediately extension as specified in [RFC7053](https://tools.ietf.org/html/rfc7053).
* The quick failover extension as specified in [draft-ietf-tsvwg-sctp-failover](https://tools.ietf.org/html/draft-ietf-tsvwg-sctp-failover).
* The stream scheduler and user message interleaving extension partially as specified in [draft-ietf-tsvwg-sctp-ndata](https://tools.ietf.org/html/draft-ietf-tsvwg-sctp-ndata).
* The NAT support partially as specified in [draft-ietf-tsvwg-natsupp](https://tools.ietf.org/html/draft-ietf-tsvwg-natsupp).
* The non-renegable SACK extension as specified in [draft-tuexen-tsvwg-sctp-multipath](https://tools.ietf.org/html/draft-tuexen-tsvwg-sctp-mutipath).
* The SCTP multipath extension as specified in [draft-tuexen-tsvwg-sctp-multipath](https://tools.ietf.org/html/draft-tuexen-tsvwg-sctp-multipath).

## Note about using Unsigned Kernel Extensions
When using Mac OS X 10.11, you can't load unsinged kernel extensions without disabling the System Integrity Protection.
See [Apple's documentation](https://developer.apple.com/library/mac/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) on how to disable it.
I'm currently not providing an signed NKE, since I don't have the necessary certificate.

## Installation of the SCTP Support KEXT

## Installtion of the SCTP KEXT

## Installation of Support Files

## Loading and unloading the SCTP KEXT
You can load the SCTP kext by executing in the `Terminal` application
```
sudo kextload /Library/Extensions/SCTP.kext
```
and unload it by executing
```
sudo kextunload /Library/Extensions/SCTP.kext
```
