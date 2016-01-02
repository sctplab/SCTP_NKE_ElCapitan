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

## Installation
Currently there is no installer provided. Therefore the following manual steps are required.
You can download a disk image containing all files at [SCTP_NKE_ElCapitan_Install_01.dmg](https://github.com/sctplab/SCTP_NKE_ElCapitan/releases/download/v01/SCTP_NKE_ElCapitan_Install_01.dmg).

### Prerequisites
It is assumed that the comand line tools are installed. This can be done
executing
```
xcode-select --install
```

### Installation of KEXTs
Execute the following commands:
```
sudo cp -R /Volumes/SCTP_NKE_ElCapitan_01/SCTPSupport.kext /Library/Extensions
sudo cp -R /Volumes/SCTP_NKE_ElCapitan_01/SCTP.kext /Library/Extensions
```
The first extension is needed to export additional symbols from the kernel.
The second extension contains the SCTP relevant code.

### Installation of Support Files
Execute the following commands:
```
sudo cp /Volumes/SCTP_NKE_ElCapitan_01/socket.h /usr/include/sys/
sudo cp /Volumes/SCTP_NKE_ElCapitan_01/sctp.h /usr/include/netinet/
sudo cp /Volumes/SCTP_NKE_ElCapitan_01/sctp_uio.h /usr/include/netinet/
sudo cp /Volumes/SCTP_NKE_ElCapitan_01/libsctp.dylib /usr/lib/
```
The first command changes an existing file by adding a definition for
`MSG_NOTIFICATION`. The other commands add additional files.

## Using the SCTP KEXT
Since the NKE's are not signed, you need the disable the System Integrity
Protection as described above.

### Loading the SCTP KEXT
You can load the SCTP kext by executing in a shell
```
sudo kextload /Library/Extensions/SCTP.kext
```
### Unloading the SCTP KEXT
You can unload the SCTP kext by executing in a shell
```
sudo kextunload /Library/Extensions/SCTP.kext
```
