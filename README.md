# IEC-61850 GOOSE and SV with Scapy
An implementation of IEC-61850 GOOSE and SV with Scapy without the use of the built in BER. 

## Why didn't you use Scapy's BER?   

For my application, I wanted to have full control over all bytes within the packet. While this may not be useful for all implementations, it worked well for me.

## What still needs to be done?

* The PhsMeas portion of SV ASDU packets is not complete.
* Validate on hardware. Current testing only utilized wireshark and libiec61850

* Hope to add MMS capability. (Need documentation however.)