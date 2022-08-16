# Project Status
I am not currently working on finishing this library. I may return to this project later, but I found attacks are easier to precisely control with C. For that I'm writing my own code, also on my Github :) 

This package was written for python 3.7.0 and [Scapy](https://github.com/secdev/scapy) 2.4.5.

## IEC-61850 GOOSE and SV with Scapy
An implementation of IEC-61850 GOOSE and SV with Scapy without the use of the built in BER. This is operational with hardware, although the lack of structure implementation limits the capabilities of packet decoding. 

## Why didn't you use Scapy's BER?   

For my application, I wanted to have full control over all bytes within the packet. While this may not be useful for all implementations, it worked well for me.

## What still needs to be done?

* The PhsMeas portion of SV ASDU packets is not complete.
* Hope to add MMS capability. (Need documentation however.)
