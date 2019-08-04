# FreeSvCheck

SNI is an optional field which can be used to establish a connection between the server and the desired website when establishing a connection via TLS during the client hello. TLS 1.3 and ESNI must be used to better protect the connections against monitoring. In addition, DNS traffic must be secured using DNSoverTLS or DNSoverHTTPS.

This bash script helps to find out if the traffic can be tracked via DNS or SNI. 

## Installation:

This script requires the TSHARK tool to analyze network traffic:

    apt-get install tshark

## Usage:

The easiest way is to briefly display the Help.

    ./freesvcheck.sh -h

You can analyze the traffic directly or via an existing PCAP file.

    ./freesvcheck.sh -i <INTERFACE>
    ./freesvcheck.sh -f <FILE>

This script is based on the basic idea of Tore (cr33y). Special thanks to the community.

Further ideas and suggestions for improvement are very welcome.

Translated with www.DeepL.com/Translator - Thanks:-)
