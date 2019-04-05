# Network traffic analyzer (school project)

Programming language: C

## Description

Create and console application for analyzing network traffic saved in the [libpcap file](https://wiki.wireshark.org/Development/LibpcapFileFormat). The application will count a number of transferred bytes on the defined conditions according to network frames:

* MAC address
* IPv4 address
* IPv6 address
* TCP port
* UDP port

Counting of each element can be specified by the position in the communication:

* source
* destination
* source or destination

## Using

* `./analyzer [-i file] [ -f filterType ] [ -v filterValue ] [ -s ] [ -d ]`   
* `-i file` - (required parameter) input file in libpcap format   
* `-f filterType` - (required parameter) define according which element will be count data size. Possible value: mac, ipv4, ipv6, tcp, udp   
* `-v filterValue` - (required parameter) possible valeu e.g.: 5C:D5:96:2C:38:63 (for mac), 192.168.1.1 (for ipv4), 2001::1 (for ipv6), 80 (for tcp, udp), top10 (for mac, ipv4, ipv6, tcp, udp)   
* `-s` - (minimally one of the parameter s/d must be specified) filter is applied on the source address (MAC, IPv4, IPv6, port)   
* `-d` - (minimally one of the parameter s/d must be specified) filter is applied on the destination address (MAC, IPv4, IPv6, port)   

## Output format

Output on `stderr` will be ignored. Output on `stdout` will be depend on the defined filter (value1_value2). 

## Counting of bytes

* value1 - Count of the bytes from L2 layer (header L2 + header L3 + header L4 + data). Attention: not all frames have all headers.
* value2
  * for filer `mac` - is counted from end of L2 header
  * for filter `ipv4`/`ipv6` - is counted from end of L3 header
  * for filter `tcp`/`udp`- is counted from end of L4 header

## Testing

* The program is tested with captured network traffic e.g. with Wireshark, which will be saved like `Wireshark/tcpdump/...-pcap`.

## Example pcap

http://www.stud.fit.vutbr.cz/~iholkovic/isa.pcap:
* -f udp -v 101,104 -s => 796 628   
* -f tcp -v 101 -s -d => 6162 5484   
* -f tcp -v 103 -s => 5373 4857   
* -f ipv4 -v 10.10.10.60 -d => 1132 860   
* -f ipv4 -v 10.10.10.100 -s -d => 354 184   
* -f mac -v 00:00:00:00:00:05 -s => 11620 10606   

## Possible extension

* A (1.5b) - Possibility to add more filters. Parameter `-v` could have more attributes separated with commas (before or after the comma will not be space). E.g.: "192.168.1.1,192.168.1.2,192.168.1.3".

## Other information

* compilation of the application must be realize by Makefilu (command `make` with out parameters)
