# MitM Example with scapy 

This script is created to be template for active MitM atttacks on unknown UDP protocols. You have to already be MitM and getting it is not part of this tool. 
The idea is to use netfilter queues for redirecting traffic into this script and using scapy to change the packets. Not very novel but st

## Why Netfilter ?
* netfilter allows to drop packets (which normal interface sniffing does not allow)
* it is agentless, no need to run a proxy server that handles traffic
* it supports also supports UDP (which some proxies like mitmproxy) does not

## Some more details

As a example an imagenery protocol is used that has the following properties
* based on UDP/5555 called _Catotron_
* little endian as byte order for binary data and big endian for strings
* packet layout (syntax <amount of bytes:name of the field>): <1:Version>, <1:SubVersion>, <2:Size in bytes>, <n:messages>, <4:CRC32>, <2:Trailer>
* the message starts with a tag and each message has defined length or a dedicated length field e.g. type 0 = HeartBeat, 1 = Textmessage
* CRC32 polynomial is 0x414141AB and only length and data are protected by the CRC32

Example:
```bash
###[ Catotron ]### 
  version   = 1
  subversion= 2
  size      = 13
  \message   \
   |###[ HeartBeat ]### 
   |  type      = 0
   |  counter   = 66
   |###[ TextMessage ]### 
   |  type      = 1
   |  length    = 4
   |  data      = 'test'
   |###[ HeartBeat ]### 
   |  type      = 0
   |  counter   = 66
  crc       = 3492012882
  end_frame = 16705

## Setup 
* via the python package manager of your choice. 
* the setup failed with python3.9 (because of compile errors of NetfilterQueue), *python 3.6 worked* :-/
```bash
pip install -r requirements.txt
```

## Usage
* root privs are needed

```bash
# setup the iptables rules
iptables -A INPUT -p udp  --sport 5555 -j NFQUEUE --queue-num 1
iptables-legacy -A INPUT -p udp  --dport 5555 -j NFQUEUE --queue-num 2
# start the script

```