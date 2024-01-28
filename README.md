# isis-mocker

Tool provides an ability to load ISIS protocol(RFC 1195) database in json format to a lab router and emulate the whole ISIS network for the router under test(DUT).
_ONLY_ L2 P2P adjacency supported and Linux OS. 

#### Features supported
* P2P 
* all database content is replicated, depending on DUT config all features can work


#### Encoded params
Tool uses the following parameters as encoded:
* MAC address: 00:0c:29:6f:14:bf

#### Installation and run
Get .deb package, install using pkg manager.
Help menu can be used to get commands descriptions:
```
isis-mocker> help
Commands available:
 - help
	This help message
 - exit
	Quit the session
 - run
	run commands
 - clear
	clear commands
 - show
	show commands
 - load
	load commands
 - debug
	debug commands

isis-mocker> run
run> help
Commands available:
 - help
	This help message
 - exit
	Quit the session
 - mock <xxxx.xxxx.xxxx>
	remove sys-id from lsdb
 - mocker <x xxxx.xxxx.xxxx ethx xx.xx.xx.xx xx.xxxx>
	start mocker instance
 - flood <x>
	start flood
 - test <x(id) x(msec 50 ... 5000)>
	start test
 - isis-mocker
	(menu)


```

Simple example how to run:

```
isis-mocker> run mock 0000.0000.0003       
isis-mocker> run mocker 0 0000.0000.0001 eth3 10.0.0.1 49.0001
isis-mocker> run mocker 1 0000.0000.0002 eth4 10.1.0.1 49.0001
isis-mocker> run flood 0
isis-mocker> run flood 1
```

0003 - is router being mocked, so DUT is placed on its position in topology
0001,0002 - neighbors of 0003 with interface on which to start mocker,ip, area
then 2 instances of flood start to load isis database to DUT 


#### Sample outputs
DUT config example:
```
Junos:

set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.0/31 arp 10.0.0.1 mac 00:0c:29:6f:14:bf
set interfaces ge-0/0/2 unit 0 family iso
set interfaces ge-0/0/2 unit 0 family mpls
set interfaces ge-0/0/3 unit 0 family inet address 10.1.0.0/31 arp 10.1.0.1 mac 00:0c:29:6f:14:bf
set interfaces ge-0/0/3 unit 0 family iso
set interfaces ge-0/0/3 unit 0 family mpls
set interfaces lo0 unit 0 family inet address 5.5.5.5/32
set interfaces lo0 unit 0 family iso address 49.0001.0000.0000.0003.00
set policy-options policy-statement LB term 0 then load-balance per-packet
set routing-options forwarding-table export LB
set protocols isis interface ge-0/0/2.0 point-to-point
set protocols isis interface ge-0/0/3.0 point-to-point
set protocols isis interface lo0.0
set protocols isis source-packet-routing srgb start-label 100000
set protocols isis source-packet-routing srgb index-range 36000
set protocols isis level 1 disable
set protocols isis level 2 wide-metrics-only
set protocols isis backup-spf-options use-source-packet-routing
set protocols mpls interface all


```

Sample run:
```
root@salt:/var/tmp/testing# isis-mocker --ifnames eth3 eth4 eth5 --json-file full.json --json-file-raw raw.json --json-hostname hostname.json (1) 

  ___ ____ ___ ____        __  __  ___   ____ _  _______ ____
 |_ _/ ___|_ _/ ___|      |  \/  |/ _ \ / ___| |/ / ____|  _ \
  | |\___ \| |\___ \ _____| |\/| | | | | |   | ' /|  _| | |_) |
  | | ___) | | ___) |_____| |  | | |_| | |___| . \| |___|  _ <
 |___|____/___|____/      |_|  |_|\___/ \____|_|\_\_____|_| \_\
Parsing JSON ...
done
isis-mocker> run mock 0000.0000.0003
isis-mocker> run mocker 0 0000.0000.0001 eth3 10.0.0.1 49.0001
isis-mocker> run mocker 1 0000.0000.0002 eth4 10.1.0.1 49.0001
isis-mocker> run flood 0
isis-mocker> run flood 1

isis-mocker> show mockers
 Mocker 0
 State: Up
 Uptime: 00:00:05
 Flooder attached
 Stats:
       hello in      3
       hello out     3
       pkts in       14
       pkts out      7
       lsp announced 851
 Mocker 1
 State: Up
 Uptime: 00:00:02
 Flooder attached
 Stats:
       hello in      3
       hello out     3
       pkts in       10
       pkts out      5
       lsp announced 294

root@Junos-DUT> show route summary
Router ID: 5.5.5.5

Highwater Mark (All time / Time averaged watermark)
    RIB unique destination routes: 17169 at 2023-06-09 18:12:58 / 1417
    RIB routes                   : 23167 at 2023-06-12 13:33:37 / 1418
    FIB routes                   : 13939 at 2023-06-09 18:12:58 / 1135
    VRF type routing instances   : 0 at 2023-06-08 18:48:05

inet.0: 10724 destinations, 10725 routes (10724 active, 0 holddown, 0 hidden)
              Direct:      6 routes,      6 active
               Local:      5 routes,      5 active
               IS-IS:  10713 routes,  10712 active  <-----
     Access-internal:      1 routes,      1 active

inet.3: 3194 destinations, 3194 routes (3194 active, 0 holddown, 0 hidden)
              L-ISIS:   3194 routes,   3194 active

iso.0: 1 destinations, 1 routes (1 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active

mpls.0: 3216 destinations, 3216 routes (3216 active, 0 holddown, 0 hidden)
                MPLS:      6 routes,      6 active
              L-ISIS:   3210 routes,   3210 active   <-----

inet6.0: 2 destinations, 2 routes (2 active, 0 holddown, 0 hidden)
               Local:      1 routes,      1 active
               INET6:      1 routes,      1 active

inetcolor.0: 10 destinations, 10 routes (10 active, 0 holddown, 0 hidden)
              L-ISIS:     10 routes,     10 active

root@Junos-DUT> show isis backup coverage
Backup Coverage:
Topology        Level   Node    IPv4    IPv4-MPLS    IPv4-MPLS(SSPF)   IPv6    IPv6-MPLS     IPv6-MPLS(SSPF)   CLNS
IPV4 Unicast        2 100.00% 100.00%      100.00%            100.00%  0.00%        0.00%               0.00%  0.00%


```
(1)
   json-file-raw is the file made by output from base64 Junos command which is supported only in latest releases
   hostname.json is output from "show isis hostname | display json" command
#### Debug mode & telnet 
```
telnet 192.168.178.152 5000
Trying 192.168.178.152...
Connected to 192.168.178.152.
Escape character is '^]'.
isis-mocker>
isis-mocker>
isis-mocker> show version
v2.0.3
isis-mocker> debug on
isis-mocker> run mock 0001.0001.0004
isis-mocker> run mocker 0 0001.0001.0002 eth4 10.3.0.0 38.3257.2132.0009.2131
isis-mocker> run mocker 1 0001.0001.0003 eth5 10.5.0.0 38.3257.2132.0009.2131
isis-mocker> run flood 0
isis-mocker> [2024-01-29 00:31:02 CST]  ISIS-1 Adj is : Init
[2024-01-29 00:31:02 CST]  ISIS-1 Adj is : Up <-----

isis-mocker>
isis-mocker> [2024-01-29 00:31:04 CST]  ISIS-0 Adj is : Init
[2024-01-29 00:31:04 CST]  ISIS-0 Adj is : Up

isis-mocker>
isis-mocker>
isis-mocker> show mockers
 Mocker 0
 State: Up
 Uptime: 00:00:04
 Flooder attached
 Stats:
       hello in      3
       hello out     3
       pkts in       10
       pkts out      4
       lsp announced 3
 Mocker 1
 State: Up
 Uptime: 00:00:06
 Stats:
       hello in      3
       hello out     3
       pkts in       16
       pkts out      8

isis-mocker> show interfaces
Interfaces:
      eth3
      eth4
      eth5
      eth6
Used:
      eth5
      eth4

isis-mocker> show mockers
 Mocker 0
 State: Up
 Uptime: 00:00:24
 Flooder attached
 Stats:
       hello in      5
       hello out     5
       pkts in       16
       pkts out      6
       lsp announced 3
 Mocker 1
 State: Up
 Uptime: 00:00:26
 Stats:
       hello in      6
       hello out     6
       pkts in       24
       pkts out      11
isis-mocker>
```


#### License and deps

libc6 (>= 2.14), libgcc-s1 (>= 3.0), libstdc++6 (>= 9)

Jan 2024. Application isis-mocker is an Open Source software. 
It is distributed under the terms of the MIT license. CLI lib uses Boost license.
