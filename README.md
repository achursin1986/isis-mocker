# isis-mocker

Tool provides an ability to load ISIS protocol(RFC 1195) database in json format to lab router and emulate that network for the router.
_ONLY_ L2 P2P adjacency supported and Linux OS. To get input json file in correct format see details below.

#### Features supported
* Base ISIS protocol structs
* IPv4 reachability
* Basic SR


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




#### JSON preparation
* Get 2 outputs from Junos router:
    show isis database extensive | display json | no-more
    show isis hostname | display json | no-more

*  Use py script to create json in the correct format*, for example
   ./convert-showisisdb.py --filepath \`pwd\` --hosts jtac-hosts-isis-json.txt --sourcedb jtac-db-isis-json.txt --output out.json

*  Run the program providing json file and nic name, for example:
   ./isis-mocker eth1 out.json

\* Junos implementation of isis json export for older releases produces duplicate json keys(not recommended by standard), also lsp-ids are exported as hostnames.


#### Sample outputs
DUT(device under test) router config example:
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
root@salt:/var/tmp/testing# isis-mocker --ifnames eth3 eth4 eth5 --json-file out.json

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


#### License and deps

libc6 (>= 2.14), libgcc-s1 (>= 3.0), libstdc++6 (>= 9)

Jun 2023. Application isis-mocker is an Open Source software. 
It is distributed under the terms of the MIT license. CLI lib uses Boost license.
