# CTF Series : Vulnerable Machines

This post (Work in Progress) records what we learned by doing vulnerable machines provided by [VulnHub](https://vulnhub.com>), [Hack the Box](https://hackthebox.eu) and others. The steps below could be followed to find vulnerabilities, exploit these vulnerabilities and finally achieve system/ root.

Once you download a virtual machines from [VulnHub](https://vulnhub.com)  you can run it by using virtualisation software such as VMware or Virtual Box.

We would like to **thank g0tm1lk** for maintaining **Vulnhub** and the **moderators** of **HackTheBox**. Also, **shout-outs** are in order for each and every **author of Vulnerable Machines and/ or write-ups**. Thank you for providing these awesome challenges to learn from and sharing your knowledge with the IT security community! **Thank You!!**

Generally, we go through the following stages when solving a vulnerable machine:

- [finding-the-ip-address](#finding-the-ip-address)
- [port-scanning](#port-scanning)
- [rabbit-holes](#Rabbit-holes)
- [from-nothing-to-unprivileged-shell](https://github.com/ArM4dA/bitvijays.github.io-sphinx/blob/Vulnerable-Machines/docs/Series_Capture_The_Flag/LFC-VulnerableMachines_P2.md)
- [unprivileged-shell-to-privileged-shell](https://github.com/ArM4dA/bitvijays.github.io-sphinx/blob/Vulnerable-Machines/docs/Series_Capture_The_Flag/LFC-VulnerableMachines_P3.md)

In this blog post, we have mentioned, what can be done in each separate stage. Furthermore, we have also provided [tips-and-tricks](https://github.com/ArM4dA/bitvijays.github.io-sphinx/blob/Vulnerable-Machines/docs/Series_Capture_The_Flag/LFC-VulnerableMachines_P4.md) for solving vulnerable VMs. Additionally [LFF-IPS-P2-VulnerabilityAnalysis](https://github.com/ArM4dA/bitvijays.github.io-sphinx/blob/Vulnerable-Machines/docs/Series_Infrastructure_Pentest/LFF-IPS-P2-VulnerabilityAnalysis.md) could be referred for exploitation of any particular services (i.e. it provides information such as "If you have identified service X (like ssh, Apache tomcat, JBoss, iscsi etc.), how they can be exploited"). Lastly there are also appendixes related to

- [A1-Local-file-Inclusion](https://github.com/ArM4dA/bitvijays.github.io-sphinx/blob/Vulnerable-Machines/docs/Series_Capture_The_Flag/LFC-VulnerableMachines_P4.md#appendix-i--local-file-inclusion)
- [A2-File-Upload](https://github.com/ArM4dA/bitvijays.github.io-sphinx/blob/Vulnerable-Machines/docs/Series_Capture_The_Flag/LFC-VulnerableMachines_P4.md#appendix-ii--file-upload)
- [A3-Tranfer-Files-From-Linux-to-Windows](https://github.com/ArM4dA/bitvijays.github.io-sphinx/blob/Vulnerable-Machines/docs/Series_Capture_The_Flag/LFC-VulnerableMachines_P4.md#appendix-iii-transferring-files-from-linux-to-windows-post-exploitation)
- [A4-Linux-Group-Membership-Issues](https://github.com/ArM4dA/bitvijays.github.io-sphinx/blob/Vulnerable-Machines/docs/Series_Capture_The_Flag/LFC-VulnerableMachines_P4.md#appendix-iv-linux-group-membership-issues)
- [A5-Coding-Languages-Tricks](https://github.com/ArM4dA/bitvijays.github.io-sphinx/blob/Vulnerable-Machines/docs/Series_Capture_The_Flag/LFC-VulnerableMachines_P4.md#appendix-v-coding-languages-tricks)

## Finding the IP address

Before, exploiting any machine, we need to figure out its IP address.

### Netdiscover

An active/ passive arp reconnaissance tool

```none
netdiscover [options]
-i interface : The network interface to sniff and inject packets on.
-r range : Scan a given range instead performing an auto scan.

Example:
netdiscover -i eth0/wlan0/vboxnet0/vmnet1 -r 192.168.1.0/24
```

Interface names of common Virtualisation Software:

- Virtualbox : vboxnet
- Vmware     : vmnet

### Nmap

Network exploration tool and security/ port scanner

```sh
nmap [Scan Type] [Options] {target specification} 
-sP/-sn Ping Scan -disable port scan 
```

Example:

```none
nmap -sP/-sn 192.168.1.0/24
```

## Port Scanning

Port scanning provides a large amount of information about open (exposed) services and possible exploits that may target these services.

Common port scanning software include: nmap, unicornscan, netcat (when nmap is not available).

### Nmap

Network exploration tool and security/ port scanner

```none
nmap [Scan Type] [Options] {target specification}

HOST DISCOVERY:
-sL: List Scan - simply list targets to scan
-sn/-sP: Ping Scan - disable port scan
-Pn: Treat all hosts as online -- skip host discovery

SCAN TECHNIQUES: 
-sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
-sU: UDP Scan -sN/sF/sX: TCP Null, FIN, and Xmas scans

PORT SPECIFICATION: 
-p : Only scan specified ports 
Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9

SERVICE/VERSION DETECTION: 
-sV: Probe open ports to determine service/version info

OUTPUT: 
-oN/-oX/-oS/-oG : Output scan in normal, XML,Output in the three major formatsat once 
-v: Increase verbosity level (use -vv or more for greater effect)

MISC: -6: Enable IPv6 scanning -A: Enable OS detection, version detection,script scanning, and traceroute
```

Common Command:

`nmap -sC -sV -oA nmap/initial 10.0.0.1`

- -sC specifies default scripts
- -sV probes each port for services
- -oA outputs to all major file types
- nmap/initial specifies the directory in which to output the scan

### Unicornscan

A port scanner that utilizes its own userland TCP/IP stack, which allows it to run asynchronous scans. It can scan 65,535 ports in a relatively short time frame.

As unicornscan is faster then nmap it makes sense to use it for scanning large networks or a large number of ports. The idea is to use unicornscan to scan all ports, and make a list of those ports that are open and pass them to nmap for service detection. Superkojiman has written [onetwopunch](https://github.com/superkojiman/onetwopunch) for this.

```none
unicornscan [options] X.X.X.X/YY:S-E 
    -i, --interface : interface name, like eth0 or fxp1, not normally required 
    -m, --mode : scan mode, tcp (syn) scan is default, U for udp T for tcp \`sf' for tcp connect scan and A for arp for -mT you can also specify tcp flags following the T like -mTsFpU for example that would send tcp syn packets with (NO Syn\|FIN\|NO Push\|URG)

    Address ranges are in cidr notation like 1.2.3.4/8 for all of 1.?.?.?, if you omit the cidr mask /32 is implied. 
    Port ranges are like 1-4096 with 53 only scanning one port, **a** for all 65k and p for 1-1024

    example: unicornscan 192.168.1.5:1-4000 gateway:a would scan port 1 - 4000 for 192.168.1.5 and all 65K ports for the host named gateway.
```

### RustScan

[Rustscan](https://github.com/RustScan/RustScan) is a open source tool and very fast tool for port scanning. visit it's github repository and there's a full tutorial for installing and using it.

[Usage Guide](https://github.com/RustScan/RustScan/wiki/Usage)

[Things you may want to do with RustScan but don't understand how](https://github.com/RustScan/RustScan/wiki/Things-you-may-want-to-do-with-RustScan-but-don't-understand-how)

Common Command:
`rustscan -a 10.0.0.1`

Note: You need nmap installed on your system for running rustscan.

### Fast Port Scan Tip

`-p-` option in nmap scans all the ports of the target but it takes ages.

Using masscan, you can scan all TCP and UDP ports in roughly some minutes.

`masscan -p1-65535,U:1-65535 10.0.0.1 --rate=1000 -e tun0`

- -p1-65535,U:1-65535: tells masscan to scan all TCP/UDP ports.

- --rate=1000: scan rate = 1000 packets per second.

- -e tun0 tells masscan to listen on the VPN network interface for responses.

After getting all the ports you can run nmap on them. For example we got port 22,80,3000,5984 from `masscan`

Now instead of running `-p-` we can just do port scan on particular ports.

`nmap -sC -sV -p 22,80,3000,5984 -oA nmap/initial 10.0.0.1`

and scan your will be much faster.

### Netcat

Netcat might not be the best tool to use for port scanning, but it can be used quickly. While Netcat scans TCP ports by default it can perform UDP scans as well.

#### TCP Scan

For a TCP scan, the format is:

```none
nc -vvn -z xxx.xxx.xxx.xxx startport-endport

    -z flag is Zero-I/O mode (used for scanning)
    -vv will provide verbose information about the results
    -n flag allows to skip the DNS lookup
```

#### UDP Scan

For a UDP Port Scan, we need to add -u flag which makes the format:

```none
nc -vvn -u -z xxx.xxx.xxx.xxx startport-endport
```

If we have windows machine without nmap, we can use [PSnmap](https://www.powershellgallery.com/packages/PSnmap/)

### Amap - Application mapper

When portscanning a host, you will be presented with a list of open ports. In many cases, the port number tells you which application is running. Port 25 is usually SMTP, port 80 mostly HTTP. However, this is not always the case, and especially when dealing with proprietary protocols running on non-standard ports you will not be able to determine which application is running.

By using **amap**, we can identify which services are running on a given port. For example is there a SSL server running on port 3445 or some oracle listener on port 23? Note that the application can also handle services that requires SSL. Therefore it will perform an SSL connect followed by trying to identify the SSL-enabled protocol!. e.g.  One of the vulnhub VM's was running http and https on the same port.

```none
amap -A 192.168.1.2 12380 
amap v5.4 (www.thc.org/thc-amap) started at 2016-08-10 05:48:09 - APPLICATION MAPPING mode
Protocol on 192.168.1.2:12380/tcp matches http 
Protocol on 192.168.1.2:12380/tcp matches http-apache-2 
Protocol on 192.168.1.2:12380/tcp matches ntp 
Protocol on 192.168.1.2:12380/tcp matches ssl
Unidentified ports: none.
amap v5.4 finished at 2016-08-10 05:48:16
```

## Rabbit Holes

There will be instances when we will not able to find anything entry point such as any open port. The section below may provide some clues on how to get unstuck.

### Listen to the interface

Many VMs send data on random ports therefore we recommend to listen to the local interface (vboxnet0 / vmnet) on which the VM is running. This can be done by using wireshark or tcpdump. For example, one of the vulnhub VMs, performs an arp scan and sends a SYN packet on port 4444, if something is listening on that port, it sends some data.

```none
tcpdump -i eth0

18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S], seq 861815232, win 16384, options [mss 1460,nop,nop,sackOK,nop,wscale 3,nop,nop,TS val 4127458640 ecr 0], length 0
18:02:04.096330 IP 192.168.56.1.4444 > 192.168.56.101.36327: Flags [R.], seq 0, ack 861815233, win 0, length 0
18:02:04.098584 ARP, Request who-has 192.168.56.2 tell 192.168.56.101, length 28
18:02:04.100773 ARP, Request who-has 192.168.56.3 tell 192.168.56.101, length 28
18:02:04.096292 IP 192.168.56.101.36327 > 192.168.56.1.4444: Flags [S],
```

While listening on port 4444, we might receive something like a base64 encoded string or some message.

```none
nc -lvp 4444
listening on [any] 4444 …
192.168.56.101: inverse host lookup failed: Unknown host
connect to [192.168.56.1] from (UNKNOWN) [192.168.56.101] 39519
0IHNpbGVuY2Ugc3Vycm91bmRpbmcgeW91Lg0KWW91IGxvb2sgZWFzdCwgdGhlbiBzb3V0aCwgdGhlbiB3ZXN0LCBhbGwgeW91IGNhbiBzZWUgaXMgYSBncmVhdCB3YXN0ZWxh
```

### DNS Server

If the targeted machine is running a DNS Server and we have a possible domain name, we may try to figure out A, MX, AAAA records or try zone-transfer to figure out other possible domain names.

```none
host <domain> <optional_name_server>
host -t ns <domain>                -- Name Servers
host -t a <domain>                 -- Address
host -t aaaa <domain>              -- AAAA record points a domain or subdomain to an IPv6 address
host -t mx <domain>                -- Mail Servers
host -t soa <domain>               -- Start of Authority
host <IP>                          -- Reverse Lookup
host -l <Domain Name> <DNS Server> -- Domain Zone Transfer
```

Example:

```none
host scanme.nmap.org
scanme.nmap.org has address 45.33.32.156
scanme.nmap.org has IPv6 address 2600:3c01::f03c:91ff:fe18:bb2f
```

Tip

Usually, DNS runs on UDP Port. However, If DNS is running on TCP port, probably DNS Zone Transfer would be possible.

### SSL Certificate

If the targeted machine is running an https server and we are getting an apache default webpage on hitting the <https://IPAddress>, virtual hosts would be probably in use. Check the alt-dns-name on the ssl-certificate, create an entry in hosts file (/etc/hosts) and check what is being hosted on these domain names by surfing to <https://alt-dns-name>.

nmap service scan result for port 443 (sample)

```none
| ssl-cert: Subject: commonName=examplecorp.com/organizationName=ExampleCorp Ltd./stateOrProvinceName=Attica/countryName=IN/localityName=Mumbai/organizationalUnitName=IT/emailAddress=admin@examplecorp.com
| Subject Alternative Name: DNS:www.examplecorp.com, DNS:admin-portal.examplecorp.com
```
