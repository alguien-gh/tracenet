# tracenet
Network range discovery tool

## Install

```
# git clone https://github.com/alguien-gh/tracenet.git
# cd tracenet
# virtualenv --clear venv
# source venv/bin/activate
(venv)# pip install -r requirements.txt
(venv)# python tracenet.py --help
```

## Options

```
usage: tracenet.py [-h] [-m MASK] [-l MASK_LIMIT] [-nW] [-nI]
                   [--timeout TIMEOUT] [--min-ttl MIN_TTL] [--max-ttl MAX_TTL]
                   [--deep DEEP] [-sn] [-sT] [-sS] [-sP] [-tT] [-tU] [-tI]
                   [--graph GRAPH]
                   IP

A tool for network range discovery using traceroute.

positional arguments:
  IP                    Any IP address in the target network

optional arguments:
  -h, --help            show this help message and exit
  -m MASK, --mask MASK  Initial netmask (default: /29)
  -l MASK_LIMIT, --mask-limit MASK_LIMIT
                        Netmask limit (default: /24)
  -nW, --no-whois       Don't use whois to autoconfig the netmask limit
  -nI, --no-info        Don't use whois to display extra info
  --timeout TIMEOUT     Timeout for portscan and traceroute (default: 10)
  --min-ttl MIN_TTL     Minimum TTL for traceroute (default: 1)
  --max-ttl MAX_TTL     Maximum TTL for traceroute (default: 20)
  --deep DEEP           Maximum deep for finding a common hop (default: 3)
  -sn, --no-scan        Don't perform host scanning
  -sT, --tcp-scan       Search hosts using TCP-CONNECT-scan (default)
  -sS, --syn-scan       Search hosts using SYN-scan
  -sP, --ping-scan      Search hosts using PING-scan
  -tT, --tcp-trace      Traceroute using TCP packets (default)
  -tU, --udp-trace      Traceroute using UDP packets
  -tI, --icmp-trace     Traceroute using ICMP packets
  --graph GRAPH         Save the traceroute graph to file (SVG format)

Author: Alguien (@alguien_tw) | alguien.site
```
