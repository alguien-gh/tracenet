#!/usr/bin/env python
'''
License: Free as in free beer
Author: Alguien (@alguien_tw) | alguien.site
Support: devnull@alguien.site
'''
import argparse
import os

from ipwhois import IPWhois
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TracerouteResult, IP, TCP, UDP, ICMP
from random import random


class NetUtils(object):
    WHOIS_INFO_CACHE = {}

    @classmethod
    def random_ip(cls, net):
        mask = net['mask']
        ip = Net('%s/%d' % (net['ip'], mask)).choice()
        numb = cls.inet_aton(ip)
        if (numb & ~(~0 << (32 - mask))) == 0:
            numb += 1
        if (numb & ~(~0 << (32 - mask))) == (2 ** (32 - mask) - 1):
            numb -= 1
        return cls.inet_ntoa(numb)

    @classmethod
    def inet_aton(cls, ip):
        return struct.unpack('!L', socket.inet_aton(ip))[0]

    @classmethod
    def inet_ntoa(cls, numb):
        return socket.inet_ntoa(struct.pack('!L', numb))

    @classmethod
    def to_net(cls, ip, mask):
        numb = cls.inet_aton(ip) & ((~0) << (32 - mask))
        return {'ip': cls.inet_ntoa(numb), 'mask': mask}

    @classmethod
    def vlsm_complement(cls, net):
        numb = cls.inet_aton(net['ip']) ^ (1 << (32 - net['mask']))
        return {'ip': cls.inet_ntoa(numb), 'mask': net['mask']}

    @classmethod
    def vlsm_divide(cls, net, mask):
        if net['mask'] >= mask:
            return [net]
        net1 = cls.to_net(net['ip'], net['mask'] + 1)
        net2 = cls.vlsm_complement(net1)
        return cls.vlsm_divide(net1, mask) + cls.vlsm_divide(net2, mask)

    @classmethod
    def unsort(cls, lst):
        return sorted(lst, key=lambda x: random())

    @classmethod
    def get_network_via_whois(cls, ip):
        res = IPWhois(ip).lookup_whois()
        nets = []
        if 'nets' in res and type(res['nets']) is list:
            nets = [net['cidr'].split('/') for net in res['nets'] if 'cidr' in net]
            nets = [{'ip': x[0], 'mask': int(x[1])} for x in nets]
        return nets

    @classmethod
    def get_whois_info(cls, ip):
        info = None
        if ip in NetUtils.WHOIS_INFO_CACHE:
            return NetUtils.WHOIS_INFO_CACHE[ip]
        if not NetUtils.is_private(ip):
            try:
                res = IPWhois(ip).lookup_whois()
                if 'nets' in res and type(res['nets']) is list and len(res['nets']) > 0:
                    info = res['nets'][0]
            except:
                pass
        NetUtils.WHOIS_INFO_CACHE[ip] = info
        return info

    @classmethod
    def is_private(cls, ip):
        ip = NetUtils.inet_aton(ip)
        if NetUtils.inet_aton('10.0.0.0') <= ip <= NetUtils.inet_aton('10.255.255.255'):
            return True
        if NetUtils.inet_aton('172.16.0.0') <= ip <= NetUtils.inet_aton('172.31.255.255'):
            return True
        if NetUtils.inet_aton('169.254.0.0') <= ip <= NetUtils.inet_aton('169.254.255.255'):
            return True
        if NetUtils.inet_aton('192.168.0.0') <= ip <= NetUtils.inet_aton('192.168.255.255'):
            return True
        return False


################################################################################
# Traceroute

class GenericTraceroute(object):
    def __init__(self, **kwargs):
        self.traceroute_result = TracerouteResult()
        self.timeout = kwargs.get('timeout') or 10
        self.verbose = kwargs.get('verbose') or False
        self.ttl = kwargs.get('ttl') or (1, 20)
        self.retry = kwargs.get('retry') or 3

    def traceroute(self, ip, **kwargs):
        raise NotImplemented('Unimplemented method.')

    def graph(self):
        self.traceroute_result.graph()

    def graph_tofile(self, filename):
        self.traceroute_result.graph(target='> %s' % filename)

    def get_path(self, ip, **kwargs):
        ans, _ = self.traceroute(ip, **kwargs)
        self.traceroute_result = self.traceroute_result + ans
        path = []
        for (snd, rcv) in ans:
            path.append({'ttl': snd.ttl, 'ip': rcv.src})
        if len(path) > 0:
            path = sorted(path, key=lambda x: x['ttl'])  # sort by TTL
            ip_addrs = [x['ip'] for x in path]
            if ip in ip_addrs:
                path = path[:ip_addrs.index(ip) + 1]  # remove repeated target_ip entries
        return path


class TracerouteTCP(GenericTraceroute):
    def __init__(self, **kwargs):
        super(TracerouteTCP, self).__init__(**kwargs)
        self.dport = kwargs.get('dport') or 80
        self.flags = kwargs.get('flags') or 'S'
        self.data = kwargs.get('data') or ''

    def traceroute(self, ip, **kwargs):
        return sr(
            IP(dst=ip,
               ttl=kwargs.get('ttl') or self.ttl,
               id=RandShort()
               ) /
            TCP(sport=RandShort(),
                dport=kwargs.get('dport') or self.dport,
                flags=kwargs.get('flags') or self.flags,
                ) /
            (kwargs.get('data') or self.data),
            timeout=kwargs.get('timeout') or self.timeout,
            verbose=kwargs.get('verbose') or self.verbose,
            retry=kwargs.get('retry') or self.retry
        )


class TracerouteUDP(GenericTraceroute):
    def __init__(self, **kwargs):
        super(TracerouteUDP, self).__init__(**kwargs)
        self.dport = kwargs.get('dport') or 53
        self.data = kwargs.get('data') or DNS(qd=DNSQR(qname="example.com"))

    def traceroute(self, ip, **kwargs):
        return sr(
            IP(dst=ip,
               ttl=kwargs.get('ttl') or self.ttl,
               id=RandShort()
               ) /
            UDP(sport=RandShort(),
                dport=kwargs.get('dport') or self.dport
                ) /
            (kwargs.get('data') or self.data),
            timeout=kwargs.get('timeout') or self.timeout,
            verbose=kwargs.get('verbose') or self.verbose,
            retry=kwargs.get('retry') or self.retry
        )


class TracerouteICMP(GenericTraceroute):
    def __init__(self, **kwargs):
        super(TracerouteICMP, self).__init__(**kwargs)
        self.type = kwargs.get('type') or 8  # ICMP Echo Request
        self.data = kwargs.get('data') or 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    def traceroute(self, ip, **kwargs):
        return sr(
            IP(dst=ip,
               ttl=kwargs.get('ttl') or self.ttl,
               id=RandShort()
               ) /
            ICMP(type=kwargs.get('type') or self.type,
                 seq=RandShort()
                 ) /
            (kwargs.get('data') or self.data),
            timeout=kwargs.get('timeout') or self.timeout,
            verbose=kwargs.get('verbose') or self.verbose,
            retry=kwargs.get('retry') or self.retry
        )


################################################################################
# Scanning
# Port Scanning using Scapy: http://resources.infosecinstitute.com/port-scanning-using-scapy/

class GenericScan(object):
    def __init__(self, **kwargs):
        self.scan_mask = kwargs.get('scan_mask') or 26
        self.timeout = kwargs.get('timeout') or 10
        self.verbose = kwargs.get('verbose') or False
        self.retry = kwargs.get('retry') or 3

    def scan(self, net, **kwargs):
        raise NotImplemented('Unimplemented method.')

    def search_hosts(self, net, **kwargs):
        mask = kwargs.get('scan_mask') or self.scan_mask
        subnets = NetUtils.vlsm_divide(net, mask)
        subnets = NetUtils.unsort(subnets)
        hosts = []
        for subnet in subnets:
            hosts = self.scan(subnet, **kwargs)
            if len(hosts) > 0:
                break
        return hosts


class TCPStealthScan(GenericScan):
    def __init__(self, **kwargs):
        super(TCPStealthScan, self).__init__(**kwargs)
        self.ports = kwargs.get('ports') or [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139]  # Top 10 TCP Ports

    def scan(self, net, **kwargs):
        ans, _ = sr(
            IP(dst='%s/%d' % (net['ip'], net['mask']),
               id=RandShort()
               ) /
            TCP(sport=RandShort(),
                dport=kwargs.get('ports') or self.ports,
                flags='S'
                ),
            timeout=kwargs.get('timeout') or self.timeout,
            verbose=kwargs.get('verbose') or self.verbose,
            retry=kwargs.get('retry') or self.retry
        )
        hosts = []
        for (snd, rcv) in ans:
            if rcv.haslayer(TCP) and rcv.getlayer(TCP).flags == 0x12:  # flags: 0x02 SYN / 0x10 ACK
                send(
                    IP(dst=snd.dst) /
                    TCP(dport=snd.getlayer(TCP).dport,
                        sport=snd.getlayer(TCP).sport,
                        flags='R'
                        ),
                    verbose=kwargs.get('verbose') or self.verbose
                )
                hosts.append({'ip': snd.dst, 'port': snd.getlayer(TCP).dport})
        return hosts


class TCPConnectScan(GenericScan):
    def __init__(self, **kwargs):
        super(TCPConnectScan, self).__init__(**kwargs)
        self.ports = kwargs.get('ports') or [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139]  # Top 10 TCP Ports

    def scan(self, net, **kwargs):
        ans, _ = sr(
            IP(dst='%s/%d' % (net['ip'], net['mask']),
               id=RandShort()
               ) /
            TCP(sport=RandShort(),
                dport=kwargs.get('ports') or self.ports,
                flags='S'
                ),
            timeout=kwargs.get('timeout') or self.timeout,
            verbose=kwargs.get('verbose') or self.verbose,
            retry=kwargs.get('retry') or self.retry
        )
        hosts = []
        for (snd, rcv) in ans:
            if rcv.haslayer(TCP) and rcv.getlayer(TCP).flags == 0x12:  # flags: 0x02 SYN / 0x10 ACK
                send(
                    IP(dst=snd.dst) /
                    TCP(dport=snd.getlayer(TCP).dport,
                        sport=snd.getlayer(TCP).sport,
                        flags='AR'
                        ),
                    verbose=kwargs.get('verbose') or self.verbose
                )
                hosts.append({'ip': snd.dst, 'port': snd.getlayer(TCP).dport})
        return hosts


class PingScan(GenericScan):
    def __init__(self, **kwargs):
        super(PingScan, self).__init__(**kwargs)

    def scan(self, net, **kwargs):
        ans, _ = sr(
            IP(dst='%s/%d' % (net['ip'], net['mask']),
               id=RandShort()
               ) /
            ICMP(
                type=0x08  # ICMP Echo Request
            ) / 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            timeout=kwargs.get('timeout') or self.timeout,
            verbose=kwargs.get('verbose') or self.verbose,
            retry=kwargs.get('retry') or self.retry
        )
        hosts = []
        for (snd, rcv) in ans:
            if rcv.haslayer(ICMP) and rcv.getlayer(ICMP).type == 0x00:  # ICMP Echo Reply
                hosts.append({'ip': snd.dst, 'port': None})
        return hosts


################################################################################
# Tracenet

class Tracenet(object):
    def __init__(self, ip, **kwargs):
        self.ip = ip
        self.init_mask = kwargs.get('init_mask') or 29
        self.scanner = kwargs.get('scanner')  # None for don't perform scanning.
        self.traceroute = kwargs.get('traceroute') or TracerouteTCP()
        self.netmask_limit = kwargs.get('netmask_limit') or 24
        self.deep = kwargs.get('deep') or 3
        self.extra_info = kwargs.get('extra_info') or True

    def find_gateway(self, trace1, trace2):
        if len(trace1['path']) == 0 or len(trace2['path']) == 0:
            return None

        compl1 = trace1['dest'] == trace1['path'][-1]['ip']
        compl2 = trace2['dest'] == trace2['path'][-1]['ip']
        if not (compl1 or compl2):
            return None

        gateways = []

        dest1 = trace1['path'][-1]
        dest2 = trace2['path'][-1]
        if not compl1:
            dest1 = dest2
        if not compl2:
            dest2 = dest1

        idx1 = len(trace1['path']) - 1
        if compl1:
            idx1 -= 1
        while idx1 >= 0:
            hop1 = trace1['path'][idx1]
            if dest1['ttl'] - hop1['ttl'] > self.deep:
                break
            idx2 = len(trace2['path']) - 1
            if compl2:
                idx2 -= 1
            while idx2 >= 0:
                hop2 = trace2['path'][idx2]
                if dest2['ttl'] - hop2['ttl'] > self.deep:
                    break
                if hop1['ip'] == hop2['ip']:
                    gateways.append({'path1': hop1, 'path2': hop2})
                idx2 -= 1
            idx1 -= 1

        if len(gateways) == 0:
            return None

        major = gateways[0]
        major_val = (
            (dest1['ttl'] - major['path1']['ttl']) +
            (dest2['ttl'] - major['path2']['ttl']) +
            abs(major['path1']['ttl'] - major['path2']['ttl']))
        for idx in range(1, len(gateways)):
            gateway = gateways[idx]
            val = (
                (dest1['ttl'] - gateway['path1']['ttl']) +
                (dest2['ttl'] - gateway['path2']['ttl']) +
                abs(gateway['path1']['ttl'] - gateway['path2']['ttl']))
            if val < major_val:
                major = gateway
                major_val = val
        if major['path1']['ttl'] == major['path2']['ttl']:
            major = major['path1']
        elif major['path1']['ttl'] > major['path2']['ttl']:
            major = major['path1']
        else:
            major = major['path2']
        return major

    def tracenet(self, net):
        hosts = []
        dest = None

        if self.scanner is None:
            # sets the port to None for use the default value
            TracenetUtils.print_message(
                msg_type=TracenetUtils.MSG_WARN,
                msg='Host discovery is disabled. Using random IP.'
            )
            hosts.append({'ip': NetUtils.random_ip(net), 'port': None})
        else:
            TracenetUtils.print_message(
                msg_type=TracenetUtils.MSG_INFO,
                msg='Starting host discovery in subnet %s/%s. Please wait...' % (net['ip'], net['mask'])
            )
            hosts = self.scanner.search_hosts(net)
            if len(hosts) == 0:
                TracenetUtils.print_message(
                    msg_type=TracenetUtils.MSG_WARN,
                    msg='No hosts found. Using random IP.'
                )
                hosts.append({'ip': NetUtils.random_ip(net), 'port': None})

        TracenetUtils.print_hosts(hosts)

        path = []
        hosts = NetUtils.unsort(hosts)
        for host in hosts:
            if host['port'] is None:
                TracenetUtils.print_message(
                    msg_type=TracenetUtils.MSG_INFO,
                    msg='Starting traceroute to host %s. Please wait...' % host['ip']
                )
                path = self.traceroute.get_path(host['ip'])
            else:
                TracenetUtils.print_message(
                    msg_type=TracenetUtils.MSG_INFO,
                    msg='Starting traceroute to host %s at port %s. Please wait...' % (host['ip'], host['port'])
                )
                path = self.traceroute.get_path(host['ip'], dport=host['port'])
            if len(path) > 0:
                dest = host
                break
            else:
                TracenetUtils.print_message(
                    msg_type=TracenetUtils.MSG_WARN,
                    msg='Traceroute to host %s has failed. Trying with another...' % host['ip']
                )

        if len(path) == 0:
            return None  # the traceroute has failed

        for hop in path:
            info = None
            if self.extra_info:
                info = NetUtils.get_whois_info(hop['ip'])
            hop['info'] = info

        return {'dest': dest['ip'], 'path': path}

    def search_network(self):
        net = NetUtils.to_net(self.ip, self.init_mask)

        traces = []
        trace = self.tracenet(net)

        if trace is None:
            TracenetUtils.print_message(
                msg_type=TracenetUtils.MSG_ERROR,
                msg='The traceroute has failed'
            )
            return None  # the traceroute has failed
        traces.append(trace)

        TracenetUtils.print_traceroute(
            trace['path'],
            target=trace['dest'],
            gateway=None
        )

        while net['mask'] > self.netmask_limit:
            trace = self.tracenet(NetUtils.vlsm_complement(net))
            if trace is None:
                break

            gateways = [self.find_gateway(tr, trace) for tr in traces]
            gateways = [gw for gw in gateways if gw is not None]
            gateway = None
            for gw in gateways:
                if gateway is None:
                    gateway = gw
                elif gw['ttl'] > gateway['ttl']:
                    gateway = gw

            if gateway is None:
                TracenetUtils.print_traceroute(
                    trace['path'],
                    target=trace['dest'],
                    gateway=None
                )
                TracenetUtils.print_message(
                    msg_type=TracenetUtils.MSG_ERROR,
                    msg='No more common hops found'
                )
                break

            TracenetUtils.print_traceroute(
                trace['path'],
                target=trace['dest'],
                gateway=gateway['ip']
            )

            traces.append(trace)
            net = NetUtils.to_net(net['ip'], net['mask'] - 1)

            TracenetUtils.print_message(
                msg_type=TracenetUtils.MSG_INFO,
                msg='Current network range: %s/%s' % (net['ip'], net['mask'])
            )
        return net


class TracenetUtils(object):
    ESCSEQ = {
        'default': '\033[39m',
        'black': '\033[30m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'cyan': '\033[36m',
        'ligth_gray': '\033[37m',
        'dark_gray': '\033[90m',
        'ligth_red': '\033[91m',
        'ligth_green': '\033[92m',
        'ligth_yellow': '\033[93m',
        'ligth_blue': '\033[94m',
        'ligth_magenta': '\033[95m',
        'ligth_cyan': '\033[96m',
        'white': '\033[97m',
        'bold': '\033[1m',
        'clear_bold': '\033[21m',
        'clear': '\033[0m'
    }
    MSG_ERROR = 'ERROR'
    MSG_INFO = 'INFO'
    MSG_WARN = 'WARNING'

    @classmethod
    def print_line(cls, template='%%(color)s%(text)s%%(endl)s\n',
                   attrib={'color': ESCSEQ['red'], 'endl': ESCSEQ['clear']},
                   values={'text': 'Hello world!'}):
        line = (template % values) % attrib
        sys.stdout.write(line)

    @classmethod
    def get_info_string(cls, hop):
        info_string = '-'
        if 'info' in hop and hop['info'] is not None:
            info = hop['info']
            country = info['country'] if 'country' in info and info['country'] is not None else '??'
            descrip = info['description'] if 'description' in info and info['description'] is not None else 'unknown'
            if country == 'PE':
                country = '\033[31m\xe2\x96\x87\033[97m\xe2\x96\x87\033[31m\xe2\x96\x87\033[0m'  # PE flag
            info_string = '%s - %s' % (descrip, country)
        return info_string

    @classmethod
    def print_message(cls, msg_type=MSG_INFO, msg='Hallo Welt!'):
        template = '%%(attr_icon)s%(icon)s %%(attr_type)s%(type)s: %%(attr_msg)s%(msg)s%%(endl)s\n'
        if msg_type == TracenetUtils.MSG_INFO:
            color = TracenetUtils.ESCSEQ['green']
            icon = '[i]'
        elif msg_type == TracenetUtils.MSG_WARN:
            color = TracenetUtils.ESCSEQ['yellow']
            icon = '[!]'
        elif msg_type == TracenetUtils.MSG_ERROR:
            color = TracenetUtils.ESCSEQ['red']
            icon = '[x]'
        else:
            color = TracenetUtils.ESCSEQ['green']
            icon = '[i]'
        TracenetUtils.print_line(
            template=template,
            attrib={
                'attr_icon': TracenetUtils.ESCSEQ['bold'] + color,
                'attr_type': TracenetUtils.ESCSEQ['bold'] + color,
                'attr_msg': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['default'],
                'endl': TracenetUtils.ESCSEQ['clear']
            },
            values={'icon': icon, 'type': msg_type, 'msg': msg}
        )

    @classmethod
    def print_traceroute(cls, path, target=None, gateway=None):
        template = '%%(attr_field)s%(field)s: %%(attr_value)s%(value)s%%(endl)s\n'
        TracenetUtils.print_line(
            template=template,
            attrib={'attr_field': TracenetUtils.ESCSEQ['bold'] + TracenetUtils.ESCSEQ['green'],
                    'attr_value': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['green'],
                    'endl': TracenetUtils.ESCSEQ['clear']},
            values={'field': 'Target', 'value': target}
        )
        TracenetUtils.print_line(
            template=template,
            attrib={'attr_field': TracenetUtils.ESCSEQ['bold'] + TracenetUtils.ESCSEQ['yellow'],
                    'attr_value': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['yellow'],
                    'endl': TracenetUtils.ESCSEQ['clear']},
            values={'field': 'Gateway', 'value': gateway}
        )

        if gateway == target:
            gateway = None

        template = '%(tab)s%%(attr_line)s%(line)s[%%(attr_ttl)s%(ttl)s: %%(attr_ip)s%(ip)s%%(attr_info)s / %(info)s%%(attr_line)s]%%(endl)s\n'

        if len(path) == 0:
            TracenetUtils.print_message(
                msg_type=TracenetUtils.MSG_ERROR,
                msg='Empty traceroute.'
            )
        elif len(path) == 1:
            hop = path[0]
            attr_ip = TracenetUtils.ESCSEQ['green']
            if target is not None and hop['ip'] != target:
                attr_ip = TracenetUtils.ESCSEQ['red']
            info = TracenetUtils.get_info_string(hop)
            TracenetUtils.print_line(
                template=template,
                attrib={
                    'attr_line': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['ligth_blue'],
                    'attr_ttl': TracenetUtils.ESCSEQ['bold'] + TracenetUtils.ESCSEQ['cyan'],
                    'attr_ip': TracenetUtils.ESCSEQ['bold'] + attr_ip,
                    'attr_info': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['white'],
                    'endl': TracenetUtils.ESCSEQ['clear']
                },
                values={'tab': '', 'line': '-->', 'ttl': hop['ttl'], 'ip': hop['ip'], 'info': info}
            )
        else:
            ttls = [hop['ttl'] for hop in path]
            max_ttl = max(ttls)
            min_ttl = min(ttls)
            count = 0
            for ttl in xrange(min_ttl, max_ttl + 1):
                hop = [hop for hop in path if hop['ttl'] == ttl]
                if len(hop) == 0:
                    TracenetUtils.print_line(
                        template=template,
                        attrib={
                            'attr_line': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['ligth_blue'],
                            'attr_ttl': TracenetUtils.ESCSEQ['bold'] + TracenetUtils.ESCSEQ['cyan'],
                            'attr_ip': TracenetUtils.ESCSEQ['bold'] + TracenetUtils.ESCSEQ['dark_gray'],
                            'attr_info': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['white'],
                            'endl': TracenetUtils.ESCSEQ['clear']
                        },
                        values={'tab': ' ' * count, 'line': '`-,->', 'ttl': ttl, 'ip': 'unknown', 'info': '-'}
                    )
                    count += 2
                else:
                    hop = hop[0]
                    info = TracenetUtils.get_info_string(hop)
                    if hop['ttl'] == min_ttl:
                        attr_ip = TracenetUtils.ESCSEQ['white']
                        if gateway is not None and hop['ip'] == gateway:
                            attr_ip = TracenetUtils.ESCSEQ['yellow']

                        TracenetUtils.print_line(
                            template=template,
                            attrib={
                                'attr_line': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['ligth_blue'],
                                'attr_ttl': TracenetUtils.ESCSEQ['bold'] + TracenetUtils.ESCSEQ['cyan'],
                                'attr_ip': TracenetUtils.ESCSEQ['bold'] + attr_ip,
                                'attr_info': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['white'],
                                'endl': TracenetUtils.ESCSEQ['clear']
                            },
                            values={'tab': '', 'line': ',--', 'ttl': ttl, 'ip': hop['ip'], 'info': info}
                        )
                    elif hop['ttl'] == max_ttl:
                        attr_ip = TracenetUtils.ESCSEQ['green']
                        if target is not None and hop['ip'] != target:
                            attr_ip = TracenetUtils.ESCSEQ['red']
                        if gateway is not None and hop['ip'] == gateway:
                            attr_ip = TracenetUtils.ESCSEQ['yellow']

                        TracenetUtils.print_line(
                            template=template,
                            attrib={
                                'attr_line': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['ligth_blue'],
                                'attr_ttl': TracenetUtils.ESCSEQ['bold'] + TracenetUtils.ESCSEQ['cyan'],
                                'attr_ip': TracenetUtils.ESCSEQ['bold'] + attr_ip,
                                'attr_info': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['white'],
                                'endl': TracenetUtils.ESCSEQ['clear']
                            },
                            values={'tab': ' ' * count, 'line': '`--->', 'ttl': ttl, 'ip': hop['ip'], 'info': info}
                        )
                    else:
                        attr_ip = TracenetUtils.ESCSEQ['white']
                        if gateway is not None and hop['ip'] == gateway:
                            attr_ip = TracenetUtils.ESCSEQ['yellow']

                        TracenetUtils.print_line(
                            template=template,
                            attrib={
                                'attr_line': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['ligth_blue'],
                                'attr_ttl': TracenetUtils.ESCSEQ['bold'] + TracenetUtils.ESCSEQ['cyan'],
                                'attr_ip': TracenetUtils.ESCSEQ['bold'] + attr_ip,
                                'attr_info': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['white'],
                                'endl': TracenetUtils.ESCSEQ['clear']
                            },
                            values={'tab': ' ' * count, 'line': '`-,->', 'ttl': ttl, 'ip': hop['ip'], 'info': info}
                        )
                        count += 2

    @classmethod
    def print_hosts(cls, hosts):
        if len(hosts) > 0:
            temp = {}
            for host in hosts:
                ip = host['ip']
                if ip not in temp:
                    temp[ip] = []
                if host['port'] not in temp[ip]:
                    temp[ip].append(host['port'])
            hosts = [{'ip': ip, 'ports': temp[ip]} for ip in temp]
            more = 0
            if len(hosts) > 10:
                more = len(hosts) - 10
                hosts = hosts[:10]
            template = '%%(attr_ip)s%(ip)s: %%(attr_ports)s%(ports)s%%(endl)s\n'
            for host in hosts:
                TracenetUtils.print_line(
                    template=template,
                    attrib={
                        'attr_ip': TracenetUtils.ESCSEQ['bold'] + TracenetUtils.ESCSEQ['white'],
                        'attr_ports': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['blue'],
                        'endl': TracenetUtils.ESCSEQ['clear']
                    },
                    values={'ip': host['ip'], 'ports': host['ports']}
                )
            if more > 0:
                TracenetUtils.print_line(
                    template='%%(color)s( %(num)s hosts more... )%%(endl)s\n',
                    attrib={
                        'color': TracenetUtils.ESCSEQ['clear_bold'] + TracenetUtils.ESCSEQ['ligth_gray'],
                        'endl': TracenetUtils.ESCSEQ['clear']
                    },
                    values={'num': more}
                )
        else:
            pass


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='A tool for network range discovery using traceroute.',
        epilog='Author: Alguien (@alguien_tw) | alguien.site')
    parser.add_argument('ip', metavar='IP', type=str, help='Any IP address in the target network')
    parser.add_argument('-m', '--mask', type=int, help='Initial netmask (default: /29)', default=29)
    parser.add_argument('-l', '--mask-limit', type=int, help='Netmask limit (default: /24)', default=None)

    parser.add_argument('-nW', '--no-whois', action='store_true', default=False,
                        help='Don\'t use whois to autoconfig the netmask limit')
    parser.add_argument('-nI', '--no-info', action='store_true', default=False,
                        help='Don\'t use whois to display extra info')

    parser.add_argument('--timeout', type=int, help='Timeout for portscan and traceroute (default: 10)', default=10)
    parser.add_argument('--min-ttl', type=int, help='Minimum TTL for traceroute (default: 1)', default=1)
    parser.add_argument('--max-ttl', type=int, help='Maximum TTL for traceroute (default: 20)', default=20)
    parser.add_argument('--deep', type=int, help='Maximum deep for finding a common hop (default: 3)', default=3)

    # Scan Techniques
    parser.add_argument('-sn', '--no-scan', action='store_true', default=False, help='Don\'t perform host scanning')
    parser.add_argument('-sT', '--tcp-scan', action='store_true', default=False,
                        help='Search hosts using TCP-CONNECT-scan (default)')
    parser.add_argument('-sS', '--syn-scan', action='store_true', default=False, help='Search hosts using SYN-scan')
    parser.add_argument('-sP', '--ping-scan', action='store_true', default=False, help='Search hosts using PING-scan')

    # Traceroute Techniques
    parser.add_argument('-tT', '--tcp-trace', action='store_true', default=False,
                        help='Traceroute using TCP packets (default)')
    parser.add_argument('-tU', '--udp-trace', action='store_true', default=False,
                        help='Traceroute using UDP packets')
    parser.add_argument('-tI', '--icmp-trace', action='store_true', default=False,
                        help='Traceroute using ICMP packets')

    # Graph Options
    parser.add_argument('--graph', type=str, help='Save the traceroute graph to file (SVG format)', default=None)

    return parser.parse_args()


def main():
    args = parse_arguments()

    if os.geteuid() != 0:
        TracenetUtils.print_message(
            msg_type=TracenetUtils.MSG_ERROR,
            msg='You must be root.'
        )
        exit()

    mask_limit = args.mask_limit
    if mask_limit is None:
        if not args.no_whois:
            whois_net = NetUtils.get_network_via_whois(args.ip)[0]
            mask_limit = whois_net['mask']
            TracenetUtils.print_message(
                msg_type=TracenetUtils.MSG_INFO,
                msg='Using whois for setting netmask limit. Netmask limit: %s' % mask_limit
            )
        else:
            mask_limit = 24
            TracenetUtils.print_message(
                msg_type=TracenetUtils.MSG_INFO,
                msg='Using default netmask limit. Netmask limit: %s' % mask_limit
            )

    scanner = None
    if not args.no_scan:
        if args.syn_scan:
            scanner = TCPStealthScan(timeout=args.timeout)
        elif args.tcp_scan:
            scanner = TCPConnectScan(timeout=args.timeout)
        elif args.ping_scan:
            scanner = PingScan(timeout=args.timeout)
        else:
            scanner = TCPConnectScan(timeout=args.timeout)  # Default

    if args.tcp_trace:
        traceroute = TracerouteTCP(timeout=args.timeout, ttl=(args.min_ttl, args.max_ttl))
    elif args.udp_trace:
        traceroute = TracerouteUDP(timeout=args.timeout, ttl=(args.min_ttl, args.max_ttl))
    elif args.icmp_trace:
        traceroute = TracerouteICMP(timeout=args.timeout, ttl=(args.min_ttl, args.max_ttl))
    else:
        traceroute = TracerouteTCP(timeout=args.timeout, ttl=(args.min_ttl, args.max_ttl))  # Default

    extra_info = not args.no_info
    tracenet = Tracenet(
        args.ip,
        init_mask=args.mask,
        netmask_limit=mask_limit,
        scanner=scanner,
        traceroute=traceroute,
        deep=args.deep,
        extra_info=extra_info
    )

    net = tracenet.search_network()
    if net is not None:
        TracenetUtils.print_message(
            msg_type=TracenetUtils.MSG_INFO,
            msg='Network range: %s/%s' % (net['ip'], net['mask'])
        )
    else:
        TracenetUtils.print_message(
            msg_type=TracenetUtils.MSG_ERROR,
            msg='Network range not found :('
        )

    if args.graph is not None:
        filename = args.graph
        if filename[-4:].lower() != '.svg':
            filename += '.svg'
        traceroute.graph_tofile(filename)
        TracenetUtils.print_message(
            msg_type=TracenetUtils.MSG_INFO,
            msg='Traceroute graph saved to: %s' % filename
        )

    TracenetUtils.print_message(
        msg_type=TracenetUtils.MSG_INFO,
        msg='Done'
    )


if __name__ == '__main__':
    main()
