from ..base.test import Test, grade
# from ..base.logger import logger
from scapy.all import *
import copy
import socket, struct

ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_MPLS = 0x08848
IPPROTO_UDP = 0x0011

ARP_TYPE_REQUEST = 1
ARP_TYPE_REPLY = 2

MPLS_LABEL_MASK = 0xfffff000
MPLS_LABEL_SHIFT = 12
MPLS_EXP_MASK = 0x00000e00
MPLS_EXP_SHIFT = 9
MPLS_S_MASK = 0x00000100
MPLS_S_SHIFT = 8

MTP_TYPE_MASK = 0xff000000
MTP_TYPE_SHIFT = 24
MTP_LABEL_MASK = 0x000fffff
MTP_LABEL_SHIFT = 0


HTYPE_Ether = 0x0001
PTYPE_IPv4 = 0x0800
HLEN_Ether = 0x06
PLEN_IPv4  = 0x04

broadcast_MAC = 'ff:ff:ff:ff:ff:ff'

vpn_names = ['vpn-A', 'vpn-B']
mtp_types = {'Reply':0x01, 'Request':0x02, 'Ack':0x03}

def read_main_memory(address):
    return address * address * address * address

def read_output(client):
    out = []
    line = client.read_io(timeout=1)
    while line != None:
        line = line.strip(" \n\t\r")
        out.append(line)
        line = client.read_io(timeout=1)
    return out

def read_recv_frames(client, iface_index):
    frames = []
    frame = client.get_recv_frame(iface=iface_index,timeout=1)
    while frame != None:
        frames.append(frame)
        frame = client.get_recv_frame(iface=iface_index,timeout=1)
    return frames

def read_send_frames(client, iface_index):
    frames = []
    frame = client.get_send_frame(iface=iface_index, timeout=1)
    while frame != None:
        frames.append(frame)
        frame = client.get_send_frame(iface=iface_index, timeout=1)
    return frames

def check_output(output, true_output):
    if len(output) != len(true_output):
        print output
        print true_output
        return False
    founded_outputs = []
    for i in range(0, len(output)):
        founded_outputs.append(False)
    for i in range(0, len(output)):
        for j in range (0, len(output)):
            # print 'myOutput:{} true_output:{}'.format(output[i], true_output[j])
            if not founded_outputs[j] and output[i] != None and output[i].lower() == true_output[j].lower():
                founded_outputs[j] = True
                break
        else:
            print output
            print true_output
            return False
    return True

# def extract_flit_fields(frame):
#     flit = str(frame.payload.payload.payload)
#     if len(flit) != 11:
#         return None, None, None
#     cf_head = str(struct.unpack('B', str(frame.payload.payload.payload)[0])[0])
#     cf_address = str(struct.unpack('!H', str(frame.payload.payload.payload)[1:3])[0])
#     cf_data = str(struct.unpack('!Q', str(frame.payload.payload.payload)[3:11])[0])
#     return cf_head, cf_address, cf_data

# def check_arp_src_dst(frame, arp_t):
#     arp = frame.payload
#     if arp.hwtype != arp_t['htype'] or arp.ptype != arp_t['ptype'] or arp.hwlen != arp_t[hlen] or\
#         arp.plen != arp_t['plen'] or arp.op != arp_t['type'] or arp.hwsrc.lower() != arp_t['smac'] or\
#         arp.psrc != arp_t['sip'] or arp.pdst != arp_t['dip']:
#         return False
#     if arp_t['type'] == ARP_TYPE_REPLY:
#         if arp.hwdst.lower() != arp_t['dmac']:
#             return False
#     return True

def check_mac_src_dst(frame , src , dst):
    if frame.src.lower() == src.lower() and\
            frame.dst.lower() == dst.lower():
                return True
    print 'frame {}to{}'.format(frame.src, frame.dst)
    print 'my    {}to{}'.format(src, dst)
    return False 

def compare_arp(payload, arp_h):
    if payload.hwtype == arp_h.hwtype and payload.ptype == arp_h.ptype and payload.hwlen == arp_h.hwlen and\
        payload.plen == arp_h.plen and payload.hwsrc.lower() == arp_h.hwsrc.lower() and\
        payload.psrc.lower() == arp_h.psrc.lower() and payload.hwdst.lower() == arp_h.hwdst.lower() and\
        payload.pdst.lower() == arp_h.pdst.lower():
        return True
    print '{} {} {} {} {} {} {} {}'.format(payload.hwtype, payload.ptype, payload.hwlen, payload.plen, payload.hwsrc.lower(),
                        payload.psrc.lower(), payload.hwdst.lower(), payload.pdst.lower())
    print '{} {} {} {} {} {} {} {}'.format(arp_h.hwtype, arp_h.ptype, arp_h.hwlen, arp_h.plen, arp_h.hwsrc.lower(),
                        arp_h.psrc.lower(), arp_h.hwdst.lower(), arp_h.pdst.lower())
    return False

def compare_ip(payload, ip_h):
    if payload.src.lower() == ip_h.src.lower() and payload.dst.lower() == ip_h.dst.lower() and\
        payload.proto == ip_h.proto and payload.payload.sport == ip_h.payload.sport and\
        payload.payload.dport == ip_h.payload.dport:
        return True
    print '{} {} {}'.format(payload.src.lower(), payload.dst.lower(), payload.proto)
    print '{} {} {}'.format(ip_h.src.lower(), ip_h.dst.lower(), ip_h.proto)
    return False

def compare_mpls(payload, mpls_h):
    if payload.label != mpls_h.label or payload.experimental_bits != mpls_h.experimental_bits or\
        payload.bottom_of_label_stack != mpls_h.bottom_of_label_stack:
        print 'label{} exp{} s{}'.format(payload.label, payload.experimental_bits, payload.bottom_of_label_stack)
        print 'label{} exp{} s{}'.format(mpls_h.label, mpls_h.experimental_bits, mpls_h.bottom_of_label_stack)
        return False
    if mpls_h.bottom_of_label_stack == 0:
        return compare_mpls(payload.payload, mpls_h.payload)
    else:
        return compare_ip(payload.payload, mpls_h.payload)

# def check_ip_src_dst(frame , ip_h): # src and dst must give in strin format
#     if frame.payload.payload != None and frame.payload.src.lower() == src.lower() and\
#             frame.payload.dst.lower() == dst.lower() and frame.payload.payload.sport == sport and\
#             frame.payload.payload.dport == dport:
#                 return True
#     return False
# 
# def check_labels(frame, labels):
#     str_label = str(frame.payload)
#     mpls_head = 0
#     for i in labels:
#         mpls_header = struct.unpack('!I', str_label[mpls_head:(mpls_head+4)])[0]
#         label = (mpls_header & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT
#         s = (mpls_header & MPLS_S_MASK) >> MPLS_S_SHIFT
#         if label != i['label'] or s != i['s']:
#             return False
#         mpls_head += 4
#     return True

# def check_mpls(frame, labels, src, dst, sport, dport):
#     mpls_h = frame.payload
#     target_mpls = labels[0]
#     if mpls_h.label != target_mpls['label'] or mpls_h.experimental_bits != target_mpls['exp'] or\
#         mpls_h.bottom_of_label_stack != target_mpls['s']:
#         return False
#     if mpls_h.bottom_of_label_stack == 0:
#         target_mpls = labels[1]
#         mpls_h = frame.payload.payload
#         if mpls_h.label != target_mpls['label'] or mpls_h.experimental_bits != target_mpls['exp'] or\
#             mpls_h.bottom_of_label_stack != target_mpls['s']:
#             return False
#     ip_h = frame.payload.payload.payload
#     if ip_h.src.lower() != src.lower() or ip_h.dst.lower() != dst.lower() or\
#         ip_h.payload.sport != sport or ip_h.payload.dport != dport:
#         return False
#     return True


def clear(routers , real):
    time.sleep(2)
    for router in routers:
        router.clear(real)

def ip2uint(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]

def uint2ip(ip):
    return socket.inet_ntoa(struct.pack("!L", ip))

def get_router_mac(i, index):
    initial_mac = '00:24:8C:09:00:01'.split(':')
    last_part = int(initial_mac[5], 16)
    last_part += 5 * i + index
    initial_mac[5] = '%0.2x' % last_part
    return ":".join(initial_mac)

def get_router_ip(i, index):
    if i == 0:
        if index == 0:
            return '192.168.145.1'
        if index == 1:
            return '192.168.144.1'
        if index == 2:
            return '192.168.156.1'
    if i == 1:
        if index == 0:
            return '192.168.155.1'
        if index == 1:
            return '192.168.145.2'
    if i == 2:
        if index == 0:
            return '192.168.144.2'
        if index == 1:
            return '192.168.154.1'
    if i == 3:
        if index == 0:
            return '192.168.154.2'
        if index == 1:
            return '192.168.200.4'
        if index == 2:
            return '192.168.200.5'
    if i == 4:
        if index == 0:
            return '192.168.156.2'
        if index == 1:
            return '192.168.201.4'
    if i == 5:
        if index == 0:
            return '192.168.155.2'
        if index == 1:
            return '192.168.202.4'
        if index == 2:
            return '192.168.202.5'
    if i == 6:
        if index == 0:
            return '192.168.200.2'
    if i == 7:
        if index == 0:
            return '192.168.200.2'
    if i == 8:
        if index == 0:
            return '192.168.201.2'
    if i == 9:
        if index == 0:
            return '192.168.202.2'
    if i == 10:
        if index == 0:
            return '192.168.202.2'

def check_unordered_frame_lists(flist0, flist1):
    if len(flist0) != len(flist1):
        return False
    founded_frames = []
    for i in xrange(len(flist0)):
        founded_frames.append(False)
    for i in xrange(len(flist0)):
        # if not flist1[i].equal(flist0[i]):
        #     return False
        for j in xrange (len(flist1)):
            if not founded_frames[j]:
                if flist1[j].equal(flist0[i]):
                    founded_frames[j] = True
                    break
        else:
            return False
    return True

class Router:
    def __init__(self, client, default_table, int_vpn, vrf_tables, tunnel_table, ls_table, id_router, max_label):
        self.client = client
        self.default_table = default_table
        self.int_vpn = int_vpn
        self.vrf_tables = vrf_tables
        self.tunnel_table = tunnel_table
        self.ls_table = ls_table 
        self.output = []
        self.send_frames = [] #Each interface has its own frames
        self.recv_frames = [] #Each interface has its own frames
        self.neighbors = []
        self.id = id_router
        self.max_label = max_label
        self.mtpLogs = {}
        

    def set_conneted_routers(self, neighbor_routers):
        self.neighbors = neighbor_routers
        for i in xrange(0, len(self.neighbors)):
            self.send_frames.append([])
            self.recv_frames.append([])

    def find_default(self, dest_ip):
        index = None
        max_mask = 0
        for i in xrange(0, len(self.default_table)):
            ip = self.default_table[i].get('ip')
            mask = self.default_table[i].get('mask')
            if (ip & mask) == (dest_ip & mask):
                if mask > max_mask:
                    index = i
                    max_mask = mask
        return index

    def find_neighbors(self, dest_ip):
        mask = ip2uint('255.255.255.0')
        for i in xrange(0, len(self.neighbors)):
            if (ip2uint(get_router_ip(self.id, i)) & mask) == (dest_ip & mask):
                return i
        return None

    def isMine(self, dest_ip):
        for i in xrange(0, len(self.neighbors)):
            if dest_ip == ip2uint(get_router_ip(self.id, i)):
                return True
        return False 

    def find_ce_ip(self, vrf_table, dest_ip):
        res = None
        max_mask = 0
        for i in vrf_table:
            if (dest_ip & i.get('mask')) == (i.get('ip') & i.get('mask')):
                if i.get('mask') > max_mask:
                    res = i
        return res

    def find_tunnel(self, pe_dest_ip):
        for i in xrange(0, len(self.tunnel_table)):
            if pe_dest_ip == self.tunnel_table[i].get('ip'):
                return self.tunnel_table[i]
        return None

    def send_ip(self, src_ip, dest_ip, sport, dport, income_interface, msg):
        # logger.log("hi")
        if income_interface != -1:
            if self.isMine(ip2uint(dest_ip)):
                self.output.append("a message from %s : %s" % (src_ip, msg))
                return
            target_vrf = self.int_vpn[income_interface].get('vpn')
            if target_vrf != -1:
                self.output.append("a packet from %s received" % vpn_names[target_vrf - 1])
                vrf_table = self.vrf_tables[target_vrf - 1]
                vpn_ce = self.find_ce_ip(vrf_table, ip2uint(dest_ip))
                if vpn_ce is None:
                    return
                if vpn_ce.get('egress-interface') != -1:
                    neighbor = self.neighbors[vpn_ce.get('egress-interface')]
                    interface = vpn_ce.get('egress-interface')
                    self.arp(vpn_ce.get('out-ip'), interface, 'Request')

                    send_frame = MockFrame(get_router_mac(self.id, interface),
                            get_router_mac(neighbor.get('router').id, neighbor.get('interface_match')), ETHERTYPE_IP)
                    send_frame.ip(src_ip, dest_ip, sport, dport, msg)
                    self.send_frame[interface].append(send_frame)
                    self.neighbors[interface].get('router').recv_frames[neighbor.get('interface_match')].append(send_frame)
                    
                    neighbor.get('router').send_ip(src_ip, dest_ip, sport, dport, neighbor.get('interface_match'), msg)
                    return    
                
                out_ip = vpn_ce.get('out-ip')
                target_tunnel = self.find_tunnel(out_ip)
                if target_tunnel is None:
                    return
                interface = target_tunnel.get('egress-interface')

                self.output.append("the label %d added to %s" % (vpn_ce.get('vpn-label'), uint2ip(out_ip)))
                self.output.append("the label %d added to %s" % (target_tunnel.get('tunnel-label'), uint2ip(out_ip)))
                self.output.append("the packet with label %d forwarded on %d" % (target_tunnel.get('tunnel-label'), interface))
                
                send_frame = MockFrame(get_router_mac(self.id, interface), target_tunnel.get('next-mac'), ETHERTYPE_MPLS)
                send_frame.mpls(target_tunnel.get('tunnel-label'), vpn_ce.get('vpn-label'), src_ip, dest_ip, sport, dport, msg)
                self.send_frames[interface].append(send_frame)
                self.neighbors[interface].get('router').recv_frames[self.neighbors[interface].get('interface_match')].append(send_frame)

                self.neighbors[interface].get('router').mpls(target_tunnel.get('tunnel-label'), 
                                                                                        vpn_ce.get('vpn-label'), src_ip, dest_ip, msg)
                return
        # cmd = 'send %s N/A %s' %(dest_ip, msg)
        # self.client.write_io(cmd)

        if self.isMine(ip2uint(dest_ip)):
            self.output.append("a message from %s : %s" % (get_router_ip(self.id, 0), msg))
            return
        index = self.find_neighbors(ip2uint(dest_ip))
        interface = None
        nh_ip = None
        if index is not None:
            nh_ip = ip2uint(dest_ip)
            interface = index
        else:
            index = self.find_default(ip2uint(dest_ip))
            if index is not None:
                nh_ip = self.default_table[index].get('nh-ip')
                interface = self.default_table[index].get('nh-interface')
            if interface is None:
                return
        if income_interface == -1:
            src_ip = get_router_ip(self.id, interface)
        self.arp(nh_ip, interface, 'Request')

        send_frame = MockFrame(get_router_mac(self.id, interface), get_router_mac(self.neighbors[interface].get('router').id, self.neighbors[interface].get('interface_match')), ETHERTYPE_IP)
        send_frame.ip(src_ip, dest_ip, sport, dport, msg)
        self.send_frames[interface].append(send_frame)
        self.neighbors[interface].get('router').recv_frames[self.neighbors[interface].get('interface_match')].append(send_frame)
    
        self.output.append("the packet for %s forwarded to %s on %d" % (dest_ip, uint2ip(nh_ip), interface))
        self.neighbors[interface].get('router').send_ip(src_ip, dest_ip, sport, dport, self.neighbors[interface].get('interface_match'), msg)
        return

    def find_LS(self, ingress_label):
        for i in xrange(0, len(self.ls_table)):
            if self.ls_table[i].get('ingress-label') == ingress_label:
                return self.ls_table[i]
        return None

    def find_ce_label(self, vrf_table, label):
        for i in vrf_table:
            if i.get('vpn-label') == label:
                return i
        return None

    def mpls(self, tunnel_label, vpn_label, src_ip, dest_ip, msg, initail_vpn=False, vpn_index=-1):
        if initail_vpn is True:
            if vpn_index == -1:
                return
            target_ce = self.find_ce_label(self.vrf_tables[vpn_index], vpn_label)
            if target_ce is None:
                return
            if target_ce.get('egress-interface') != -1:
                next_ip = target_ce.get('out-ip')
                interface = target_ce.get('egress-interface')
                self.arp(next_ip, interface, 'Request')

                send_frame = MockFrame(get_router_mac(self.id, interface), get_router_mac(self.neighbors[interface].get('router').id, self.neighbors[interface].get('interface_match')), ETHERTYPE_IP)
                send_frame.ip(src_ip, dest_ip, 5000, 3000, msg)
                self.send_frames[interface].append(send_frame)
                self.neighbors[interface].get('router').recv_frames[self.neighbors[interface].get('interface_match')].append(send_frame)
            
                self.output.append("the packet for %s forwarded to %s on %d" % (dest_ip, uint2ip(next_ip), interface))
                self.neighbors[interface].get('router').send_ip(src_ip, dest_ip, 5000, 3000, self.neighbors[interface].get('interface_match'), msg)
                return

            out_ip = target_ce.get('out-ip')  
            target_tunnel = self.find_tunnel(out_ip)
            if target_tunnel is None:
                return

            if target_tunnel.get('tunnel-label') != -1:
                interface = target_tunnel.get('egress-interface')

                self.output.append("the label %d added to %s" % (vpn_label, uint2ip(out_ip)))
                self.output.append("the label %d added to %s" % (target_tunnel.get('tunnel-label'), uint2ip(out_ip)))
                self.output.append("the packet with label %d forwarded on %d" % (target_tunnel.get('tunnel-label'), interface))
                
                send_frame = MockFrame(get_router_mac(self.id, interface), target_tunnel.get('next-mac'), ETHERTYPE_MPLS)
                send_frame.mpls(target_tunnel.get('tunnel-label'), vpn_label, src_ip, dest_ip, 5000, 3000, msg)
                self.send_frames[interface].append(send_frame)
                self.neighbors[interface].get('router').recv_frames[self.neighbors[interface].get('interface_match')].append(send_frame)

                self.neighbors[interface].get('router').mpls(target_tunnel.get('tunnel-label'), 
                                                                                        vpn_label, src_ip, dest_ip, msg)
                return

            interface = target_tunnel.get('egress-interface')

            self.output.append("the label %d added to %s" % (vpn_label, uint2ip(out_ip)))
            self.output.append("the packet with label %d forwarded on %d" % (vpn_label, interface))
            
            send_frame = MockFrame(get_router_mac(self.id, interface), target_tunnel.get('next-mac'), ETHERTYPE_MPLS)
            send_frame.mpls(target_tunnel.get('tunnel-label'), vpn_label, src_ip, dest_ip, 5000, 3000, msg)
            self.send_frames[interface].append(send_frame)
            self.neighbors[interface].get('router').recv_frames[self.neighbors[interface].get('interface_match')].append(send_frame)

            self.neighbors[interface].get('router').mpls(target_tunnel.get('tunnel-label'), 
                                                                                    vpn_label, src_ip, dest_ip, msg)
            return


        target_label = tunnel_label
        if tunnel_label == -1:
            target_label = vpn_label

        target_ls = self.find_LS(target_label)
        if target_ls is None:
            return
        egress_label = target_ls.get('egress-label')

        if egress_label != -1:
            self.output.append("the packet with label %d forwarded with label %d on %d" % (target_label, egress_label, target_ls.get('egress-interface')))
            
            send_frame = MockFrame(get_router_mac(self.id, target_ls.get('egress-interface')), target_ls.get('egress-mac'), ETHERTYPE_MPLS)
            send_frame.mpls(egress_label, vpn_label, src_ip, dest_ip, 5000, 3000, msg)
            self.send_frames[target_ls.get('egress-interface')].append(send_frame)
            self.neighbors[target_ls.get('egress-interface')].get('router').recv_frames[self.neighbors[target_ls.get('egress-interface')].get('interface_match')].append(send_frame)

            self.neighbors[target_ls.get('egress-interface')].get('router').mpls(egress_label, vpn_label, src_ip, dest_ip, msg)
            return
        if egress_label == -1:
            self.output.append("the label of the packet with label %d popped" % target_label)
            egress_mac = target_ls.get('egress-mac')
            if len(egress_mac) != 1:
                 self.output.append("the packet with label %d forwarded on %d" % (vpn_label, target_ls.get('egress-interface')))
                 
                 send_frame = MockFrame(get_router_mac(self.id, target_ls.get('egress-interface')), target_ls.get('egress-mac'), ETHERTYPE_MPLS)
                 send_frame.mpls(egress_label, vpn_label, src_ip, dest_ip, 5000, 3000, msg)
                 self.send_frames[target_ls.get('egress-interface')].append(send_frame)
                 self.neighbors[target_ls.get('egress-interface')].get('router').recv_frames[self.neighbors[target_ls.get('egress-interface')].get('interface_match')].append(send_frame)

                 self.neighbors[target_ls.get('egress-interface')].get('router').mpls(-1, vpn_label, src_ip, dest_ip, msg)
                 return
            if len(egress_mac) == 1:
                vrf_table = self.vrf_tables[int(egress_mac) - 1]
                target_ce = self.find_ce_label(vrf_table, vpn_label)
                if target_ce is None:
                   return
                nh_ip = target_ce.get('out-ip')
                if target_ce.get('egress-interface') != -1:
                    interface = target_ce.get('egress-interface') 
                    neighbor = self.neighbors[target_ce.get('egress-interface')]

                    self.arp(nh_ip, interface, 'Request')
                    self.output.append("the packet for %s forwarded to %s on %d" % (dest_ip, uint2ip(nh_ip), interface))
                    
                    send_frame = MockFrame(get_router_mac(self.id, interface), 
                                            get_router_mac(neighbor.get('router').id, neighbor.get('interface_match')), ETHERTYPE_IP)
                    send_frame.ip(src_ip, dest_ip, 5000, 3000, msg)
                    self.send_frames[interface].append(send_frame)
                    neighbor.get('router').recv_frames[neighbor.get('interface_match')].append(send_frame)

                    neighbor.get('router').send_ip(src_ip, dest_ip, 5000, 3000, neighbor.get('interface_match'), msg)
                    return
                if target_ce.get('egress-interface') == -1:   
                    target_tunnel = self.find_tunnel(target_ce.get('out-ip'))
                    if target_tunnel is None:
                        return
                    out_ip = target_ce.get('out-ip')
                    interface = target_tunnel.get('egress-interface')
                    neighbor = self.neighbors[target_tunnel.get('egress-interface')]

                    self.output.append("the label %d added to %s" % (target_ce.get('vpn-label'), uint2ip(out_ip)))
                    self.output.append("the label %d added to %s" % (target_tunnel.get('tunnel-label'), uint2ip(out_ip)))
                    self.output.append("the packet with label %d forwarded on %d" % (target_tunnel.get('tunnel-label'), interface))
                    
                    send_frame = MockFrame(get_router_mac(self.id, interface), target_tunnel.get('next-mac'), ETHERTYPE_MPLS)
                    send_frame.mpls(target_tunnel.get('tunnel-label'), target_ce.get('vpn-label'), src_ip, dest_ip, 5000, 3000, msg)
                    self.send_frames[interface].append(send_frame)
                    neighbor.get('router').recv_frames[neighbor.get('interface_match')].append(send_frame)
                    
                    neighbor.get('router').mpls(target_tunnel.get('tunnel-label'), 
                                                target_ce.get('vpn-label'), src_ip, dest_ip, msg)
                    return
        return

    def arp(self, target_ip, target_interface, type):
        if type == 'Request':
            self.output.append("the ARP request sent for %s" % uint2ip(target_ip) )
            send_frame = MockFrame(get_router_mac(self.id, target_interface), broadcast_MAC, ETHERTYPE_ARP)
            send_frame.arp(ARP_TYPE_REQUEST, get_router_mac(self.id, target_interface), get_router_ip(self.id, target_interface),
                            0, uint2ip(target_ip))
            self.send_frames[target_interface].append(send_frame)
            self.neighbors[target_interface].get('router').recv_frames[self.neighbors[target_interface].get('interface_match')].append(send_frame)
            self.neighbors[target_interface].get('router').arp(ip2uint(get_router_ip(self.id, target_interface)), self.neighbors[target_interface].get('interface_match'), 'Reply')
            return
        if type == 'Reply':
            self.output.append("the ARP response sent to %s" % uint2ip(target_ip))
            send_frame = MockFrame(get_router_mac(self.id, target_interface), get_router_mac(self.neighbors[target_interface].get('router').id, self.neighbors[target_interface].get('interface_match')), ETHERTYPE_ARP)
            send_frame.arp(ARP_TYPE_REPLY, get_router_mac(self.id, target_interface), get_router_ip(self.id, target_interface),
                            get_router_mac(self.neighbors[target_interface].get('router').id, self.neighbors[target_interface].get('interface_match')), uint2ip(target_ip))
            self.send_frames[target_interface].append(send_frame)
            self.neighbors[target_interface].get('router').recv_frames[self.neighbors[target_interface].get('interface_match')].append(send_frame)
            return

    def mtp(self, income_interface, src_ip, dest_ip, src_port, dest_port, ingress_ip, egress_ip, type_mtp, label):
        if self.isMine(ip2uint(dest_ip)) is False:
            index = self.find_neighbors(ip2uint(dest_ip))
            interface = None
            nh_ip = None
            if index is not None:
                nh_ip = ip2uint(dest_ip)
                interface = index
            else:
                index = self.find_default(ip2uint(dest_ip))
                if index is not None:
                    nh_ip = self.default_table[index].get('nh-ip')
                    interface = self.default_table[index].get('nh-interface')
                if interface is None:
                    return
            self.arp(nh_ip, interface, 'Request')
            
            next_router = self.neighbors[interface].get('router')
            interface_match = self.neighbors[interface].get('interface_match')
            send_frame = MockFrame(get_router_mac(self.id, interface), get_router_mac(next_router.id, interface_match), ETHERTYPE_IP)
            send_frame.mtp(src_ip, dest_ip, src_port, dest_port, type_mtp, label, ingress_ip, egress_ip)
            self.send_frames[interface].append(send_frame)
            next_router.recv_frames[interface_match].append(send_frame)

            self.neighbors[interface].get('router').mtp(interface_match, src_ip, dest_ip, src_port, dest_port, ingress_ip, egress_ip, type_mtp, label)
            return
        else:
            if type_mtp == mtp_types['Request']:
                log = mtpLog(ingress_ip, egress_ip)

                self.output.append("mtp request from %s received" % ingress_ip)
                interface = None
                nh_ip = None
                if index is not None:
                    nh_ip = ip2uint(ingress_ip)
                    interface = index
                else:
                    index = self.find_default(ip2uint(ingress_ip))
                    if index is not None:
                        nh_ip = self.default_table[index].get('nh-ip')
                        interface = self.default_table[index].get('nh-interface')
                    if interface is None:
                        return
                sug_label = self.max_label + 1
                log.src['label'] = sug_label
                log.src['interface'] = interface
                log.dest['set'] = True
                self.mtpLogs[ingress_ip] = log

                self.arp(nh_ip, interface, 'Request')
                self.output.append("mtp reply with label %d sent to %s" % (sug_label, uint2ip(nh_ip)))
                
                next_router = self.neighbors[interface].get('router')
                interface_match = self.neighbors[interface].get('interface_match')
                send_frame = MockFrame(get_router_mac(self.id, interface), get_router_mac(next_router.id, interface_match), ETHERTYPE_IP)
                send_frame.mtp(get_router_ip(self.id, interface), get_router_ip(next_router.id, interface_match), 
                                8000, 7000, mtp_types['Reply'], sug_label, ingress_ip, egress_ip)
                self.send_frames[interface].append(send_frame)
                next_router.recv_frames[interface_match].append(send_frame)
                
                self.neighbors[interface].get('router').mtp(interface_match, get_router_ip(self.id, interface), uint2ip(nh_ip), 8000, 7000, ingress_ip, egress_ip, mtp_types['Reply'], sug_label)
                return
            if type_mtp == mtp_types['Reply']:
                log = self.mtpLogs.get(ingress_ip)
                if log is None:
                    log = mtpLog(ingress_ip, egress_ip)

                if label <= self.max_label:
                    sug_label = self.max_label + 1
                    if dest_port == 8000:
                        log.src['label'] = sug_label
                        log.src['interface'] = income_interface
                    if dest_port == 7000:
                        log.dest['label'] = sug_label
                        log.dest['interface'] = income_interface
                    self.mtpLogs[ingress_ip] = log
                    self.output.append("mtp reply with label %d sent to %s" % (self.max_label, src_ip))
                    
                    next_router = self.neighbors[income_interface].get('router')
                    interface_match = self.neighbors[income_interface].get('interface_match')
                    send_frame = MockFrame(get_router_mac(self.id, income_interface), get_router_mac(next_router.id. interface_match), ETHERTYPE_IP)
                    send_frame.mtp(dest_ip, src_ip, dest_port, src_port, type_mtp, sug_label, ingress_ip, egress_ip)
                    self.send_frames[income_interface].append(send_frame)
                    next_router.recv_frames[interface_match].append(send_frame)
                    
                    self.neighbors[income_interface].get('router').mtp(interface_match, dest_ip, src_ip, dest_port, src_port, ingress_ip, egress_ip, mtp_types['Reply'], sug_label)
                    return
                else:
                    self.max_label = label
                    self.output.append("mtp ack sent to " % src_ip)
                    
                    next_router = self.neighbors[income_interface].get('router')
                    interface_match = self.neighbors[income_interface].get('interface_match')
                    send_frame = MockFrame(get_router_mac(self.id, income_interface), get_router_mac(next_router.id. interface_match), ETHERTYPE_IP)
                    send_frame.mtp(dest_ip, src_ip, dest_port, src_port, mtp_types['Ack'], self.max_label, ingress_ip, egress_ip)
                    self.send_frames[income_interface].append(send_frame)
                    next_router.recv_frames[interface_match].append(send_frame)

                    self.neighbors[income_interface].get('router').mtp(interface_match, dest_ip, src_ip, dest_ip, src_ip, ingress_ip, egress_ip, mtp_types['Ack'], self.max_label)
                    if dest_port == 8000:
                        log.src['label'] = self.max_label
                        log.src['interface'] = income_interface
                        log.src['set'] = True
                        self.update_tables(log)
                    else:
                        log.dest['label'] = self.max_label
                        log.dest['interface'] = income_interface
                        log.dest['set'] = True
                    self.mtpLogs[ingress_ip] = log
                    if log.src['set'] is False:
                        index = self.find_neighbors(ip2uint(ingress_ip))
                        interface = None
                        nh_ip = None
                        if index is not None:
                            nh_ip = ip2uint(ingress_ip)
                            interface = index
                        else:
                            index = self.find_default(ip2uint(ingress_ip))
                            if index is not None:
                                nh_ip = self.default_table[index].get('nh-ip')
                                interface = self.default_table[index].get('nh-interface')
                            if interface is None:
                                return
                        sug_label = self.max_label + 1
                        log.src['label'] = sug_label
                        log.src['interface'] = interface
                        self.mtpLogs[ingress_ip] = log

                        self.arp(nh_ip, interface, "Request")
                        self.output.append("mtp reply with label %d sent to %s" % (sug_label, uint2ip(nh_ip)))
                        
                        next_router = self.neighbors[interface].get('router')
                        interface_match = self.neighbors[interface].get('interface_match')
                        send_frame = MockFrame(get_router_mac(self.id, interface), get_router_mac(next_router.id. interface_match), ETHERTYPE_IP)
                        send_frame.mtp(get_router_ip(self.id, interface), get_router_ip(next_router.id, interface_match), 
                                        8000, 7000, mtp_types['Reply'], sug_label, ingress_ip, egress_ip)
                        self.send_frames[interface].append(send_frame)
                        next_router.recv_frames[interface_match].append(send_frame)
                        
                        self.neighbors[interface].get('router').mtp(interface_match, get_router_ip(self.id, interface), uint2ip(nh_ip), 8000, 7000, ingress_ip, egress_ip, mtp_types['Reply'], sug_label)
                        return
            if type_mtp == mtp_types['Ack']:
                log = self.mtpLogs.get(ingress_ip)
                if log is None:
                    log = mtpLog(ingress_ip, egress_ip)
                if dest_port == 8000:
                    log.src['label'] = label
                    log.src['interface'] = income_interface
                    log.src['set'] = True
                    self.update_tables(log)
                if dest_port == 7000:
                    log.dest['label'] = label
                    log.dest['interface'] = income_interface
                    log.dest['set'] = True
                self.mtpLogs[ingress_ip] = log
                if log.src['set'] is False:
                    index = self.find_neighbors(ip2uint(ingress_ip))
                    interface = None
                    nh_ip = None
                    if index is not None:
                        nh_ip = ip2uint(ingress_ip)
                        interface = index
                    else:
                        index = self.find_default(ip2uint(ingress_ip))
                        if index is not None:
                            nh_ip = self.default_table[index].get('nh-ip')
                            interface = self.default_table[index].get('nh-interface')
                        if interface is None:
                            return
                    sug_label = self.max_label + 1
                    log.src['label'] = sug_label
                    log.src['interface'] = interface
                    self.mtpLogs[ingress_ip] = log

                    self.arp(nh_ip, interface, "Request")
                    self.output.append("mtp reply with label %d sent to %s" % (sug_label, uint2ip(nh_ip)))
                    
                    next_router = self.neighbors[interface].get('router')
                    interface_match = self.neighbors[interface].get('interface_match')
                    send_frame = MockFrame(get_router_mac(self.id, interface), get_router_mac(next_router.id. interface_match), ETHERTYPE_IP)
                    send_frame.mtp(get_router_ip(self.id, interface), get_router_ip(next_router.id, interface_match), 
                                    8000, 7000, mtp_types['Reply'], sug_label, ingress_ip, egress_ip)
                    self.send_frames[interface].append(send_frame)
                    next_router.recv_frames[interface_match].append(send_frame)

                    self.neighbors[interface].get('router').mtp(interface_match, get_router_ip(self.id, interface), uint2ip(nh_ip), 8000, 7000, ingress_ip, egress_ip, mtp_types['Reply'], sug_label)
                    return
            return
    
    def update_tables(self, log):
        if log.src['label']!= -1:
            node = {}
            node['ip'] = log(ip2uint(log.src['ip']))
            if self.find_neighbors(ip2uint(log.src['ip'])) is None:
                node['tunnel-label'] = log.src['label']
            else:
                node['tunnel-label'] = -1
            node['egress-interface'] = log.src['interface']
            node['next-mac'] = log.src['mac']
            if self.find_tunnel(ip2uint(log.src['ip'])) is None:
                self.tunnel_label.append(node)
        if log.dest['label']!= -1:
            node = {}
            node['ip'] = log(ip2uint(log.dest['ip']))
            if self.find_neighbors(ip2uint(log.dest['ip'])) is None:
                node['tunnel-label'] = log.dest['label']
            else:
                node['tunnel-label'] = -1
            node['egress-interface'] = log.dest['interface']
            node['next-mac'] = log.dest['mac']
            if self.find_tunnel(ip2uint(log.dest['ip'])) is None:
                self.tunnel_label.append(node)
        if log.src['label'] != -1 and log.dest['label'] != -1:
            node_src = {}
            node_src['ingress-label'] = log.dest['label']
            if self.find_neighbors(ip2uint(log.src['ip'])) is None:
                node_src['egress-label'] = log.src['label']
            else:
                node_src['egress-label'] = -1
            node_src['egress-interface'] = log.src['interface']
            node_src['egress-mac'] = log.src['mac']
            self.ls_table.append(node_src)

            node_dest = {}
            node_dest['ingress-label'] = log.src['label']
            if self.find_neighbors(ip2uint(log.dest['ip'])) is None:
                node_dest['egress-label'] = log.dest['label']
            else:
                node_dest['egress-label'] = -1
            node_dest['egress-interface'] = log.dest['interface']
            node_dest['egress-mac'] = log.dest['mac']
            self.ls_table.append(node_dest)

    def printTables(self):
        self.output.append("Tunnel Table")
        self.output.append("IP Tunnel-label egress-interface next-mac")
        for i in xrange(0, len(self.tunnel_table)):
            node = self.tunnel_table[i]
            label_str = None
            if node['tunnel-label'] != -1:
                label_str = str(node['tunnel-label'])
            else:
                label_str = 'N/A'
            self.output.append("%s %s %s %s" % (uint2ip(node['ip'], label_str, node['egress-interface'], node['next-mac'])))
        self.output.append("LS Table")
        self.output.append("ingress-label egress-label egress-mac egress-interface")
        for v in xrange(0, len(vpn_names)):
            self.output.append("%s" % vpn_names[v])
            for i in xrange(0, len(self.ls_table[v])):
                node = self.ls_table[v][i]
                egress_str = None
                if node['egress-label'] != -1:
                    egress_str = str(node['egress-label'])
                else:
                    egress_str = 'POP'
                mac = None
                if len(node['egress-label']) == 1:
                    if int(node['egress-label']) == 1:
                        mac = 'vpn-A'
                    else:
                        mac = 'vpn-B'
                else:
                    mac = node['egress-label']
                egress_inter = None
                if node['egress-interface'] == -1:
                    egress_inter = 'N/A'
                else:
                    egress_inter = node['egress-interface']
                self.output.append("%s %s %s %s" % (node['ingress-label'], egress_str, mac, egress_inter))

    def clear(self, real):
        self.output = []
        self.recv_frames = []
        self.send_frames = []
        for i in xrange(len(self.neighbors)):
            self.send_frames.append([])
            self.recv_frames.append([])
        if real:
            self.client.clear_read_queue()
            for i in xrange(len(self.neighbors)):
                self.client.clear_send_queue(iface=i)
                self.client.clear_recv_queue(iface=i)

    def check_output(self):
        output = read_output(self.client)
        # print output
        if check_output(output, self.output):
            return True
        return False

    def check_all_recv_frames(self):
        for i in xrange(len(self.neighbors)):
            if not self.check_recv_frames(i):
                return False
        return True

    def check_all_send_frames(self):
        for i in xrange(len(self.neighbors)):
            if not self.check_send_frames(i):
                return False
        return True

    def check_recv_frames(self, iface_index):
        recv_frames = read_recv_frames(self.client, iface_index)
        return check_unordered_frame_lists(recv_frames, self.recv_frames[iface_index])

    def check_send_frames(self, iface_index):
        send_frames = read_send_frames(self.client, iface_index)
        # print 'in node%d iface%d: my_sends:%d actual:%d' %(self.id, iface_index, len(send_frames), len(self.send_frames[iface_index]))
        return check_unordered_frame_lists(send_frames, self.send_frames[iface_index])

    def issue_invalid_message_type_request(self, processor, address):
        command = "invalid_message_type_request %d %x" % (processor.id, address)
        self.client.write_io(command)
        processor.output.append("A packet dropped at application layer")    #We should check only "output" and "send_frames" of destination processor

class mtpLog:
    def __init__(self, ingress_ip, egress_ip):
        self.src = {'interface':-1, 'label':-1, 'mac':'sample', 'set':False, 'ip':ingress_ip}
        self.dest = {'interface':-1, 'label':-1, 'mac':'sample', 'set':False, 'ip':egress_ip}

class Map:
    def __init__(self, router_clients):
        self.router_clients = router_clients
        self.routers = []
        self.state = {}

        self.routers.append(Router(self.router_clients[0], [{'ip':ip2uint(get_router_ip(2,1)), 'mask':ip2uint('255.255.255.0'),'nh-ip':ip2uint(get_router_ip(2,0)), 'nh-interface':1},
                                                            {'ip':ip2uint(get_router_ip(1,0)), 'mask':ip2uint('255.255.255.0'),'nh-ip':ip2uint(get_router_ip(1,1)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}, {'interface':1, 'vpn':-1}, {'interface':2, 'vpn':-1}],
                                                           # vrf-tables
                                                           [[{'ip':ip2uint(get_router_ip(6,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':2, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(8,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':1, 'out-ip':ip2uint(get_router_ip(4, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(10,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':3, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}],
                                                            [{'ip':ip2uint(get_router_ip(7,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':4, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(9,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':5, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}]],
                                                           # Tunnel table
                                                           [{'ip':ip2uint(get_router_ip(3,0)), 'tunnel-label':8, 'egress-interface':1, 'next-mac':get_router_mac(2, 0)},
                                                            {'ip':ip2uint(get_router_ip(5,0)), 'tunnel-label':7, 'egress-interface':0, 'next-mac':get_router_mac(1, 1)}],
                                                           # LS table
                                                           [{'ingress-label':7, 'egress-label':8, 'egress-mac':get_router_mac(2,0), 'egress-interface':1},
                                                            {'ingress-label':8, 'egress-label':7, 'egress-mac':get_router_mac(1,1), 'egress-interface':0}],
                                                           # id
                                                           0, 8))
        self.routers.append(Router(self.router_clients[1], [{'ip':ip2uint('192.168.144.0'), 'mask':ip2uint('255.255.240.0'),'nh-ip':ip2uint(get_router_ip(0,0)), 'nh-interface':1}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}, {'interface':1, 'vpn':-1}],
                                                           # vrf-tables
                                                           [[{'ip':ip2uint(get_router_ip(6,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':2, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(8,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':1, 'out-ip':ip2uint(get_router_ip(4, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(10,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':3, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}],
                                                            [{'ip':ip2uint(get_router_ip(7,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':4, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(9,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':5, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}]],
                                                           # Tunnel table
                                                           [{'ip':ip2uint(get_router_ip(3,0)), 'tunnel-label':7, 'egress-interface':1, 'next-mac':get_router_mac(0, 0)},
                                                            {'ip':ip2uint(get_router_ip(5,0)), 'tunnel-label':-1, 'egress-interface':0, 'next-mac':get_router_mac(5, 0)}],
                                                           # LS table
                                                           [{'ingress-label':6, 'egress-label':7, 'egress-mac':get_router_mac(0,0), 'egress-interface':1},
                                                            {'ingress-label':7, 'egress-label':-1, 'egress-mac':get_router_mac(5,0), 'egress-interface':0}],
                                                           # id
                                                           1, 7))
        self.routers.append(Router(self.router_clients[2], [{'ip':ip2uint('192.168.144.0'), 'mask':ip2uint('255.255.240.0'),'nh-ip':ip2uint(get_router_ip(0,0)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}, {'interface':1, 'vpn':-1}],
                                                           # vrf-tables
                                                           [[{'ip':ip2uint(get_router_ip(6,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':2, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(8,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':1, 'out-ip':ip2uint(get_router_ip(4, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(10,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':3, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}],
                                                            [{'ip':ip2uint(get_router_ip(7,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':4, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(9,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':5, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}]],
                                                           # Tunnel table
                                                           [{'ip':ip2uint(get_router_ip(3,0)), 'tunnel-label':-1, 'egress-interface':1, 'next-mac':get_router_mac(3, 0)},
                                                            {'ip':ip2uint(get_router_ip(5,0)), 'tunnel-label':8, 'egress-interface':0, 'next-mac':get_router_mac(0, 1)}],
                                                           # LS table
                                                           [{'ingress-label':8, 'egress-label':-1, 'egress-mac':get_router_mac(3,0), 'egress-interface':1},
                                                            {'ingress-label':9, 'egress-label':8, 'egress-mac':get_router_mac(0,1), 'egress-interface':0}],
                                                           # id
                                                           2, 9))
        self.routers.append(Router(self.router_clients[3], [{'ip':ip2uint('192.168.144.0'), 'mask':ip2uint('255.255.240.0'),'nh-ip':ip2uint(get_router_ip(2,1)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}, {'interface':1, 'vpn':1}, {'interface':2, 'vpn':2}],
                                                           # vrf-tables
                                                           [[{'ip':ip2uint(get_router_ip(6,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':2, 'out-ip':ip2uint(get_router_ip(6, 0)), 'egress-interface':1},
                                                             {'ip':ip2uint(get_router_ip(8,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':1, 'out-ip':ip2uint(get_router_ip(4, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(10,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':3, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}],
                                                            [{'ip':ip2uint(get_router_ip(7,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':4, 'out-ip':ip2uint(get_router_ip(7, 0)), 'egress-interface':2},
                                                             {'ip':ip2uint(get_router_ip(9,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':5, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}]],
                                                           # Tunnel table
                                                           [{'ip':ip2uint(get_router_ip(5,0)), 'tunnel-label':9, 'egress-interface':0, 'next-mac':get_router_mac(2, 1)}],
                                                           # LS table
                                                           [{'ingress-label':2, 'egress-label':-1, 'egress-mac':'1', 'egress-interface':-1},
                                                            {'ingress-label':4, 'egress-label':-1, 'egress-mac':'2', 'egress-interface':-1}],
                                                           # id
                                                           3, 9))
        self.routers.append(Router(self.router_clients[4], [{'ip':ip2uint('192.168.144.0'), 'mask':ip2uint('255.255.240.0'),'nh-ip':ip2uint(get_router_ip(0,2)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}, {'interface':1, 'vpn':1}],
                                                           # vrf-tables
                                                           [[{'ip':ip2uint(get_router_ip(6,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':2, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(8,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':1, 'out-ip':ip2uint(get_router_ip(8, 0)), 'egress-interface':1},
                                                             {'ip':ip2uint(get_router_ip(10,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':3, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}],
                                                            [{'ip':ip2uint(get_router_ip(7,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':4, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(9,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':5, 'out-ip':ip2uint(get_router_ip(5, 0)), 'egress-interface':-1}]],
                                                           # Tunnel table
                                                           [],
                                                           # LS table
                                                           [{'ingress-label':1, 'egress-label':-1, 'egress-mac':'1', 'egress-interface':-1}],
                                                           # id
                                                           4, 5))
        self.routers.append(Router(self.router_clients[5], [{'ip':ip2uint('192.168.144.0'), 'mask':ip2uint('255.255.240.0'),'nh-ip':ip2uint(get_router_ip(1,0)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}, {'interface':1, 'vpn':1}, {'interface':2, 'vpn':2}],
                                                           # vrf-tables
                                                           [[{'ip':ip2uint(get_router_ip(6,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':2, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(8,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':1, 'out-ip':ip2uint(get_router_ip(4, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(10,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':3, 'out-ip':ip2uint(get_router_ip(10, 0)), 'egress-interface':1}],
                                                            [{'ip':ip2uint(get_router_ip(7,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':4, 'out-ip':ip2uint(get_router_ip(3, 0)), 'egress-interface':-1},
                                                             {'ip':ip2uint(get_router_ip(9,0)), 'mask':ip2uint('255.255.255.252'), 'vpn-label':5, 'out-ip':ip2uint(get_router_ip(9, 0)), 'egress-interface':2}]],
                                                           # Tunnel table
                                                           [{'ip':ip2uint(get_router_ip(3,0)), 'tunnel-label':6, 'egress-interface':0, 'next-mac':get_router_mac(1, 0)}],
                                                           # LS table
                                                           [{'ingress-label':3, 'egress-label':-1, 'egress-mac':'1', 'egress-interface':-1},
                                                            {'ingress-label':5, 'egress-label':-1, 'egress-mac':'2', 'egress-interface':-1}],
                                                           # id
                                                           5, 6))
        self.routers.append(Router(self.router_clients[6], [{'ip':ip2uint('192.168.201.0'), 'mask':ip2uint('255.255.255.252'),'nh-ip':ip2uint(get_router_ip(3,1)), 'nh-interface':0},
                                                            {'ip':ip2uint('192.168.202.0'), 'mask':ip2uint('255.255.255.252'),'nh-ip':ip2uint(get_router_ip(3,1)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}],
                                                           # vrf-tables
                                                           [],
                                                           # Tunnel table
                                                           [],
                                                           # LS table
                                                           [],
                                                           # id
                                                           6, 3))
        self.routers.append(Router(self.router_clients[7], [{'ip':ip2uint('192.168.202.0'), 'mask':ip2uint('255.255.255.252'),'nh-ip':ip2uint(get_router_ip(3,2)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}],
                                                           # vrf-tables
                                                           [],
                                                           # Tunnel table
                                                           [],
                                                           # LS table
                                                           [],
                                                           # id
                                                           7, 5))
        self.routers.append(Router(self.router_clients[8], [{'ip':ip2uint('192.168.200.0'), 'mask':ip2uint('255.255.255.252'),'nh-ip':ip2uint(get_router_ip(4,1)), 'nh-interface':0},
                                                            {'ip':ip2uint('192.168.202.0'), 'mask':ip2uint('255.255.255.252'),'nh-ip':ip2uint(get_router_ip(4,1)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}],
                                                           # vrf-tables
                                                           [],
                                                           # Tunnel table
                                                           [],
                                                           # LS table
                                                           [],
                                                           # id
                                                           8, 3))
        self.routers.append(Router(self.router_clients[9], [{'ip':ip2uint('192.168.200.0'), 'mask':ip2uint('255.255.255.252'),'nh-ip':ip2uint(get_router_ip(5,2)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}],
                                                           # vrf-tables
                                                           [],
                                                           # Tunnel table
                                                           [],
                                                           # LS table
                                                           [],
                                                           # id
                                                           9, 5))
        self.routers.append(Router(self.router_clients[10], [{'ip':ip2uint('192.168.200.0'), 'mask':ip2uint('255.255.255.252'),'nh-ip':ip2uint(get_router_ip(5,1)), 'nh-interface':0},
                                                            {'ip':ip2uint('192.168.201.0'), 'mask':ip2uint('255.255.255.252'),'nh-ip':ip2uint(get_router_ip(5,1)), 'nh-interface':0}],
                                                           # interface_vpn
                                                           [{'interface':0, 'vpn':-1}],
                                                           # vrf-tables
                                                           [],
                                                           # Tunnel table
                                                           [],
                                                           # LS table
                                                           [],
                                                           # id
                                                           10, 3))
        self.routers[0].set_conneted_routers([{'router':self.routers[1], 'interface_match':1}, {'router': self.routers[2], 'interface_match':0}, {'router':self.routers[4], 'interface_match':0}])
        self.routers[1].set_conneted_routers([{'router':self.routers[5], 'interface_match':0}, {'router': self.routers[0], 'interface_match':0}])
        self.routers[2].set_conneted_routers([{'router':self.routers[0], 'interface_match':1}, {'router': self.routers[3], 'interface_match':0}])
        self.routers[3].set_conneted_routers([{'router':self.routers[2], 'interface_match':1}, {'router': self.routers[6], 'interface_match':0}, {'router':self.routers[7], 'interface_match':0}])
        self.routers[4].set_conneted_routers([{'router':self.routers[0], 'interface_match':2}, {'router': self.routers[8], 'interface_match':0}])
        self.routers[5].set_conneted_routers([{'router':self.routers[1], 'interface_match':0}, {'router': self.routers[10], 'interface_match':0}, {'router':self.routers[9], 'interface_match':0}])
        self.routers[6].set_conneted_routers([{'router':self.routers[3], 'interface_match':1}])
        self.routers[7].set_conneted_routers([{'router':self.routers[3], 'interface_match':2}])
        self.routers[8].set_conneted_routers([{'router':self.routers[4], 'interface_match':1}])
        self.routers[9].set_conneted_routers([{'router':self.routers[5], 'interface_match':2}])
        self.routers[10].set_conneted_routers([{'router':self.routers[5], 'interface_match':1}])

class MockFrame:
    def __init__(self, ether_src , ether_dst , type_frame):
        self.ether_src = ether_src
        self.ether_dst = ether_dst
        self.type = type_frame
        self.is_mtp = False

    def ip(self, src, dest, sport, dport, content):
        self.ip_h = IP(src=src, dst=dest, ttl=0)/UDP(sport=sport, dport=dport)/content

    def arp(self, arp_type, src_mac, src_ip, dest_mac, dest_ip):
        self.arp_h = None
        if arp_type == ARP_TYPE_REPLY:
            self.arp_h = ARP(hwtype=HTYPE_Ether, ptype=PTYPE_IPv4, hwlen=HLEN_Ether, plen=PLEN_IPv4, op=arp_type, hwsrc=src_mac,
                        psrc=src_ip, hwdst=dest_mac, pdst=dest_ip)
        else:
            self.arp_h = ARP(hwtype=HTYPE_Ether, ptype=PTYPE_IPv4, hwlen=HLEN_Ether, plen=PLEN_IPv4, op=arp_type, hwsrc=src_mac,
                        psrc=src_ip, pdst=dest_ip)

    def mpls(self, tunnel_label, vpn_label, src, dest, sport, dport, content):
        self.mpls_h = None
        if tunnel_label is not None and tunnel_label != -1:
            self.mpls_h = MPLS(label=tunnel_label, experimental_bits=0, TTL=0)/MPLS(label=vpn_label, experimental_bits=0, TTL=0)/IP(src=src, dst=dest, ttl=0)/UDP(sport=sport, dport=dport)/content
        else:
            self.mpls_h = MPLS(label=vpn_label, experimental_bits=0, TTL=0)/IP(src=src, dst=dest, ttl=0)/UDP(sport=sport, dport=dport)/content
        

    def mtp(self, src, dest, sport, dport, mtp_type, label, ingress_ip, egress_ip):
        self.is_mtp = True
        self.mtp_h = {}
        self.mtp_h['type'] = mtp_type
        self.mtp_h['label'] = label
        self.mtp_h['ingress_ip'] = ingress_ip
        self.mtp_h['egress_ip'] = egress_ip
        self.ip(src, dest, sport, dport,'')

    def equal(self, frame):
        print 'actual_type:%s' %self.type
        if frame == None or type(frame.payload) == NoPayload:
            print 'no frame or no payload'
            return False
        if frame.type != self.type:
            print frame.type
            print 'not equal to actual type'
            return False
        if check_mac_src_dst(frame, self.ether_src, self.ether_dst) is False:
            print 'Ether not equal'
            return False
        if self.type == ETHERTYPE_IP:
            frame.payload.ttl = 0 
            if self.is_mtp:
                frame_mtp = frame
                frame_mtp.payload.payload.payload = ''
                return check_mtp(frame, self.mtp_h) and compare_ip(frame_mtp.payload, self.ip_h)
            return compare_ip(frame.payload, self.ip_h)

        if self.type == ETHERTYPE_ARP:
            if frame.payload.op == ARP_TYPE_REQUEST:
                frame.payload.hwdst = '00:00:00:00:00:00'
            return compare_arp(frame.payload, self.arp_h)

        if self.type == ETHERTYPE_MPLS:
            if frame.payload.bottom_of_label_stack == 0:
                frame.payload.payload.payload.ttl = 0
            else:
                frame.payload.payload.ttl = 0
            return compare_mpls(frame.payload, self.mpls_h)

    def __str__(self):
        return 'src: %s, dst: %s, type: %s, content: %s' % (self.src, self.dst, self.type, self.content)

class MPLS(Packet):
        name = "MPLS"
        fields_desc =  [
                BitField("label", 3, 20),
                BitField("experimental_bits", 0, 3),
                BitField("bottom_of_label_stack", 1, 1), # Now we're at the bottom
                ByteField("TTL", 0)
        ]

bind_layers(Ether, MPLS, type= ETHERTYPE_MPLS)
bind_layers(MPLS, MPLS, bottom_of_label_stack = 0)
bind_layers(MPLS, IP)