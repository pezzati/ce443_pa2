//                   In the name of GOD
/**
 * Partov is a simulation engine, supporting emulation as well,
 * making it possible to create virtual networks.
 *  
 * Copyright © 2009-2015 Behnam Momeni.
 * 
 * This file is part of the Partov.
 * 
 * Partov is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Partov is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Partov.  If not, see <http://www.gnu.org/licenses/>.
 *  
 */

#include "sm.h"

#include "interface.h"
#include "frame.h"
#include "sr_protocol.h"

#include <netinet/in.h>
#include <netinet/ip.h> // for iphdr struct
#include <vector>
#include <map>

using namespace std;

#define ipHeader   (sizeof(struct sr_ethernet_hdr))

//*************************************************Structs

struct vrfi
{
  uint32_t ip;
  uint32_t mask;
  int vpn_label;
  uint32_t egress_ip;
};

struct vrf
{
  int vrf_index;
  vector<struct vrfi*> vrfi_arry;
};


struct default_node
{
  uint32_t ip;
  uint32_t mask;
  uint32_t egress_ip;
  int ifaceIndex;
};


struct msg_stored
{
  //struct default_node *node;
  uint32_t egress_ip;
  int ifaceIndex;
  uint32_t destIp;
  string msg;
  int vpn_label;
};
//*************************************************End of structs


//*************************************************Vectors && Maps
map<string, struct vrf*> VRFs;
vector<struct default_node*> default_table;
map<uint32_t, struct msg_stored*> arp_waiting_que;
map<int, string> interface_vpn;
//*************************************************End of Vectors && Maps

//*************************************************Statics
uint8_t broadcastMAC[6];
//*************************************************End of Statics


//*************************************************Functions
uint32_t StrToIntIp(string str_ip){
  uint32_t ip;
  uint8_t ip_temp[4];
  int size = str_ip.length();
  int begin = 0;
  int end = 0;
  for(int i = 0; i < 4; i++){
    int value = 0;
    
    while(end < size && str_ip[end] != '.')
      end++;
    int power = 1;
    int count = 1;
    while(begin != end){
      value = value + power * ((int) (str_ip[end - count] - '0'));
      power = power * 10;
      begin++;
      count++;
    }
    end++;
    begin++;
    ip_temp[3 - i] = (uint8_t) value;
  }
  memcpy(&ip, ip_temp, 4);
  return ip;
}


struct default_node* getDefault(uint32_t destIp){
  for(int i = 0; i < default_table.size(); i++)
    if((default_table.at(i)->ip & default_table.at(i)->mask) == (default_table.at(i)->mask & destIp))
      return default_table.at(i);
  return NULL;
}

struct vrfi* getVPN(uint32_t destIp, struct vrf *vrf_dest){
  for(int i = 0; i < vrf_dest->vrfi_array->size(); i++)
    if((vrf_dest->vrfi_array->at(i)->ip & vrf_dest->vrfi_array->at(i)->mask) == (vrf_dest->vrfi_array->at(i)->mask & destIp))
      return vrf_dest->vrfi_array->at(i);
  return NULL;
}


uint16_t checksum(const uint16_t* buf, unsigned int size){
  uint32_t sum = 0;

  for (; size > 1; size -= 2)
    sum += *buf++;
  
  if (size == 1)
    sum += *(unsigned char*) buf;

  sum  = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);

  return ~sum;
}

string getIPString(uint32_t ipAddr){
   struct in_addr ip_addr;
   ip_addr.s_addr = htonl(ipAddr);
   const char* result = inet_ntoa(ip_addr);
   string s = result;
   return s;
}



void sendARPReq( int ifaceIndex, uint32_t egress_ip){
  //build ARP req
  struct arp arp;
  arp.arp_hard_type = htons(HTYPE_Ether);
  arp.arp_proto_type = htons(PTYPE_IPv4);
  arp.arp_hard_size = HLEN_Ether;
  arp.arp_proto_size = PLEN_IPv4;
  arp.arp_op = htons(ARP_OP_REQUSET);
  memcpy(arp.arp_eth_source, iface[ifaceIndex].mac, 6);
  arp.arp_ip_source = htonl(iface[ifaceIndex].getIp());
  arp.arp_ip_dest = htonl(egress_ip);

  //build Ether
  struct sr_ethernet_hdr ethernet_hdr;
  memcpy(ethernet_hdr.ether_dhost, broadcastMAC, 6);
  memcpy(ethernet_hdr.ether_shost, iface[ifaceIndex].mac, 6);
  ethernet_hdr.ether_type = htons(ETHERTYPE_ARP);

  //save to memory
  uint8_t data;
  memcpy(&data, &ethernet_hdr, sizeof(struct sr_ethernet_hdr));
  memcpy(&data + sizeof(struct sr_ethernet_hdr), &arp, sizeof(struct arp));

  //Frame
  Frame frame( sizeof(struct sr_ethernet_hdr) + sizeof(struct arp), &data);
  sendFrame(frame, ifaceIndex);

  cout << "The ARP requset sent out." << endl;
  return;
}


void sendARPRes(uint8_t *data, int ifaceIndex){
  struct sr_ethernet_hdr *ether = (struct sr_ethernet_hdr*)data;
  memcpy(ether->ether_dhost, ether->ether_shost, 6);
  memcpy(ether->ether_shost, iface[ifaceIndex].mac, 6);

  struct arp *arp = (struct arp*)(data + sizeof(struct sr_ethernet_hdr));
  //change Opertaon field to Response
  arp->arp_op = htons(ARP_OP_REPLY);
  //add source to dest MAC
  memcpy(arp->arp_eth_dest, arp->arp_eth_source, 6);
  //add interface MAC to source field
  memcpy(arp->arp_eth_source, iface[ifaceIndex].mac, 6);
  //Switch IPs
  arp->arp_ip_dest = arp->arp_ip_source;
  arp->arp_ip_source = htonl(iface[ifaceIndex].getIp());

  Frame frame( sizeof(struct sr_ethernet_hdr) + sizeof(struct arp), &data);
  sendFrame(frame, ifaceIndex);

  cout << "The ARP response sent." << endl;
  return;
}


void sendPacket(uint32_t destIp, uint8_t *destMac, int ifaceIndex, string msg){
  //build UDP
  //uint8_t *beginUdp = new uint8_t[msg.length() + sizeof(struct sr_udp)];
  //struct sr_udp *udp_hdr = (struct sr_udp*)beginUdp;
  struct sr_udp udp_hdr;
  udp_hdr.port_src = htons(5000);
  udp_hdr.port_dst = htons((uint16_t)3000);
  udp_hdr.length = htons((uint16_t)(sizeof(sr_udp) + msg.length()));
  udp_hdr.udp_sum = htons((uint16_t)0);

  //IP
  struct ip ip_header;
  ip_header.ip_tos = 0;
  ip_header.ip_id = htons((uint16_t)0);
  ip_header.ip_off = htons((uint16_t)0);
  ip_header.ip_src.s_addr = htonl(iface[ifaceIndex].getIp());
  ip_header.ip_dst.s_addr = htonl(destIp);
  ip_header.ip_p = IPPROTO_UDP;
  ip_header.ip_ttl = 64;
  ip_header.ip_hl = 5;
  ip_header.ip_v = 4;
  ip_header.ip_len = htons(sizeof(struct ip) + sizeof(struct sr_udp) + msg.length());
  ip_header.ip_sum = 0x0000; 
  ip_header.ip_sum = checksum((uint16_t *)&ip_header, sizeof(struct ip));

  // build ethernet
  struct sr_ethernet_hdr ethernet_hdr;
  memcpy(ethernet_hdr.ether_dhost, destMac, 6);
  memcpy(ethernet_hdr.ether_shost, iface[ifaceIndex].mac, 6);
  ethernet_hdr.ether_type = htons(ETHERTYPE_IP);

  uint8_t *data = new uint8_t[sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct stuct sr_udp) + msg.length()];
  memcpy(data, &ethernet_hdr, sizeof(struct sr_ethernet_hdr));
  memcpy(data + sizeof(struct sr_ethernet_hdr), &ip_header, sizeof(struct ip));
  memcpy(data + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), &udp_hdr, sizeof(struct stuct sr_udp));
  memcpy(data + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct stuct sr_udp), &msg, msg.length());

  Frame frame( sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct stuct sr_udp) + msg.length(), data);
  sendFrame(frame, ifaceIndex);
  return;
}


void sendMPLSPacket(uint32_t destIp, uint8_t *destMac, int ifaceIndex, string msg, int vpn_label){
  //build UDP
  //uint8_t *beginUdp = new uint8_t[msg.length() + sizeof(struct sr_udp)];
  //struct sr_udp *udp_hdr = (struct sr_udp*)beginUdp;
  struct sr_udp udp_hdr;
  udp_hdr.port_src = htons(5000);
  udp_hdr.port_dst = htons((uint16_t)3000);
  udp_hdr.length = htons((uint16_t)(sizeof(sr_udp) + msg.length()));
  udp_hdr.udp_sum = htons((uint16_t)0);

  //IP
  struct ip ip_header;
  ip_header.ip_tos = 0;
  ip_header.ip_id = htons((uint16_t)0);
  ip_header.ip_off = htons((uint16_t)0);
  ip_header.ip_src.s_addr = htonl(iface[ifaceIndex].getIp());
  ip_header.ip_dst.s_addr = htonl(destIp);
  ip_header.ip_p = IPPROTO_UDP;
  ip_header.ip_ttl = 64;
  ip_header.ip_hl = 5;
  ip_header.ip_v = 4;
  ip_header.ip_len = htons(sizeof(struct ip) + sizeof(struct sr_udp) + msg.length());
  ip_header.ip_sum = 0x0000; 
  ip_header.ip_sum = checksum((uint16_t *)&ip_header, sizeof(struct ip));

  //MPLS
  struct mpls_label mpls;
  //vpn label
  mpls.entry = vpn_label;
  mpls.entry = mpls.entry << (MPLS_LS_LABEL_SHIFT - MPLS_LS_TC_SHIFT);
  //TC
  mpls.entry = mpls.entry + (uint32_t)0;
  mpls.entry = mpls.entry << (MPLS_LS_TC_SHIFT - MPLS_LS_S_SHIFT);
  //S
  mpls.entry = mpls.entry + (uint32_t)1;
  mpls.entry = mpls.entry << (MPLS_LS_S_SHIFT - MPLS_LS_TTL_SHIFT);
  //TTL
  mpls.entry = mpls.entry + (uint32_t)0;

  
  // build ethernet
  struct sr_ethernet_hdr ethernet_hdr;
  memcpy(ethernet_hdr.ether_dhost, destMac, 6);
  memcpy(ethernet_hdr.ether_shost, iface[ifaceIndex].mac, 6);
  ethernet_hdr.ether_type = htons(ETHERTYPE_ARP);


  uint8_t *data = new uint8_t[sizeof(struct sr_ethernet_hdr) +  4 /*MPLS header*/
                   + sizeof(struct ip) + sizeof(struct stuct sr_udp) + msg.length()];
  memcpy(data, &ethernet_hdr, sizeof(struct sr_ethernet_hdr));
  memcpy(data + sizeof(struct sr_ethernet_hdr), &mpls, 4);
  memcpy(data + sizeof(struct sr_ethernet_hdr) + 4, &ip_header, sizeof(struct ip));
  memcpy(data + sizeof(struct sr_ethernet_hdr) + 4 + sizeof(struct ip), &udp_hdr, sizeof(struct stuct sr_udp));
  memcpy(data + sizeof(struct sr_ethernet_hdr) + 4 + sizeof(struct ip) + sizeof(struct stuct sr_udp), &msg, msg.length());

  Frame frame( sizeof(struct sr_ethernet_hdr) + 4 + sizeof(struct ip) + sizeof(struct stuct sr_udp) + msg.length(), data);
  sendFrame(frame, ifaceIndex);
  return;
}


//*************************************************End of Functions

SimulatedMachine::SimulatedMachine (const ClientFramework *cf, int count) :
	Machine (cf, count) {
	// The machine instantiated.
	// Interfaces are not valid at this point.
}

SimulatedMachine::~SimulatedMachine () {
	// destructor...
}

void SimulatedMachine::initialize () {
  for (int i = 0; i < 6; ++i)
    broadcastMAC[i] = 0xff;
	// TODO: Initialize your program here; interfaces are valid now.
}

/**
 * This method is called from the main thread.
 * Also ownership of the data of the frame is not with you.
 * If you need it, make a copy for yourself.
 *
 * You can also send frames using:
 * <code>
 *     bool synchronized sendFrame (Frame frame, int ifaceIndex) const;
 * </code>
 * which accepts one frame and the interface index (counting from 0) and
 * sends the frame on that interface.
 * The Frame class used here, encapsulates any kind of network frame.
 * <code>
 *     class Frame {
 *     public:
 *       uint32 length;
 *       byte *data;
 *
 *       Frame (uint32 _length, byte *_data);
 *       virtual ~Frame ();
 *     };
 * </code>
 */
void SimulatedMachine::processFrame (Frame frame, int ifaceIndex) {
	// TODO: process the raw frame; frame.data points to the frame's byte stream
	cerr << "Frame received at iface " << ifaceIndex <<
		" with length " << frame.length << endl;

	uint8_t *data = new uint8_t [frame.length];
	memcpy(data, frame.data, frame.length);
	
	struct sr_ethernet_hdr *ether = (struct sr_ethernet_hdr*)data;

	//***************************************** MPLS *****************************************// 
  if(ntohs(ether->ether_type) == ETHERTYPE_MPLS){
		//packet is on MPLS protocol
		struct mpls_label *label = (struct mpls_label*)(data + sizeof(struct sr_ethernet_hdr));
		if(label->s == 1){
			//label is the last label of stack, thus is VPN label and must check the VRF table
		}
		else{
			//label is Tunnel label, so we must use Tunneling table
		}
	}
  //***************************************** End of MPLS *****************************************//

  //***************************************** ARP *****************************************//
  if(ntohs(ether->ether_type) == ETHERTYPE_ARP){
    struct arp *arp = (struct arp*)(data + sizeof(struct sr_ethernet_hdr));
    //An ARP Requset arrived
    if(ntohs(arp->arp_op) == ARP_OP_REQUSET){
      if(ntohl(arp->arp_ip_dest) == iface[ifaceIndex].getIp())
        sendARPRes(data, ifaceIndex);
      return;
    }
    //An ARP Reply arrived
    if(ntohs(arp->arp_op) == ARP_OP_REPLY){
      if(ntohl(arp->arp_ip_dest) == iface[ifaceIndex].getIp()){
        if(arp_waiting_que[ntohl(arp->arp_ip_source)] != NULL){
          struct msg_stored *awaken_msg = arp_waiting_que[ntohl(arp->arp_ip_source)];
          uint8_t destMac[6];
          memcpy(destMac, arp->arp_eth_source, 6);
          if(awaken_msg->vpn_label == -1)
            sendPacket(awaken_msg->destIp, destMac, awaken_msg->ifaceIndex, awaken_msg->msg);
          if(awaken_msg->vpn_label > 0)
            sendMPLSPacket(awaken_msg->destIp, destMac, awaken_msg->ifaceIndex, awaken_msg->msg, awaken_msg->vpn_label);
        }
      }
    }
  }
  //***************************************** End of ARP *****************************************//


  //***************************************** IP *****************************************//
  if(ntohs(ether->ether_type) == ETHERTYPE_IP){
    struct ip *iphdr = (struct ip*)(data + sizeof(struct sr_ethernet_hdr));
    //****** Get MSG *****//
    if(ntohl(iphdr->ip_dst.s_addr) == iface[ifaceIndex].getIp()){
      if(iphdr->ip_p == IPPROTO_UDP){
        struct sr_udp *udp = (struct sr_udp*)(data + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
        if(ntohs(udp->port_src) == 5000  && ntohs(udp->port_dst) == 3000){
          int str_len = ntohs(udp->length) - sizeof(struct sr_udp);
          string *msg = new string[str_len];
          memcpy(msg, data + sizeof(struct sr_udp), length);

          cout << "A message from " << getIPString(ntohl(iphdr->ip_src.s_addr)) << " : " << *msg << endl;
          return;
        }
      }
    }
    //****** End of Get MSG *****//


    //****** Forward *****//
    else{

    }
    //****** End of Forward *****//    
  }
  //***************************************** End of IP *****************************************//
}


/**
 * This method will be run from an independent thread. Use it if needed or simply return.
 * Returning from this method will not finish the execution of the program.
 */
void SimulatedMachine::run () {
  std::string command;
  while (cin >> command) {
    if (command == "send") {
      string destIp;
      strinf vrfIndex;
      string msg;

      cin >> str_destIp >> str_vrfIndex >> msg;
      uint32_t destIp = StrToIntIp(str_destIp);
      
      //if vrf index equals to '--' this means target send it non VPN or in its VPN
      if(str_vrfIndex != "--"){
        //Search VRFs
        struct vrf *vrf_dest = VRFs[str_vrfIndex];
        if(vrf_dest == NULL)
          return;
        struct vrfi *vrfi_dest = getVPN(destIp, vrf_dest);
        if(vrfi_dest == NULL)
          return;

        //Search in default table
        struct default_node *node = getDefault(vrfi_dest->egress_ip);
        if(node == NULL){
          cout << "Destination is unreachable" << endl;
          return;
        }

        struct msg_stored save_msg;
        save_msg.egress_ip = node->egress_ip;
        save_msg.ifaceIndex = node->ifaceIndex;
        save_msg.destIp = destIp;
        save_msg.msg = msg;
        save_msg.vpn_label = vrfi_dest->vpn_label;
        arp_waiting_que[node->egress_ip] = &msg_stored;

        sendARPReq(node->ifaceIndex, node->egress_ip);
        return;
      }
      else{
        //Search in default table
        struct default_node *node = getDefault(destIp);
        if(node == NULL){
          cout << "Destination is unreachable" << endl;
          return;
        }
        struct msg_stored save_msg;
        save_msg.egress_ip = node->egress_ip;
        save_msg.ifaceIndex = node->ifaceIndex;
        save_msg.destIp = destIp;
        save_msg.msg = msg;
        save_msg.vpn_label = -1;
        arp_waiting_que[node->egress_ip] = &msg_stored;

        sendARPReq(node->ifaceIndex, node->egress_ip);
        return;
      }

    }
  }
}


/**
 * You could ignore this method if you are not interested on custom arguments.
 */
void SimulatedMachine::parseArguments (int argc, char *argv[]) {
	// TODO: parse arguments which are passed via --args
}
