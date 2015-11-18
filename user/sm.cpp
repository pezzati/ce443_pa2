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
#include <arpa/inet.h>
/*#include <netinet/ip.h> // for iphdr struct*/
#include <vector>
#include <map>
#include <cstdlib>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <sstream>

using namespace std;

#define ipHeader   (sizeof(struct sr_ethernet_hdr))

//*************************************************Structs

struct vrfi
{
  uint32_t ip;
  uint32_t mask;
  int vpn_label;
  uint32_t egress_ip;
  int ifaceIndex;
};

struct vrf
{
  string vpn_name;
  vector<struct vrfi*> vrfi_array;
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
  uint8_t *data;
  int length;
};

struct tunnel_node
{
  uint32_t ip;
  int lsp;
  int tunnel_label;
  int egress_interface;
  uint8_t nextMAC[6];
};


struct label_routing_node
{
  int ingress_label;
  int egress_label;
  uint8_t nextMAC[6];
  bool vpn;
  string vpn_name;
  int egress_interface;
};
//*************************************************End of structs


//*************************************************Vectors && Maps
vector<string> vrf_name;
map<string, struct vrf*> vrf_table;
vector<struct default_node*> default_table;
map<uint32_t, struct msg_stored*> arp_waiting_que;
map<int, string> interface_vpn;
vector<struct tunnel_node*> tunnel_table;
vector<struct label_routing_node*> label_routing_table;
/*map<uint32_t, > map;*/
//*************************************************End of Vectors && Maps

//*************************************************Statics
uint8_t broadcastMAC[6];
//*************************************************End of Statics


//********************************************************************************************Functions
uint32_t ip_string_binary(string str_gatewayIP){
  uint8_t ip_temp[4];
  int size = str_gatewayIP.length();
  int begin = 0;
  int end = 0;
  for(int i = 0; i < 4; i++){
    int value = 0;
    
    while(end < size && str_gatewayIP[end] != '.')
      end++;
    int power = 1;
    int count = 1;
    while(begin != end){
      value = value + power * ((int) (str_gatewayIP[end - count] - '0'));
      power = power * 10;
      begin++;
      count++;
    }
    end++;
    begin++;
    ip_temp[3 - i] = (uint8_t) value;
  }
  uint32_t ip;
  memcpy(&ip, ip_temp, 4);
  return ip;
}

string ip_binary_string(uint32_t ip){
  struct in_addr ip_addr;
  ip_addr.s_addr = htonl(ip);
  const char* result = inet_ntoa(ip_addr);
  string s = result;
  return s;
}


struct default_node* getDefault(uint32_t destIp){
  for(int i = 0; i < default_table.size(); i++){
    uint32_t ip_table = default_table.at(i)->ip;
    uint32_t mask = default_table.at(i)->mask;
    if((ip_table & mask) == (mask & destIp)){
      return default_table.at(i);
    }
  }
  return NULL;
}

struct vrfi* getVRFi_inVRF(uint32_t destIp, struct vrf *vrf_dest){
  for(int i = 0; i < vrf_dest->vrfi_array.size(); i++)
    if((vrf_dest->vrfi_array.at(i)->ip & vrf_dest->vrfi_array.at(i)->mask) == (vrf_dest->vrfi_array.at(i)->mask & destIp))
      return vrf_dest->vrfi_array.at(i);
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

struct tunnel_node* getTunnelNode(uint32_t egress_ip){
  for(int i = 0; i < tunnel_table.size(); i++)
    if(tunnel_table.at(i)->ip == egress_ip)
      return tunnel_table.at(i);
  return NULL;
}

struct label_routing_node* getLabelNode(int ingress_label){
  for(int i = 0; i < label_routing_table.size(); i++)
    if(label_routing_table.at(i)->ingress_label == ingress_label)
      return label_routing_table.at(i);
  return NULL;
}

struct vrfi* getVRFi_by_label_vrf(int ingress_label, struct vrf *vrf_temp){
  for(int i = 0; i < vrf_temp->vrfi_array.size(); i++){
    if(vrf_temp->vrfi_array.at(i)->vpn_label == ingress_label)
      return vrf_temp->vrfi_array.at(i);
  }
  return NULL;
}


int SimulatedMachine::getNeighbor(uint32_t ip){
  for(int i = 0; i < interface_vpn.size(); i++){
    if(interface_vpn[i] == "N/A"){
        if((iface[i].getIp() & iface[i].getMask()) == (ip & iface[i].getMask())){
        return i;
      }
    }
  }
  return -1;
}

Frame* SimulatedMachine::createMPLS_IP_packet(uint32_t destIp, uint8_t *destMac, int ifaceIndex, int vpn_label, int tunnel_label, string msg){
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
  iface[ifaceIndex];
  ip_header.ip_src.s_addr = htonl(iface[ifaceIndex].getIp());
  ip_header.ip_dst.s_addr = htonl(destIp);
  ip_header.ip_p = IPPROTO_UDP;
  ip_header.ip_ttl = 64;
  ip_header.ip_hl = 5;
  ip_header.ip_v = 4;
  ip_header.ip_len = htons(sizeof(struct ip) + sizeof(struct sr_udp) + msg.length());
  ip_header.ip_sum = 0x0000; 
  ip_header.ip_sum = checksum((uint16_t *)&ip_header, sizeof(struct ip));

  //********MPLS
  //VPN label
  struct mpls_label *mpls_vpn = new struct mpls_label;
  //Tunnel label
  struct mpls_label *mpls_tunnel = new struct mpls_label;
  int vpn_size = 0;
  int tunnel_size = 0;
  if(vpn_label != -1){
    vpn_size = 4;
    //value
    mpls_vpn->entry = vpn_label;
    mpls_vpn->entry = mpls_vpn->entry << (MPLS_LS_LABEL_SHIFT - MPLS_LS_TC_SHIFT);
    //TC
    mpls_vpn->entry = mpls_vpn->entry + (uint32_t)0;
    mpls_vpn->entry = mpls_vpn->entry << (MPLS_LS_TC_SHIFT - MPLS_LS_S_SHIFT);
    //S
    mpls_vpn->entry = mpls_vpn->entry + (uint32_t)1;
    mpls_vpn->entry = mpls_vpn->entry << (MPLS_LS_S_SHIFT - MPLS_LS_TTL_SHIFT);
    //TTL
    mpls_vpn->entry = mpls_vpn->entry + (uint32_t)0;

    cout << "the label " << vpn_label << " added to " << ip_binary_string(destIp) << endl;

    mpls_vpn->entry = htonl(mpls_vpn->entry);
  }
  if(tunnel_label != -1){
    tunnel_size = 4;
    //value
    mpls_tunnel->entry = tunnel_label;
    mpls_tunnel->entry = mpls_tunnel->entry << (MPLS_LS_LABEL_SHIFT - MPLS_LS_TC_SHIFT);
    //TC
    mpls_tunnel->entry = mpls_tunnel->entry + (uint32_t)0;
    mpls_tunnel->entry = mpls_tunnel->entry << (MPLS_LS_TC_SHIFT - MPLS_LS_S_SHIFT);
    //S
    mpls_tunnel->entry = mpls_tunnel->entry + (uint32_t)0;
    if(vpn_label != -1)
      mpls_tunnel->entry = mpls_tunnel->entry + (uint32_t)1;
    mpls_tunnel->entry = mpls_tunnel->entry << (MPLS_LS_S_SHIFT - MPLS_LS_TTL_SHIFT);
    //TTL
    mpls_tunnel->entry = mpls_tunnel->entry + (uint32_t)0;

    cout << "the label " << tunnel_label << " added to " << ip_binary_string(destIp) << endl;

    mpls_tunnel->entry = htonl(mpls_tunnel->entry);
  }
  
  // build ethernet
  struct sr_ethernet_hdr ethernet_hdr;
  memcpy(ethernet_hdr.ether_dhost, destMac, 6);
  memcpy(ethernet_hdr.ether_shost, iface[ifaceIndex].mac, 6);
  if(vpn_label != -1 || tunnel_label != -1)
    ethernet_hdr.ether_type = htons(ETHERTYPE_MPLS);
  else
    ethernet_hdr.ether_type = htons(ETHERTYPE_IP);

  uint8_t *data = new uint8_t[sizeof(struct sr_ethernet_hdr) +  vpn_size + tunnel_size
                   + sizeof(struct ip) + sizeof(struct sr_udp) + msg.length()];
  memcpy(data, &ethernet_hdr, sizeof(struct sr_ethernet_hdr));
  memcpy(data + sizeof(struct sr_ethernet_hdr), mpls_tunnel, tunnel_size);
  memcpy(data + sizeof(struct sr_ethernet_hdr) + tunnel_size, mpls_vpn, vpn_size);
  memcpy(data + sizeof(struct sr_ethernet_hdr) + vpn_size + tunnel_size , &ip_header, sizeof(struct ip));
  memcpy(data + sizeof(struct sr_ethernet_hdr) + vpn_size + tunnel_size + sizeof(struct ip), &udp_hdr, sizeof(struct sr_udp));
  memcpy(data + sizeof(struct sr_ethernet_hdr) + vpn_size + tunnel_size + sizeof(struct ip) + sizeof(struct sr_udp), msg.c_str(), msg.length());

  Frame *frame = new Frame( sizeof(struct sr_ethernet_hdr) + vpn_size + tunnel_size + sizeof(struct ip) + sizeof(struct sr_udp) + msg.length(), data);
  return frame;
}




void SimulatedMachine::sendARPReq( int ifaceIndex, uint32_t egress_ip){
  //build ARP req
  struct arp arp;
  arp.arp_hard_type = htons(HTYPE_Ether);
  printf("%x\n", arp.arp_hard_type);
  arp.arp_proto_type = htons(PTYPE_IPv4);
  arp.arp_hard_size = HLEN_Ether;
  arp.arp_proto_size = PLEN_IPv4;
  arp.arp_op = htons(ARP_OP_REQUEST);
  memcpy(arp.arp_eth_source, iface[ifaceIndex].mac, 6);
  arp.arp_ip_source = htonl(iface[ifaceIndex].getIp());
  arp.arp_ip_dest = htonl(egress_ip);

  //build Ether
  struct sr_ethernet_hdr ethernet_hdr;
  memcpy(ethernet_hdr.ether_dhost, broadcastMAC, 6);
  memcpy(ethernet_hdr.ether_shost, iface[ifaceIndex].mac, 6);
  ethernet_hdr.ether_type = htons(ETHERTYPE_ARP);

  //save to memory
  uint8_t *data = new uint8_t[sizeof(struct sr_ethernet_hdr) + sizeof(struct arp)];
  memcpy(data, &ethernet_hdr, sizeof(struct sr_ethernet_hdr));
  memcpy(data + sizeof(struct sr_ethernet_hdr), &arp, sizeof(struct arp));

  //Frame
  Frame frame( sizeof(struct sr_ethernet_hdr) + sizeof(struct arp), data);
  sendFrame(frame, ifaceIndex);

  cout << "the ARP requset sent for " << ip_binary_string(egress_ip)<< "." << endl;
  return;
}


void SimulatedMachine::sendARPRes(uint8_t *data, int ifaceIndex){
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

  Frame frame( sizeof(struct sr_ethernet_hdr) + sizeof(struct arp), data);
  sendFrame(frame, ifaceIndex);

  cout << "the ARP response sent to " <<  ip_binary_string(ntohl(arp->arp_ip_dest)) << "." << endl;
  return;
}


void changeMPLSlabel(struct mpls_label *label, int egress_label){
  uint32_t new_label = egress_label;
  new_label = new_label << MPLS_LS_LABEL_SHIFT;

  label->entry = (label->entry & (~MPLS_LS_LABEL_MASK)) | new_label;
}

void SimulatedMachine::forwardMPLSPacket(uint8_t *data, int length, struct label_routing_node *target_router){
  struct mpls_label *label = (struct mpls_label*)(data + sizeof(struct sr_ethernet_hdr));
  int ingress_label = (label->entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
  changeMPLSlabel(label, target_router->egress_label);
  cout << "the packet with label " << ingress_label << " forward with label " << target_router->egress_label << endl;
  label->entry = htonl(label->entry);


  struct sr_ethernet_hdr *ether = (struct sr_ethernet_hdr*)(data);
  memcpy(ether->ether_shost, ether->ether_dhost, 6);
  memcpy(ether->ether_dhost, target_router->nextMAC, 6);

  Frame frame( length, data);
  sendFrame(frame, target_router->egress_interface);
  return;
}


void printBinary(uint32_t entry){
  for(int i = 0; i < 32; i++){
    uint32_t t = entry << i;
    t = t >> 31;
    cout << t;
  }
  cout << endl;
}


Frame* SimulatedMachine::addLabel(uint8_t *data, int frame_length, uint8_t *nextMAC, int vpn_label, int tunnel_label, uint32_t dest_ip){
  struct sr_ethernet_hdr *ether = (struct sr_ethernet_hdr*)data;
  memcpy(ether->ether_shost, ether->ether_dhost, 6);
  memcpy(ether->ether_dhost, nextMAC, 6);
  if(vpn_label != -1 || tunnel_label != -1)
    ether->ether_type = htons(ETHERTYPE_MPLS);
  
  //********MPLS
  //VPN label
  struct mpls_label *mpls_vpn = new struct mpls_label;
  //Tunnel label
  struct mpls_label *mpls_tunnel = new struct mpls_label;
  int vpn_size = 0;
  int tunnel_size = 0;
  if(vpn_label != -1){
    vpn_size = 4;
    //value
    mpls_vpn->entry = (uint32_t)vpn_label;
    mpls_vpn->entry = mpls_vpn->entry << (MPLS_LS_LABEL_SHIFT - MPLS_LS_TC_SHIFT);
    //TC
    mpls_vpn->entry = mpls_vpn->entry + (uint32_t)0;
    mpls_vpn->entry = mpls_vpn->entry << (MPLS_LS_TC_SHIFT - MPLS_LS_S_SHIFT);
    //S
    mpls_vpn->entry = mpls_vpn->entry + (uint32_t)1;
    mpls_vpn->entry = mpls_vpn->entry << (MPLS_LS_S_SHIFT - MPLS_LS_TTL_SHIFT);
    //TTL
    mpls_vpn->entry = mpls_vpn->entry + (uint32_t)0;

    cout << "the label " << vpn_label << " added to " << ip_binary_string(dest_ip) << endl;

    mpls_vpn->entry = htonl(mpls_vpn->entry);

  }
  if(tunnel_label != -1){
    tunnel_size = 4;
    //value
    mpls_tunnel->entry = (uint32_t)tunnel_label;
    mpls_tunnel->entry = mpls_tunnel->entry << (MPLS_LS_LABEL_SHIFT - MPLS_LS_TC_SHIFT);
    //TC
    mpls_tunnel->entry = mpls_tunnel->entry + (uint32_t)0;
    mpls_tunnel->entry = mpls_tunnel->entry << (MPLS_LS_TC_SHIFT - MPLS_LS_S_SHIFT);
    //S
    mpls_tunnel->entry = mpls_tunnel->entry + (uint32_t)0;
    if(vpn_label == -1)
      mpls_tunnel->entry = mpls_tunnel->entry + (uint32_t)1;
    mpls_tunnel->entry = mpls_tunnel->entry << (MPLS_LS_S_SHIFT - MPLS_LS_TTL_SHIFT);
    //TTL
    mpls_tunnel->entry = mpls_tunnel->entry + (uint32_t)0;

    cout << "the label " << tunnel_label << " added to " << ip_binary_string(dest_ip) << endl;
    mpls_tunnel->entry = htonl(mpls_tunnel->entry);
  }

  uint8_t *data_temp = new uint8_t[frame_length + tunnel_size + vpn_size];

  memcpy(data_temp, ether, sizeof(struct sr_ethernet_hdr));
  memcpy(data_temp + sizeof(struct sr_ethernet_hdr), &(mpls_tunnel->entry), tunnel_size);
  memcpy(data_temp + sizeof(struct sr_ethernet_hdr) + tunnel_size, &(mpls_vpn->entry), vpn_size);
  memcpy(data_temp + sizeof(struct sr_ethernet_hdr) + tunnel_size + vpn_size, 
    data + sizeof(struct sr_ethernet_hdr), frame_length - sizeof(struct sr_ethernet_hdr));

  Frame frame(frame_length + vpn_size + tunnel_size, data_temp);
  return &frame;
}

string getVPNfromLS(string s){
  int size = strlen(s.c_str());
  size = size - 2;
  char res_char[6];
  for(int i = 0; i < 6; i++)
    res_char[i] = s[i + 2];
  string res = res_char;
  return res;
}


Frame* SimulatedMachine::popLabel(uint8_t *data, int length){
  uint8_t *data_temp = new uint8_t[length - sizeof(struct mpls_label)];
  memcpy(data_temp, data, sizeof(struct sr_ethernet_hdr));
  data = data + sizeof(struct sr_ethernet_hdr) + sizeof(struct mpls_label);
  memcpy(data_temp + sizeof(struct sr_ethernet_hdr), data, length - sizeof(struct sr_ethernet_hdr) - sizeof(struct mpls_label));
  Frame frame_temp(length - sizeof(struct mpls_label), data_temp);
  return &frame_temp;
}



//********************************************************************************************End of Functions

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
  string cs = getCustomInformation();
  stringstream ss(cs);

  string table_name;
  ss >> table_name;
  char first_char_table = table_name[0];
  bool end = false;
  while(!end){
    switch(first_char_table){
      case 'D': /*Default Table*/{ 
        string input;
        for(int i = 0; i < 5; i++)
          ss >> input;
        while(true){
          ss >> input;
          if(input[0] == 'I'){
            first_char_table = input[0];
            break;
          }
          struct default_node *default_temp = new struct default_node;
          default_temp->ip = ip_string_binary(input);
          ss >> input;
          default_temp->mask = ip_string_binary(input);
          ss >> input;
          default_temp->egress_ip = ip_string_binary(input);
          int input_int;
          ss >> input_int;
          default_temp->ifaceIndex = input_int; 
          default_table.push_back(default_temp);
        }
        break;
      }

      case 'I': /*Interface-vpn*/{
        string input;
        for(int i = 0; i < 3; i++)
          ss >> input;
        while(true){
          ss >> input;
          /*cout << input << endl;*/
          if(input[0] == 'V'){
            first_char_table = input[0];
            break;
          }

          int index = atoi(input.c_str());
          ss >> input;
          interface_vpn[index] = input;
        }
        break;
      }

      case 'V': /*Interface-vpn*/{
        string input;
        while(true){
          if(input[0] != 'v')
            ss >> input;
          if(input[0] == 'I'){
            for (int i = 0; i < 4; i++)
              ss >> input;
            ss >> input;
            first_char_table = input[0];
            break;
          }
          struct vrf *vrf_temp = new struct vrf;
          vrf_temp->vpn_name = input;
          for(int i =
           0; i < 5; i++)
            ss >> input;
          while(true){
            ss >> input;
            if(input[0] == 'T' || input[0] == 'v')
              break;
            struct vrfi *vrfi_temp = new struct vrfi;
            vrfi_temp->ip = ip_string_binary(input);
            ss >> input;
            vrfi_temp->mask = ip_string_binary(input);
            ss >> input;
            vrfi_temp->vpn_label = atoi(input.c_str());
            ss >> input;
            vrfi_temp->egress_ip = ip_string_binary(input);
            ss >> input;
            if(input[0] == 'N')
              vrfi_temp->ifaceIndex = -1;
            else
              vrfi_temp->ifaceIndex = atoi(input.c_str());
            vrf_temp->vrfi_array.push_back(vrfi_temp);
          }
          vrf_table[vrf_temp->vpn_name] = vrf_temp;
          if(input[0] == 'T'){
            first_char_table = input[0];
            break;
          }
        }
        break;
      }

      case 'T': /*Tunnel Table*/{
        string input;
        for(int i = 0; i < 5; i++)
          ss >> input;
        while(true){
          ss >> input;
          if(input[0] == 'L'){
            first_char_table = input[0];
            break;
          }
          struct tunnel_node *tunnel_node_temp = new struct tunnel_node;
          tunnel_node_temp->ip = ip_string_binary(input);
          ss >> input;
          if(input[0] == 'N')
            tunnel_node_temp->tunnel_label = -1;
          else
            tunnel_node_temp->tunnel_label = atoi(input.c_str());
          
          ss >> input;
          tunnel_node_temp->egress_interface = atoi(input.c_str());
          ss >> input;
          sscanf(input.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &(tunnel_node_temp->nextMAC[0]), &(tunnel_node_temp->nextMAC[1]), 
                    &(tunnel_node_temp->nextMAC[2]), &(tunnel_node_temp->nextMAC[3]), &(tunnel_node_temp->nextMAC[4]), 
                    &(tunnel_node_temp->nextMAC[5]));
          tunnel_table.push_back(tunnel_node_temp);
        }
        break;
      }

      case 'L': /*LS Table*/{
        string input;
        string cach_input;
        for(int i = 0; i < 5; i++)
          ss >> input;
        cach_input = input;
        // cout << input << endl;
        // cin >> n;
        while(true){
          // cout << "in while" << endl;
          ss >> input;
          // cout << input << endl;
          if(input == cach_input)
            break;
          struct label_routing_node *ls_node = new struct label_routing_node;
          ls_node->ingress_label = atoi(input.c_str());
          
          ss >> input;
          if(input[0] == 'P')
            ls_node->egress_label = -1;
          else
            ls_node->egress_label = atoi(input.c_str());
          
          ss >> input;
          ls_node->vpn = false;
          if(input[0] != 'v')
            sscanf(input.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &(ls_node->nextMAC[0]), &(ls_node->nextMAC[1]), 
                    &(ls_node->nextMAC[2]), &(ls_node->nextMAC[3]), &(ls_node->nextMAC[4]), &(ls_node->nextMAC[5]));
          else{
            ls_node->vpn = true;
            ls_node->vpn_name = getVPNfromLS(input);
          }
          ss >> input;
          cach_input = input;
          if(input[0] == 'N')
            ls_node->egress_interface = -1;
          else
            ls_node->egress_interface = atoi(input.c_str());
          label_routing_table.push_back(ls_node);
        }
        end = true;
        break;
      }
    }
  }
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
  /*cerr << "Frame received at iface " << ifaceIndex <<
    " with length " << frame.length << endl;*/

  uint8_t *data = new uint8_t [frame.length];
  int frame_length = frame.length;
  memcpy(data, frame.data, frame.length);
  
  struct sr_ethernet_hdr *ether = (struct sr_ethernet_hdr*)data;

  //***************************************** MPLS *****************************************// 
  if(ntohs(ether->ether_type) == ETHERTYPE_MPLS){
    struct mpls_label *label = (struct mpls_label*)(data + sizeof(struct sr_ethernet_hdr));
    label->entry = ntohl(label->entry);



    int ingress_label = (label->entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
    struct label_routing_node *target_router = getLabelNode(ingress_label);
    if(target_router == NULL)
      return;
    
    if(target_router->egress_label == -1){ /* POP */
      if(!target_router->vpn){/*just POP the label and forward*/
        //Frame *frame_temp = popLabel(data, frame_length);

        uint8_t *data_temp = new uint8_t[frame.length - sizeof(struct mpls_label)];
        memcpy(data_temp, data, sizeof(struct sr_ethernet_hdr));
        data = data + sizeof(struct sr_ethernet_hdr) + sizeof(struct mpls_label);
        memcpy(data_temp + sizeof(struct sr_ethernet_hdr), data, frame.length - sizeof(struct sr_ethernet_hdr) - sizeof(struct mpls_label));
        
        struct sr_ethernet_hdr *ether_dest = (struct sr_ethernet_hdr*)data_temp;
        memcpy(ether_dest->ether_shost, ether_dest->ether_dhost, 6);
        memcpy(ether_dest->ether_dhost, target_router->nextMAC, 6);


        Frame frame_temp(frame.length - sizeof(struct mpls_label), data_temp);

        cout << "the label of the packet with label " << ingress_label << " popped" <<endl;
        sendFrame(frame_temp, target_router->egress_interface);
        return;
      }
      else{/*look in vrfs*/
        struct vrfi *vrfi_dest = getVRFi_by_label_vrf(ingress_label, vrf_table[target_router->vpn_name]);
        //Frame *frame_temp = popLabel(data, frame_length);
        uint8_t *data_temp = new uint8_t[frame.length - sizeof(struct mpls_label)];
        memcpy(data_temp, data, sizeof(struct sr_ethernet_hdr));
        data = data + sizeof(struct sr_ethernet_hdr) + sizeof(struct mpls_label);
        memcpy(data_temp + sizeof(struct sr_ethernet_hdr), data, frame.length - sizeof(struct sr_ethernet_hdr) - sizeof(struct mpls_label));
        
        struct sr_ethernet_hdr *ether_dest = (struct sr_ethernet_hdr*)data_temp;
        memcpy(ether_dest->ether_shost, ether_dest->ether_dhost, 6);
        ether_dest->ether_type = htons(ETHERTYPE_IP);

        Frame frame_temp(frame.length - sizeof(struct mpls_label), data_temp);

        struct msg_stored *msg_stored_temp = new struct msg_stored;
        msg_stored_temp->data = new uint8_t[frame_temp.length];
        msg_stored_temp->data = frame_temp.data;
        msg_stored_temp->length = frame_temp.length;
        arp_waiting_que[vrfi_dest->egress_ip] = msg_stored_temp;

        sendARPReq(vrfi_dest->ifaceIndex, vrfi_dest->egress_ip);
        return;
      }
    }
    if(target_router->egress_label != -1){ /* change label*/
      forwardMPLSPacket(data, frame.length, target_router);
      return;
    }
  }
  //***************************************** End of MPLS *****************************************//

  //***************************************** ARP *****************************************//
  if(ntohs(ether->ether_type) == ETHERTYPE_ARP){
    struct arp *arp = (struct arp*)(data + sizeof(struct sr_ethernet_hdr));
    //An ARP Requset arrived
    if(ntohs(arp->arp_op) == ARP_OP_REQUEST){
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
          uint8_t *data_temp = awaken_msg->data;
          struct sr_ethernet_hdr *ether_dest = (struct sr_ethernet_hdr*)data_temp;
          memcpy(ether_dest->ether_dhost, destMac, 6);
          Frame frame_temp(awaken_msg->length, data_temp);

          struct ip *ip_dest = (struct ip*)(data_temp + sizeof(struct sr_ethernet_hdr));


          sendFrame(frame_temp, ifaceIndex);
          cout << "the packet for " <<  ip_binary_string(ntohl(ip_dest->ip_dst.s_addr)) << " forwarded to " << 
                ip_binary_string(ntohl(arp->arp_ip_source)) << " on " << ifaceIndex << endl;
          arp_waiting_que.erase(ntohl(arp->arp_ip_source));
          return;
        }
        else{
          /*cout << "saved masg not founded" << endl;*/
          return;
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

          char *msg_char = new char[str_len + 1];

          memcpy(msg_char, data + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_udp), str_len);
          msg_char[str_len] = '\0';
          uint8_t *data_temp_temp =  data + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_udp);
          string msg = msg_char;

          cout << "A message from " << getIPString(ntohl(iphdr->ip_src.s_addr)) << " : " << msg << endl;
          return;
        }
      }
    }
    //****** End of Get MSG *****//


    //****** Forward *****//
    else{
      if(interface_vpn[ifaceIndex][0] != 'N'){/*Forward with MPLS label*/
        //Get VRFi by dst IP and input Interface
        struct vrfi *vrfi_dest = getVRFi_inVRF(ntohl(iphdr->ip_dst.s_addr), vrf_table[interface_vpn[ifaceIndex]]);
        if(vrfi_dest == NULL)
          return;
        cout << "a packet from " << interface_vpn[ifaceIndex] << " received\n";
        //send packet directly to dest without any label
        if(vrfi_dest->ifaceIndex != -1){
          if(ifaceIndex != vrfi_dest->ifaceIndex){
            memcpy(ether->ether_shost, ether->ether_dhost, 6);
            struct msg_stored *msg_stored_temp = new struct msg_stored;
            msg_stored_temp->data = data;
            msg_stored_temp->length = frame_length;
            arp_waiting_que[vrfi_dest->egress_ip] = msg_stored_temp;

            sendARPReq(vrfi_dest->ifaceIndex, vrfi_dest->egress_ip);
            return;
          }
          else{
            uint8_t tempMac[6];
            memcpy(tempMac, ether->ether_shost, 6);
            memcpy(ether->ether_shost, ether->ether_dhost, 6);
            memcpy(ether->ether_dhost, tempMac, 6);
            Frame frame_temp(frame_length, data);
            sendFrame(frame_temp, ifaceIndex);
            return; 
          }
        }
        //search in non CE neighbors
        int neigh_index = getNeighbor(vrfi_dest->egress_ip);
        if(neigh_index != -1){
          /*TODO write this part*/
        }
        //Get Tunnel Label
        struct tunnel_node *tunnel_dest = getTunnelNode(vrfi_dest->egress_ip);
        if(tunnel_dest == NULL)
          return;
        Frame *frame_temp = addLabel(data, frame_length, tunnel_dest->nextMAC, vrfi_dest->vpn_label, tunnel_dest->tunnel_label, vrfi_dest->egress_ip);
        sendFrame(*frame_temp, tunnel_dest->egress_interface);
        return;
      }
      else{/*normal routing*/
        int neigh_index = getNeighbor(ntohl(iphdr->ip_dst.s_addr)); /*check neighbors*/
        if(neigh_index != -1){
          memcpy(ether->ether_shost, iface[neigh_index].mac, 6);


          struct msg_stored *save_msg = new struct msg_stored;
          save_msg->data = data;
          save_msg->length = frame_length;
          arp_waiting_que[ntohl(iphdr->ip_dst.s_addr)] = save_msg;

          sendARPReq(neigh_index, ntohl(iphdr->ip_dst.s_addr));
          return;
        }
        //Search in default table
        struct default_node *node = getDefault(ntohl(iphdr->ip_dst.s_addr));
        if(node == NULL){
          cout << "Destination is unreachable" << endl;
          return;
        }
        memcpy(ether->ether_shost, iface[node->ifaceIndex].mac, 6);

        struct msg_stored *msg_stored_temp = new struct msg_stored;
        msg_stored_temp->data = data;
        msg_stored_temp->length = frame_length;
        arp_waiting_que[node->egress_ip] = msg_stored_temp;

        sendARPReq(node->ifaceIndex, node->egress_ip);
        return;
      }
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
      string str_destIp;
      string str_vrfIndex;
      string msg;

      cin >> str_destIp >> str_vrfIndex >> msg;
      uint32_t destIp = ip_string_binary(str_destIp);
      
      //if vrf index equals to '--' this means target send it non VPN or in its VPN
      if(str_vrfIndex != "--"){
        //Search vrf_table
        struct vrf *vrf_dest = vrf_table[str_vrfIndex];
        if(vrf_dest == NULL){
          continue;
        }
        struct vrfi *vrfi_dest = getVRFi_inVRF(destIp, vrf_dest);
        if(vrfi_dest == NULL)
          continue;
        if(vrfi_dest->ifaceIndex != -1){
          Frame *frame = createMPLS_IP_packet(destIp, broadcastMAC, vrfi_dest->ifaceIndex, -1, -1, msg);

          struct msg_stored *save_msg = new struct msg_stored;
          save_msg->data = frame->data;
          save_msg->length = frame->length;

          arp_waiting_que[destIp] = save_msg;
          sendARPReq(vrfi_dest->ifaceIndex, destIp);
          continue;
        }

        struct tunnel_node *tunnel_node_temp = getTunnelNode(vrfi_dest->egress_ip);
        if(tunnel_node_temp == NULL)
          continue;

        Frame *frame = createMPLS_IP_packet(destIp, tunnel_node_temp->nextMAC, tunnel_node_temp->egress_interface, 
                      vrfi_dest->vpn_label, tunnel_node_temp->tunnel_label, msg);

        sendFrame(*frame, tunnel_node_temp->egress_interface);
        continue;
      }
      else{
        int neigh_index = getNeighbor(destIp);
        if(neigh_index != -1){
          struct msg_stored *save_msg = new struct msg_stored;

          Frame *frame = createMPLS_IP_packet(destIp, broadcastMAC, neigh_index, -1, -1, msg);
          save_msg->data = frame->data;
          save_msg->length = frame->length;

          arp_waiting_que[destIp] = save_msg;

          sendARPReq(neigh_index, destIp);
          continue;
        }
        //Search in default table
        struct default_node *node = getDefault(destIp);
        if(node == NULL){
          cout << "Destination is unreachable" << endl;
          continue;
        }

        struct msg_stored *save_msg = new struct msg_stored;

        Frame *frame = createMPLS_IP_packet(destIp, broadcastMAC, node->ifaceIndex, -1, -1, msg);
        save_msg->data = frame->data;
        save_msg->length = frame->length;

        arp_waiting_que[node->egress_ip] = save_msg;

        sendARPReq(node->ifaceIndex, node->egress_ip);
        continue;
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

