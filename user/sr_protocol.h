/*
 *  Copyright (c) 1998, 1999, 2000 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * sr_protocol.h
 *
 */

#ifndef SR_PROTOCOL_H
#define SR_PROTOCOL_H
#endif

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#include <sys/types.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>

#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 2
#endif
#ifdef _CYGWIN_
#ifndef __BYTE_ORDER
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#endif
#ifdef _LINUX_
#ifndef __BYTE_ORDER
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#endif
#ifdef _SOLARIS_
#ifndef __BYTE_ORDER
#define __BYTE_ORDER __BIG_ENDIAN
#endif
#endif

/*
 * Fix for Mac OS X
 */
#ifndef __BYTE_ORDER
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif

/*
 * Structure of an Internet Protocol header, naked of options.
 */
struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;       /* header length */
    unsigned int ip_v:4;        /* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;        /* version */
    unsigned int ip_hl:4;       /* header length */
#else
#error "Byte ordering not specified "
#endif
    uint8_t ip_tos;         /* type of service */
    uint16_t ip_len;            /* total length */
    uint16_t ip_id;         /* identification */
    uint16_t ip_off;            /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    uint8_t ip_ttl;         /* time to live */
    uint8_t ip_p;           /* protocol */
    uint16_t ip_sum;            /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
  } __attribute__ ((packed)) ;

/*
 *  Ethernet packet header prototype.  Too many O/S's define this differently.
 *  Easy enough to solve that and define it here.
 */
struct sr_ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    uint16_t ether_type;                     /* packet type ID */
} __attribute__ ((packed)) ;

#ifndef IPPROTO_TCP
#define IPPROTO_TCP            0x0006  /* TCP protocol */
#endif


#ifndef IPPROTO_UDP
#define IPPROTO_UDP            0x0011  /* UDP protocol */
#endif

#ifndef IPPORTO_ICMP
#define IPPORTO_ICMP            0x0001  /* ICMP protocol */


#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP           0x0806 /* ARP protocl */
#endif

#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS          0x08847 /* ARP protocl */
#endif

struct sr_tcp
{
    uint16_t port_src; /* source port */
    uint16_t port_dst; /* destination port */
    uint32_t tcp_seq; /* sequence number */
    uint32_t tcp_ack; /* acknowledgement number */
    #define TCP_FIN 0x1 /* FIN flag */
    #define TCP_SYN 0x2 /* SYN flag */
    #define TCP_RST 0x4 /* RST flag */
    #define TCP_PSH 0x8 /* PSH flag */
    #define TCP_ACK 0x10 /* ACK flag */
    #define TCP_URG 0x20 /* URG flag */
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        unsigned int tcp_ecn_1:1; /* ecn, the first bit */
        unsigned int tcp_reserved:3; /* reserved */
        unsigned int tcp_doff:4; /* data offset */
        unsigned int tcp_flags:6; /* flags */
        unsigned int tcp_ecn_2:2; /* ecn, the last 2 bits */
    #elif __BYTE_ORDER == __BIG_ENDIAN
        unsigned int tcp_doff:4; /* data offset */
        unsigned int tcp_reserved:3; /* reserved */
        unsigned int tcp_ecn_1:1; /* ecn, the first bit */
        unsigned int tcp_ecn_2:2; /* ecn, the last 2 bits */
        unsigned int tcp_flags:6; /* flags */
    #else
        #error "Byte ordering not specified "
    #endif
    uint16_t tcp_window; /* window size */
    uint16_t tcp_sum; /* checksum */
    uint16_t tcp_ptr; /* urgent pointer */
} __attribute__ ((packed)) ;
/* for using: struct sr_tcp * tcp=(struct sr_tcp *)((void *)ip_hdr+ip_hdr->ip_hl*4); */

struct sr_udp
{
    uint16_t port_src; /* source port */
    uint16_t port_dst; /* destination port */
    uint16_t length; /* length of udp header and data in bytes */
    uint16_t udp_sum; /* checksum */
} __attribute__ ((packed)) ;


/* Reference: RFC 5462, RFC 3032
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Label                  | TC  |S|       TTL     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *      Label:  Label Value, 20 bits
 *      TC:     Traffic Class field, 3 bits
 *      S:      Bottom of Stack, 1 bit
 *      TTL:    Time to Live, 8 bits
 */

struct mpls_label {
        uint32_t entry;
} __attribute__ ((packed)) ;

#define MPLS_LS_LABEL_MASK      0xFFFFF000
#define MPLS_LS_LABEL_SHIFT     12
#define MPLS_LS_TC_MASK         0x00000E00
#define MPLS_LS_TC_SHIFT        9
#define MPLS_LS_S_MASK          0x00000100
#define MPLS_LS_S_SHIFT         8
#define MPLS_LS_TTL_MASK        0x000000FF
#define MPLS_LS_TTL_SHIFT       0

/* Reserved labels */
#define MPLS_LABEL_IPV4NULL             0 /* RFC3032 */
#define MPLS_LABEL_RTALERT              1 /* RFC3032 */
#define MPLS_LABEL_IPV6NULL             2 /* RFC3032 */
#define MPLS_LABEL_IMPLNULL             3 /* RFC3032 */
#define MPLS_LABEL_ENTROPY              7 /* RFC6790 */
#define MPLS_LABEL_GAL                  13 /* RFC5586 */
#define MPLS_LABEL_OAMALERT             14 /* RFC3429 */
#define MPLS_LABEL_EXTENSION            15 /* RFC7274 */




//! ARP request operation.
#define ARP_OP_REQUEST          0x0001
//! ARP reply operation.
#define ARP_OP_REPLY            0x0002
//! RARP request operation.
#define RARP_OP_REQUEST         0x0003
//! RARP reply operation.
#define RARP_OP_REPLY           0x0004

#ifndef HTYPE_Ether
#define HTYPE_Ether           0x0001 /* Ethernet HTYPE*/
#endif

#ifndef PTYPE_IPv4
#define PTYPE_IPv4            0x0800 /* IPv4 PTYPE */
#endif

#ifndef HLEN_Ether 
#define HLEN_Ether            0x06 /* ARP protocl */
#endif

#ifndef PLEN_IPv4
#define PLEN_IPv4             0x04 /* ARP protocl */
#endif

// The ARP packet structure.
struct arp{
        //! Format of hardware address.
        uint16_t arp_hard_type;
        //! Format of protocol address.
        uint16_t arp_proto_type;
        //! Length of hardware address.
        uint8_t  arp_hard_size;
        //! Length of protocol address.
        uint8_t  arp_proto_size;
        //! ARP operation code (command).
        uint16_t arp_op;
        //! Hardware source address.
        uint8_t  arp_eth_source[6];
        //! IP source address.
        uint32_t arp_ip_source;
        //! Hardware destination address.
        uint8_t  arp_eth_dest[6];
        //! IP destination address.
        uint32_t arp_ip_dest;
} __attribute__ ((packed));



#endif /* -- SR_PROTOCOL_H -- */

