#ifndef __LIBNET_HEADERS_H
#define __LIBNET_HEADERS_H
/**
 * @file libnet-headers.h
 * @brief libnet header information
 */

/**
 * Libnet defines header sizes for every builder function exported.
 */
#define LIBNET_ARP_H            0x08    /**< ARP header w/o addrs: 8 bytes */
#define LIBNET_ARP_ETH_IP_H     0x1c    /**< ARP w/ ETH and IP:   28 bytes */
#define LIBNET_ETH_H            0x0e    /**< Ethernet header:     14 bytes */
#define LIBNET_IPV4_H           0x14    /**< IPv4 header:         20 bytes */
#define LIBNET_IPV6_H           0x28    /**< IPv6 header:         40 bytes */
#define LIBNET_TCP_H            0x14    /**< TCP header:          20 bytes */
#define LIBNET_UDP_H            0x08    /**< UDP header:           8 bytes */


/* 
 *  ARP header
 *  Address Resolution Protocol
 *  Base header size: 8 bytes
 */
struct libnet_arp_hdr
{
    u_int16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    u_int16_t ar_pro;         /* format of protocol address */
    u_int8_t  ar_hln;         /* length of hardware address */
    u_int8_t  ar_pln;         /* length of protocol addres */
    u_int16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */
};


/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */

#define ETHER_ADDR_LEN 0x06

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

#ifndef ETHERTYPE_PUP
#define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP           0x0806  /* addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035  /* reverse addr. resolution protocol */
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_EAP
#define ETHERTYPE_EAP           0x888e  /* IEEE 802.1X EAP authentication */
#endif
#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS          0x8847  /* MPLS */
#endif
#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK      0x9000  /* used to test interfaces */
#endif

struct libnet_ether_addr
{
    u_int8_t  ether_addr_octet[6];        /* Ethernet address */
};

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */

#define LIBNET_LIL_ENDIAN  0x01

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  IP options
 */
#ifndef IPOPT_EOL
#define IPOPT_EOL       0   /* end of option list */
#endif
#ifndef IPOPT_NOP
#define IPOPT_NOP       1   /* no operation */
#endif   
#ifndef IPOPT_RR
#define IPOPT_RR        7   /* record packet route */
#endif
#ifndef IPOPT_TS
#define IPOPT_TS        68  /* timestamp */
#endif
#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY  130 /* provide s,c,h,tcc */   
#endif
#ifndef IPOPT_LSRR
#define IPOPT_LSRR      131 /* loose source route */
#endif
#ifndef IPOPT_SATID
#define IPOPT_SATID     136 /* satnet id */
#endif
#ifndef IPOPT_SSRR
#define IPOPT_SSRR      137 /* strict source route */
#endif


/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

#endif  /* __LIBNET_HEADERS_H */

/* EOF */
