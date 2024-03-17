#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ether.h>

#define ETHERTYPE_IP 0x0800
#define LIBNET_LIL_ENDIAN 1
#define LIBNET_BIG_ENDIAN 0

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

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


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("\n%u bytes captured\n", header->caplen);

        /* Ethernet Header */
        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
        if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;
        printf("type = %04x \n",ntohs(eth_hdr->ether_type));
        printf("Source MAC: %s\n" , ether_ntoa((struct ether_addr*)eth_hdr->ether_shost));
        printf("Destination MAC: %s\n" , ether_ntoa((struct ether_addr*)eth_hdr->ether_dhost));


        /* IPv4 Header */
        struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        if(ip_hdr->ip_p != IPPROTO_TCP) continue;
        printf("proto = %d \n", ip_hdr->ip_p);
        printf("Source IP: %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

        /* TCP Header */
        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
        printf("Source Port: %d\n",ntohs(tcp_hdr->th_sport));
        printf("Destination Port: %d\n",ntohs(tcp_hdr->th_dport));

        /* Data After TCP Header */
        u_int8_t *data = (u_int8_t *)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + (tcp_hdr->th_off)*4);
        size_t hdr_size = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + (tcp_hdr->th_off)*4;
        if(header->caplen > hdr_size){
            if(header->caplen - hdr_size < 10){ /* Ehternet Padding */
                printf("Ethernet Padding: ");
                for(size_t j=0;j<header->caplen - hdr_size;j++){
                    printf("0x%02X ", data[j]);
                }
                printf("\n");
                printf("Data 0 byte.\n");
            }else{ /* Print Data */
                printf("Data(10bytes): ");
                for(size_t j=0;j<10;j++){
                    printf("0x%02X ", data[j]);
                }
                printf("\n");
            }
        }else{ /* header->caplen == hdr_size */
            printf("Data 0 byte.\n");
        }
    }

    pcap_close(pcap);
}
