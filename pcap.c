#define __FAVOR_BSD
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>


#define MAC_ADDRSTRLEN 2*6+5+1
void dump_ethernet(u_int32_t length, const u_char *content);
void dump_ip(u_int32_t length, const u_char *content);
void dump_tcp(u_int32_t length, const u_char *content);
void dump_udp(u_int32_t length, const u_char *content);
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);
char *macnum_ntoa(u_char *d);
char *ip_ntoa(void *i);
char *ip_ttoa(u_int8_t flag);
char *ip_ftoa(u_int16_t flag);
char *tcp_ftoa(u_int8_t flag);

int specify = 0;
int decide;
char flag[4] = "";

int main(int argc, const char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    char *device;
    bpf_u_int32 net, mask;
    struct bpf_program fcode;
    char filename[100]="";
    //printf("%s\n", argv[1]);
    //printf("%s\n", argv[2]);
    device = pcap_lookupdev(errbuf);

    handle = pcap_open_live(device, 65535, 1, 1, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        exit(1);
    }//end if

    
    strcpy(filename,argv[2]);
    handle = pcap_open_offline(filename, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
        exit(1);
    }
    //printf("Open: %s\n", filename);

    //start capture
    int in = 0, i;
    i = atoi(argv[1]);
    //printf("%d\n",i);
    //sleep(10);
    if( argc > 3 )
    {
        //printf("%s\n", argv[3]);
        //sleep(10);
        if(strcmp(argv[3],"-c")==0)
        {
            strcpy(flag, argv[4]);
            specify = 1;
        }
    }
    pcap_loop(handle, i, pcap_callback, (u_char*)&in);

    //free
    pcap_close(handle);
    return 0;
}


char *macnum_ntoa(u_char *d)
{
    static char str[MAC_ADDRSTRLEN];
    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    return str;
}//end macnum_ntoa

char *ip_ntoa(void *i)
{
    static char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, i, str, sizeof(str));
    return str;
}//end ip_ntoa

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content)
{

    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    static int d = 0;
    u_char protocol = ip->ip_p;
    if( specify == 1 )
    {
        if( strncmp(flag, "tcp", 3) == 0)
        {
            if( protocol != IPPROTO_TCP ) return;
        }
        else 
        {
            if( protocol != IPPROTO_UDP ) return;
        }
    }

    printf("No. %d\n", ++d);

    //print header
    printf("Recieved time: %s", ctime((const time_t *)&header->ts.tv_sec));
    printf("Length: %d bytes\n", header->len);
    printf("Capture length: %d bytes\n", header->caplen);

    //dump ethernet
    dump_ethernet(header->caplen, content);

    printf("\n");
}//end pcap_callback

void dump_ethernet(u_int32_t length, const u_char *content)
{
    struct ether_header *ethernet = (struct ether_header *)content;
    char dst_mac_addr[MAC_ADDRSTRLEN] = {};
    char src_mac_addr[MAC_ADDRSTRLEN] = {};
    u_int16_t type;

    //copy header
    strncpy(dst_mac_addr, macnum_ntoa(ethernet->ether_dhost), sizeof(dst_mac_addr));
    strncpy(src_mac_addr, macnum_ntoa(ethernet->ether_shost), sizeof(src_mac_addr));
    type = ntohs(ethernet->ether_type);

    //print
    if(type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");

    //printf("+-------------------------+-------------------------+-------------------------+\n");
    printf(" - Destination MAC Address: %s\n", dst_mac_addr);
    //printf("+-------------------------+-------------------------+-------------------------+\n");
    printf(" - Source MAC Address: %s\n", src_mac_addr);
    //printf("+-------------------------+-------------------------+-------------------------+\n");
    if (type < 1500)
        printf(" - Length: %u\n", type);
    else
        printf(" - Ethernet Type: 0x%04x\n", type);
    //printf("+-------------------------+\n");

    switch (type)
    {
        case ETHERTYPE_ARP:
            printf("Next is ARP\n");
            break;

        case ETHERTYPE_IP:
            dump_ip(length, content);
            break;

        case ETHERTYPE_REVARP:
            printf("Next is RARP\n");
            break;

        case ETHERTYPE_IPV6:
            printf("Next is IPv6\n");
            break;

        default:
            printf("Next is %#06x", type);
            break;
    }//end switch

}//end dump_ethernet


void dump_ip(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_int version = ip->ip_v;
    u_int header_len = ip->ip_hl << 2;
    u_char tos = ip->ip_tos;
    u_int16_t total_len = ntohs(ip->ip_len);
    u_int16_t id = ntohs(ip->ip_id);
    u_int16_t offset = ntohs(ip->ip_off);
    u_char ttl = ip->ip_ttl;
    u_char protocol = ip->ip_p;
    u_int16_t checksum = ntohs(ip->ip_sum);

    //print
    printf("Protocol: IP\n");
    //printf("+------------+------------+-------------------------+\n");
    printf(" - Source IP Address: %s\n",  ip_ntoa(&ip->ip_src));
    //printf("+---------------------------------------------------+\n");
    printf(" - Destination IP Address: %s\n", ip_ntoa(&ip->ip_dst));
    //printf("+---------------------------------------------------+\n");
    
    switch (protocol)
    {
        case IPPROTO_UDP:
            dump_udp(length, content);
            //printf("Next is UDP\n");
            break;

        case IPPROTO_TCP:
            dump_tcp(length, content);
            break;

        case IPPROTO_ICMP:
            printf("Next is ICMP\n");
            break;

        default:
            printf("Next is %d\n", protocol);
            break;
    }//end switch
}//end dump_ip

void dump_tcp(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    u_int32_t sequence = ntohl(tcp->th_seq);
    u_int32_t ack = ntohl(tcp->th_ack);
    u_int8_t header_len = tcp->th_off << 2;
    u_int8_t flags = tcp->th_flags;
    u_int16_t window = ntohs(tcp->th_win);
    u_int16_t checksum = ntohs(tcp->th_sum);
    u_int16_t urgent = ntohs(tcp->th_urp);

    //print
    printf("Protocol: TCP\n");
    printf(" - Source Port: %u\n", source_port);
    printf(" - Destination Port: %u\n", destination_port);
    
    printf("\n");
}

void dump_udp(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));
    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);
    printf("Protocol: UDP\n");
    printf(" - Source Port: %u\n", source_port);
    printf(" - Destination Port: %u\n", destination_port);
    
    printf("\n");
}//end dump_udp