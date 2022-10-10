#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct pcap_hdr {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr;

typedef struct pcap_pkthdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_pkthdr;

typedef struct ethernet_hdr {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
} ethernet_hdr;

typedef struct ip_hdr {
   uint8_t hlen : 4;
   uint8_t version : 4;
   uint8_t service;
   uint16_t total_len;
   uint16_t id;
   uint16_t frag;
   uint8_t time_to_live;
   uint8_t protocol;
   uint16_t checksum;
   uint8_t src_addr[4];
   uint8_t dest_addr[4];
} ip_hdr;

int main()
{
    FILE* fp;
    pcap_hdr dummy;
    
    int pkt_count = 1;

    if ((fp = fopen("Ethernet.pcap", "rb")) == NULL){
        printf("Failed to load file.\n");
        exit(1);
    }

    fread(&dummy, sizeof(pcap_hdr), 1, fp);

    while (!feof(fp)){
        pcap_pkthdr packet_hdr;
        char pkt_data[100000];

        if (pkt_count > 30) break;
        if ((fread(&packet_hdr, sizeof(pcap_pkthdr), 1, fp)) != 1) break;
        fread(pkt_data, 1, packet_hdr.incl_len, fp);

        uint32_t temp_h = packet_hdr.ts_sec / 3600 % 24;
        uint32_t temp_m = packet_hdr.ts_sec % 3600 / 60;
        uint32_t temp_s = packet_hdr.ts_sec % 3600 % 60; 

        //1. local time 
        printf("\nPacket %d\n", pkt_count);
        printf("time: %02d:%02d:%02d:%06d\n", temp_h, temp_m, temp_s, packet_hdr.ts_usec);
        

        //ethernet protocol parse
        ethernet_hdr* eth_header = (ethernet_hdr*) pkt_data;


        

        //ip protocol parse
        ip_hdr* ip_header = (ip_hdr*)(pkt_data + sizeof(ethernet_hdr));

        //2. cap len, real len, len in IP header
        printf("captured length: %u bytes\n", packet_hdr.incl_len);
        printf("actual length: %u bytes\n",packet_hdr.orig_len);
        printf("length of IP header: %u bytes\n",ip_header->hlen*4);

        //3. src dst MAC
        printf("Source MAC: ");
        for (int i=0;i<5;i++){
            printf("%02x:", eth_header->src_mac[i]);
        }
        printf("%02x\n", eth_header->src_mac[5]);

        printf("Destination MAC: ");
        for (int i=0;i<5;i++){
            printf("%02x:", eth_header->dest_mac[i]);
        }
        printf("%02x\n", eth_header->dest_mac[5]);

        //4. src dst IP
        printf("Source IP: ");
        for (int i=0;i<3;i++){
            printf("%d.", ip_header->src_addr[i]);
        }
        printf("%d\n", ip_header->src_addr[3]);

        printf("Destination IP: ");
        for (int i=0;i<3;i++){
            printf("%d.", ip_header->dest_addr[i]);
        }
        printf("%d\n", ip_header->dest_addr[3]);

        switch (ip_header->protocol){
            case 1:
                printf("Protocol: ICMP\n");
                break;
            case 6:
                printf("Protocol: TCP\n");
                break;
            case 17:
                printf("Protocol: UDP\n");
                break;
            default:
                break;
        }

        printf("Packet TTL: %d\n", ip_header->time_to_live);
        printf("Identification: %d\n", ip_header->id);
        printf("DF: %d\n", (ip_header->frag & 0x40) >> 6);
        printf("MF: %d\n", ip_header->frag & 0x20);

        switch(ip_header->service >> 5){
            case 0:
                printf("Type of Service: Routine");
                break;
            case 1:
                printf("Type of Service: Priority");
                break;
            case 2:
                printf("Type of Service: Immediate");
                break;
            case 3:
                printf("Type of Service: Flash");
                break;
            case 4:
                printf("Type of Service: Flash Override");
                break;
            case 5:
                printf("Type of Service: Critical");
                break;
            case 6:
                printf("Type of Service: Internetwork Control");
                break;
            case 7:
                printf("Type of Service: Network Control");
                break;
            default:
                break;
        }
        printf("\n");
        printf("Delay: %d\n", ip_header->service & 0x8);
        printf("Throughput: %d\n", ip_header->service & 0x4);
        printf("Reliability: %d\n", ip_header->service & 0x2);
        printf("Minimum Cost: %d\n", ip_header->service & 0x1);
        pkt_count++;
    }

    


}