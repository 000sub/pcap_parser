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

uint16_t ntoh(uint16_t id){
    return (id<<8) | (id>>8);
}

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

        if ((fread(&packet_hdr, sizeof(pcap_pkthdr), 1, fp)) != 1) break;
        fread(pkt_data, 1, packet_hdr.incl_len, fp);

        uint32_t temp_h = (packet_hdr.ts_sec / 3600 % 24 + 9) % 24; //UTC+9
        uint32_t temp_m = packet_hdr.ts_sec % 3600 / 60;
        uint32_t temp_s = packet_hdr.ts_sec % 3600 % 60; 

        //ethernet protocol parse
        ethernet_hdr* eth_header = (ethernet_hdr*) pkt_data;
        //ip protocol parse
        ip_hdr* ip_header = (ip_hdr*)(pkt_data + sizeof(ethernet_hdr));

        //1. local time 
        printf("\nPacket %d\n", pkt_count);
        printf("time: %02d:%02d:%02d:%06d (UTC+9)\n", temp_h, temp_m, temp_s, packet_hdr.ts_usec);

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

        //5. protocol
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

        
        printf("Identification: %d\n", ntoh(ip_header->id));
        printf("DF: %d, ", (ip_header->frag & 0x40) >> 6);
        printf("MF: %d\n", ip_header->frag & 0x20);
        printf("Time to live: %d\n", ip_header->time_to_live);
        switch(ip_header->service >> 2){
            case 0:
                printf("DSCP: CS0");
                break;
            case 1:
                printf("DSCP: LE");
                break;
            case 8: case 10: case 12: case 14:
                printf("DSCP: CS1");
                break;
            case 16: case 18: case 20: case 22:
                printf("DSCP: CS2");
                break;
            case 24: case 26: case 28: case 30:
                printf("DSCP: CS3");
                break;
            case 32: case 34: case 36: case 38:
                printf("DSCP: CS4");
                break;
            case 40: case 46:
                printf("DSCP: CS5");
                break;
            case 48:
                printf("DSCP: CS6");
                break;
            case 56:
                printf("DSCP: CS7");
                break;
            default:
                break;
        }

        printf(", ");

        switch(ip_header->service & 0x3){
            case 0:
                printf("ECN: Not-ECT\n");
                break;
            case 1:
                printf("ECN: ECT(0)\n");
                break;
            case 2:
                printf("ECN: ECT(1)\n");
                break;
            case 3:
                printf("ECN: CE\n");
                break;
            default:
                break;
        }
        pkt_count++;
    }

    


}