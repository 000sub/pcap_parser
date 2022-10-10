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
   uint32_t src_addr;
   uint32_t dest_addr;
} ip_hdr;

int main()
{
    FILE* fp;
    pcap_hdr dummy;
    pcap_pkthdr packet_hdr;
    char pkt_data[100000];
    int pkt_count = 1;

    if ((fp = fopen("sample.pcap", "rb")) == NULL){
        printf("Failed to load file.\n");
        exit(1);
    }

    fread(&dummy, sizeof(pcap_hdr), 1, fp);

    while (!feop(fp)){
        if (pkt_count > 30) break;
        if ((fread(&packet_hdr, sizeof(pcap_pkthdr), 1, fp)) != 1) break;
        fread(pkt_data, 1, packet_hdr.incl_len, fp);

        //print infos in packet_hdr
        //1. local time 
        //2. cap len, real len, len in IP header

        //ethernet protocol parse
        ethernet_hdr* eth_header = (ethernet_hdr*) pkt_data;

        //3. src dst MAC
        printf("Source MAC: ");
        for (int i=0;i<4;i++){
            printf("%02x:", eth_header->src_mac[i]);
        }
        printf("%02x\n", eth_header->src_mac);

        printf("Destination MAC: ");
        for (int i=0;i<4;i++){
            printf("%02x:", eth_header->dest_mac[i]);
        }
        printf("%02x\n", eth_header->dest_mac);

        //ip protocol parse
        ip_hdr* ip_header = (ip_hdr*)(pkt_data + sizeof(ethernet_hdr));


        pkt_count++;
    }

    


}