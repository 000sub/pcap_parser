#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/msg.h> 
#include <sys/ipc.h> 
#include <netinet/in.h>

#define PORT_NUM 8202

typedef struct {
  uint16_t xid;      
  uint16_t flags;    
  uint16_t qdcount;  
  uint16_t ancount; 
  uint16_t nscount;  
  uint16_t arcount; 
} dns_header_t;

typedef struct {
  char *name;        
  uint16_t dnstype;  
  uint16_t dnsclass; 
} dns_question_t;

typedef struct {
  uint16_t compression;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t length;
  struct in_addr addr;
} __attribute__((packed)) dns_answer_t;

int main(int argc, char** argv){
    dns_header_t header;
    dns_question_t question;
    socklen_t dns_response_len = 0, clilen;
    unsigned char response[512];
    struct sockaddr_in sktaddr, dnsaddr, servaddr, cliaddr;
    char domain_name[50], ip_addr[50];
    char buf[1024], tokens[1024];
    int sockfd, dnsfd, listenfd, connfd;

    //create DNS socket
    if ((dnsfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
        printf("DNS socket creating error.\n");
        exit(1);
    }

    dnsaddr.sin_family = AF_INET;
    dnsaddr.sin_addr.s_addr = htonl(0x01010101); //Cloudflare 1.1.1.1
    dnsaddr.sin_port = htons(53);

    //DNS header set
    memset(&header, 0x00, sizeof(dns_header_t));
    header.xid = htons(0x1234);
    header.flags = htons(0x0100);
    header.qdcount = htons(1);

    strcpy(domain_name, "2022fcn.ddns.net");

    //DNS question set
    question.dnstype = htons(1);
    question.dnsclass = htons(1);
    question.name = calloc(strlen(domain_name) + 2, sizeof (char)); // +2 for termination
    memcpy(question.name +1, domain_name, strlen(domain_name));
    uint8_t *prev = (uint8_t *) question.name;
    uint8_t count = 0;

    //replace '.' with field length
    for (size_t i = 0; i < strlen(domain_name); i++)
    {
        if (domain_name[i] == '.')
        {
            *prev = count;
            prev = question.name + i + 1;
            count = 0;
        }
        else
        count++;
    }
    *prev = count;

    //Copy all fields into a single packet 
    size_t packetlen = sizeof(header) + strlen(domain_name) + 2 + sizeof(question.dnstype) + sizeof(question.dnsclass);
    uint8_t *packet = calloc(packetlen, sizeof(uint8_t));
    uint8_t *p = (uint8_t *)packet;
    memcpy(p, &header, sizeof(header));
    p += sizeof(header);
    memcpy(p, question.name, strlen(domain_name) + 1);
    p += strlen(domain_name) + 2;
    memcpy(p, &question.dnstype, sizeof(question.dnstype));
    p += sizeof(question.dnstype);
    memcpy(p, &question.dnsclass, sizeof(question.dnsclass));

    // send DNS packet
    if (sendto(dnsfd, packet, packetlen, 0, (struct sockaddr *) &dnsaddr, (socklen_t) sizeof(dnsaddr)) == -1){
        printf("DNS request error.\n");
        exit(1);
    }

    // receive DNS response and close DNS socket
    memset(&response, 0x00, 512);

    if (recvfrom(dnsfd, response, 512, 0, (struct sockaddr *) &dnsaddr, &dns_response_len) == -1){
        printf("DNS response error.\n");
        exit(1);
    }
    close(dnsfd);

    dns_header_t *response_header = (dns_header_t *)response;
    uint8_t *start_of_name = (uint8_t *) (response + sizeof (dns_header_t));
    uint8_t total = 0;
    uint8_t *field_length = start_of_name;
    while (*field_length != 0) {
        total += *field_length + 1;
        *field_length = '.';
        field_length = start_of_name + total;
    }

    dns_answer_t *dns_answer = (dns_answer_t *) (field_length + 5);
    strcpy(ip_addr, inet_ntoa(dns_answer[0].addr));
    
    //create TCP socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        printf("TCP socket creating error.\n");
        exit(1);
    }

    sktaddr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_addr, &sktaddr.sin_addr) != 1){
        printf("inet_pton call error.\n");
        exit(1);
    }
    sktaddr.sin_port = htons(50000);

    if (connect(sockfd, (struct sockaddr*)&sktaddr, sizeof(sktaddr)) == -1){
        printf("server connection error.\n");
        exit(1);
    }

    //create another TCP socket that receive tokens
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        printf("socket creating error.\n");
        exit(1);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT_NUM);

    if (bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){
        printf("bind error.\n");
        close(listenfd);
        exit(1);
    }

    if (listen(listenfd, 1) == -1){
        printf("listen error.\n");
        close(listenfd);
        exit(1);
    }


    //Interact with server
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);

    //1: Type your ID
    memset(buf, 0x00, sizeof(buf));
    read(0, buf, sizeof(buf));
    write(sockfd, buf, strlen(buf));

    //print next instrument in terminal
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);

    //3: Your server IP address
    memset(buf, 0x00, sizeof(buf));
    read(0, buf, sizeof(buf));
    write(sockfd, buf, strlen(buf));

    //print next instrument in terminal
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);

    //5: Your server Port Number
    memset(buf, 0x00, sizeof(buf));
    read(0, buf, sizeof(buf));
    write(sockfd, buf, strlen(buf));

    //print next instrument in terminal
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);

    //7: confirm -> [Y/N]
    memset(buf, 0x00, sizeof(buf));
    read(0, buf, sizeof(buf));
    write(sockfd, buf, strlen(buf));

    //print next instrument in terminal
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);

    //8: confirm -> [Y]
    memset(buf, 0x00, sizeof(buf));
    read(0, buf, sizeof(buf));
    write(sockfd, buf, strlen(buf));

    //print next instrument in terminal
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);

    //9: If server is concurrent, type OK
    memset(buf, 0x00, sizeof(buf));
    read(0, buf, sizeof(buf));
    write(sockfd, buf, strlen(buf));

    //get tokens
    sleep(15);
    memset(tokens, 0x00, sizeof(tokens));
    clilen = sizeof(cliaddr);
    connfd = accept(listenfd, (struct sockaddr*) &cliaddr, &clilen);
    while (recv(connfd, tokens, 1024,0) > 0);
    tokens[strlen(tokens)-1] = '\n';
    write(sockfd, tokens, strlen(tokens));

    sleep(3);
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);
    memset(buf, 0x00, sizeof(buf));
    read(sockfd, buf, sizeof(buf));
    printf("%s", buf);

    close(sockfd);
    close(listenfd);
    return 0;
}