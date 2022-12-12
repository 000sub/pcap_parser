#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/msg.h> 
#include <sys/ipc.h>

#define PORT_NUM 8201
#define CLI_PORT 8202
#define LISTEN_QLEN 3

int main(int argc, char** argv){
    int listenfd, connfd, sockfd;
    int client_idx = 1;
    int fd[2];
    char buf[1024], tokens[1024];
    struct sockaddr_in cliaddr, servaddr, sktaddr;
    socklen_t clilen;
    pid_t childpid;

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

    if (listen(listenfd, LISTEN_QLEN) == -1){
        printf("listen error.\n");
        close(listenfd);
        exit(1);
    }

    memset(tokens, 0x00, sizeof(tokens));
    printf("Server running, wating for connections.\n");

    while (client_idx < 6){
        clilen = sizeof(cliaddr);
        connfd = accept(listenfd, (struct sockaddr*) &cliaddr, &clilen);

        printf("%s\n","Received request...");

        //pipe create
        if (pipe(fd) < 0){
            printf("pipe error.\n");
            exit(1);
        }

        if ( (childpid = fork ()) == 0 ) {//if 0, it’s child process

            printf("Child created for dealing with client %d requests", client_idx);

            //close listening socket
            close (listenfd);

            memset(buf, 0x00, sizeof(buf));

            while ( recv(connfd, buf, 1024,0) > 0){
                printf("reading data...\n");

                printf("%s", buf);
                write(fd[1], buf, sizeof(buf));
                printf("client %d connection ended.\n", client_idx);
            }

            close(connfd);
            exit(0);
        }

        sleep(2);

        read(fd[0], buf, sizeof(buf));
        memcpy(tokens+((strlen(buf) - 1)*(client_idx - 1)), buf, strlen(buf)-1);
        tokens[strlen(tokens)-1] = ',';

        //close socket of the server
        close(connfd);
        client_idx++;
    } 

    //create TCP socket to send tokens
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        printf("TCP socket creating error.\n");
        exit(1);
    }

    sktaddr.sin_family = AF_INET;
    if (inet_pton(AF_INET, "127.0.0.1", &sktaddr.sin_addr) != 1){
        printf("inet_pton call error.\n");
        exit(1);
    }
    sktaddr.sin_port = htons(CLI_PORT);
    if (connect(sockfd, (struct sockaddr*)&sktaddr, sizeof(sktaddr)) == -1){
        printf("server connection error.\n");
        exit(1);
    }

    write(sockfd, tokens, sizeof(tokens)-1);


    printf("server closed.\n");
    close(listenfd);
    close(sockfd);

    return 0;
}
