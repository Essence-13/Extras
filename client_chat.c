#include <sys/types.h>

#include <sys/socket.h>

#include <fcntl.h>

#include <netinet/in.h>

#include <stdio.h>

#include <arpa/inet.h>

#include <string.h>


int main() {

    int sfd;

    fd_set rset;

    char buff[1024] = " ";

    struct sockaddr_in server;


    sfd = socket(AF_INET, SOCK_STREAM, 0);


    if (sfd < 0) {

        printf("Socket creation failed.\n");

        return -1;

    }


    bzero(&server, sizeof(struct sockaddr_in));

    server.sin_family = AF_INET;

    server.sin_port = htons(1005);

    inet_aton("172.16.29.110", &server.sin_addr);


    printf("Connect: %d\n", connect(sfd, (struct sockaddr*)&server, sizeof(server)));


    for (;;) {

        FD_ZERO(&rset);

        FD_SET(0, &rset); // 0 represents the standard input (stdin)

        FD_SET(sfd, &rset);


        select(sfd + 1, &rset, NULL, NULL, NULL);


        if (FD_ISSET(0, &rset)) {

            printf("Enter the message:\n");

            scanf("%s", buff);

            write(sfd, buff, strlen(buff));

        }


        if (FD_ISSET(sfd, &rset)) {

            read(sfd, buff, 1024);

            printf("Message received: %s\n", buff);

        }

    }


    close(sfd);


    return 0;

}