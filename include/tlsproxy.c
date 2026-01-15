#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char *argv[])
{
        short PORT;
        char buf[BUFSIZ];
        int exitcode = EXIT_FAILURE;
        struct sockaddr_in addr = { 0 };
        int sockfd = -1, connfd = -1, yes = 1, rc;
        if (argc != 2) {
                fprintf(stderr, "usage:␣%s␣PORT\n", argv[0]);
                goto done;
        }
        errno = 0;
        PORT = strtol(argv[1], NULL, 10);
        if (errno != 0 || PORT == 0) {
                fprintf(stderr, "usage:␣%s␣PORT\n", argv[0]);
                goto done;
        }
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (-1 == sockfd) {
                perror("error␣creating␣listening␣socket");
                goto done;
        }
        rc = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if (-1 == rc) {
                perror("error␣setting␣socket␣option");
                goto done;
        }
        addr.sin_port = htons(PORT);
        addr.sin_family = PF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        rc = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
        if (-1 == rc) {
                perror("error␣binding␣listening␣socket␣to␣port");
                goto done;
        }
        rc = listen(sockfd, 0);
        if (-1 == rc) {
                perror("failed␣to␣listen");
                goto done;
        }
        connfd = accept(sockfd, NULL, NULL);
        if (-1 == connfd) {
                perror("failed␣to␣accept");
                goto done;
        }
        for (;;) {
                ssize_t size = recv(connfd, buf, sizeof(buf), 0);
                switch (size) {
                        case 0:
                                exitcode = EXIT_SUCCESS;
                                goto done;
                        case -1:
                                perror("error␣writing");
                                goto done;
                        default:
                                write(STDOUT_FILENO, buf, size);
                }
        }
done:
        if (-1 != sockfd) {
                close(sockfd);
        }
        if (-1 != connfd) {
                close(connfd);
        }
        exit(exitcode);
}
