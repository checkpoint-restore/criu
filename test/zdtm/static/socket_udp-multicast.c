#include "zdtmtst.h"

const char *test_doc = "static test for UDP multicast socket membership\n";
const char *test_author = "Piyush Khobragade\n";

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#define MCAST_GRP "239.0.0.1"
#define PORT 8888
#define MSG "mcast_test"
#define LOCAL_IF "127.0.0.1"

int main(int argc, char **argv)
{
        int sock;
        int loop = 1;
        struct sockaddr_in addr = {0};
        struct sockaddr_in group = {0};
        struct ip_mreq mreq;
        char buf[32];
        int ret;
        struct in_addr local_addr;
        struct timeval tv;

        test_init(argc, argv);

        local_addr.s_addr = inet_addr(LOCAL_IF);

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
                pr_perror("socket");
                return 1;
        }

        // 1. Force loopback delivery
        if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
                pr_perror("IP_MULTICAST_LOOP");
                return 1;
        }

        // 2. Set 2-second timeout on recv() so we don't hang if membership is lost
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
                pr_perror("SO_RCVTIMEO");
                return 1;
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                pr_perror("bind");
                return 1;
        }

        // Join multicast strictly on the loopback interface
        mreq.imr_multiaddr.s_addr = inet_addr(MCAST_GRP);
        mreq.imr_interface = local_addr;
        if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
                pr_perror("IP_ADD_MEMBERSHIP");
                return 1;
        }

        test_daemon();
        test_waitsig();

        // FIX: Force egress traffic strictly through loopback to bypass isolated routing tables
        if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &local_addr, sizeof(local_addr)) < 0) {
                pr_perror("IP_MULTICAST_IF");
                return 1;
        }

        group.sin_family = AF_INET;
        group.sin_port = htons(PORT);
        group.sin_addr.s_addr = inet_addr(MCAST_GRP);

        ret = sendto(sock, MSG, strlen(MSG), 0, (struct sockaddr *)&group, sizeof(group));
        if (ret != strlen(MSG)) {
                fail("sendto failed");
                return 1;
        }

        memset(buf, 0, sizeof(buf));
        ret = recv(sock, buf, sizeof(buf), 0);
        
        if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        fail("Multicast membership lost across restore (recv timed out)");
                } else {
                        pr_perror("recv failed");
                }
                return 1;
        }

        if (ret != strlen(MSG)) {
                fail("recv length mismatch");
                return 1;
        }

        if (memcmp(buf, MSG, strlen(MSG)) != 0) {
                fail("message mismatch");
                return 1;
        }

        pass();
        return 0;
}
