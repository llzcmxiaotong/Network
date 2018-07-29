#include <iostream>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

enum {
    ARP_MSG_SIZE = 0x2a
} ;

char * strncpy_IFNAMSIZ( char * dst, const char * src)
{
# ifndef IFNAMSIZ
        enum { IFNAMSIZ = 16 } ;
# endif
            return strncpy ( dst, src, IFNAMSIZ) ;
}

struct argMsg
{
    // 数据链路层的数据
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short arpType;

    // Arp的数据结构
    unsigned short hwType; // 硬件类型
    unsigned short ptType; // 协议类型
    unsigned char hwSize; //硬件地址长度, mac地址长度
    unsigned char ptSize; // 协议地址长度,即ip的长度
    unsigned short opt; //ARP数据包的功能，1表示请求，2表示相应
    unsigned char senderMac[6];
    unsigned int senderIp;
    unsigned char targetMac[6];
    unsigned int targetIp;
} ARPMsg;

char * safe_strncpy( char * dst, const char * src, size_t size)
{
    if ( ! size) return dst;
    dst[ - - size] = '/0' ;
    return strncpy ( dst, src, size) ;
}

const int const_int_1 = 1;
int setsockopt_broadcast(int fd)
{
    return setsockopt(fd, SOL_SOCKET, SO_BROADCAST, & const_int_1, sizeof(const_int_1)) ;
}

int read_interface(const char* interface, int* ifindex, unsigned int*addr, unsigned char* arp)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *our_ip;

    memset(&ifr, 0, sizeof(ifr));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface);
    if (addr)
    {
        if (ioctl(fd, SIOCGIFADDR, &ifr) != 0)
        {
            perror("ioctl");
            close(fd);
            return -1;
        }

        our_ip = (struct sockaddr_in*) &ifr.ifr_addr;
        *addr = our_ip->sin_addr.s_addr;
        printf("ip of %s=%s\n", interface, inet_ntoa(our_ip->sin_addr));
    }

    if (ifindex)
    {
        if (ioctl(fd, SIOCGIFINDEX, &ifr) != 0)
        {
            close(fd);
            return -1;
        }
        printf("adapter index %d\n", ifr.ifr_ifindex);
        *ifindex = ifr.ifr_ifindex;
    }

    if (arp)
    {
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0)
        {
            close(fd);
            return -1;
        }

        memcpy(arp, ifr.ifr_hwaddr.sa_data, 6);
        printf("adapter hardware address %02x:%02x:%02x:%02x:%02x:%02x\n", arp[0], arp[1], arp[2], arp[3], arp[4], arp[5]);
    }
    close(fd);
    return 0;
}

int sendArp(unsigned int targetIp, unsigned int srcIp, unsigned char* srcMac, const char* interface)
{
    int timeout_ms;
    int fd;
    int rv = 1;
    struct sockaddr addr;
    struct argMsg arp;

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0)
    {
        perror("socket");
        return -1;
    }

    if (-1 == setsockopt_broadcast(fd))
    {
        perror("cannot enable broadcast on packet socket");
        close(fd);
        return -1;
    }

    memset(&arp, 0, sizeof(arp));
    memset(arp.dstMac, 0xff, 6);
    memcpy(arp.srcMac, srcMac, 6);
    arp.arpType = htons(ETH_P_ARP);

    arp.hwType = htons(ARPHRD_ETHER);
    arp.ptType = htons(ETH_P_IP);
    arp.hwSize = 6;
    arp.ptSize = 4;
    arp.opt = htons(ARPOP_REQUEST);
    memcpy(arp.senderMac, srcMac, 6);
    memcpy(&arp.senderIp, &srcIp, 4);
    memcpy(&arp.targetIp, &targetIp, 4);

    memset(&addr, 0, sizeof(addr));
    safe_strncpy(addr.sa_data, interface, sizeof(addr.sa_data));

    int count = 0;
    if ((count = sendto(fd, &arp, sizeof(arp), 0, &addr, sizeof(addr))) < 0)
    {
        perror("sendto fail");
        printf("sendto fail");
    }

    printf("send count: %d\n", count);

ret:
    close(fd);

    return rv;
}

int main()
{
    unsigned int test_ip = inet_addr("192.168.9.2");
    char interface[] = "ens33";
    unsigned int ip;
    unsigned char mac[6] = {0};
    read_interface(interface, NULL, &ip, mac);

    printf("ip:%0x", ip);

    while (true)
    {
        printf("send arp");
        sendArp(test_ip, ip, mac, interface);
        sleep(1);
    }

    return 0;
}
