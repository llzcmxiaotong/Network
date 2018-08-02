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
#include <netpacket/packet.h>

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
    unsigned char targetIp[4];

    void print()
    {
        printf("------------ether header----------\n");
        printf("destMac: %02x:%02x:%02x:%02x:%02x:%02x\n", dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5]);
        printf("srcMac: %02x:%02x:%02x:%02x:%02x:%02x\n", srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5]);
        printf("arpType: %4x\n", htons(arpType));
        printf("------------ether header end------\n");

        printf("hwType: %4x\n", htons(hwType));
        printf("ptType: %4x\n", htons(ptType));
        printf("hwSize: %d\n", hwSize);
        printf("ptSize: %d\n", ptSize);
        printf("opt: %x\n", htons(opt));
        printf("senderMac: %02x:%02x:%02x:%02x:%02x:%02x\n", senderMac[0], senderMac[1], senderMac[2], senderMac[3], senderMac[4], senderMac[5]);
        in_addr addr;
        addr.s_addr = senderIp;
        printf("senderIp: %ux, src: %s\n", senderIp, inet_ntoa(addr));
        printf("targetMac: %02x:%02x:%02x:%02x:%02x:%02x\n", targetMac[0], targetMac[1], targetMac[2], targetMac[3], targetMac[4], targetMac[5]);
        // addr.s_addr = targetIp;
        memcpy(&addr.s_addr, &targetIp, 4);
        printf("targetIp: %ux, src: %s\n", targetIp, inet_ntoa(addr));
    }
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
    struct sockaddr_ll addr;
    struct argMsg arp;

    printf("targetIp:%d, srcIp: %d, interface:%s", targetIp, srcIp, interface);

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
    addr.sll_family = PF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_hatype = ARPHRD_ETHER;
    addr.sll_halen = ETH_ALEN;
    addr.sll_ifindex = 2;
    // strncpy(addr.sll_addr, (char*) arp.dstMac, 6);

    /*addr.sll_ifindex  = 2;
    addr.sll_family   = PF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);*/

    // strncpy(addr.sa_data, interface, strlen(interface));

    arp.print();

    printf("sizeof(addr): %d, sizeof(sockaddr_in): %d\n", sizeof(addr), sizeof(sockaddr_in));
    printf("sizeof(arp):%d\n", sizeof(arp));
    int count = 0;
    if ((count = sendto(fd, &arp, sizeof(arp), 0, (struct sockaddr*)&addr, sizeof(addr))) < 0)
    {
        perror("sendto fail\n");
        printf("sendto fail\n");
    }

    printf("send count: %d\n", count);

ret:
    close(fd);

    return rv;
}

int main()
{
    unsigned int test_ip = inet_addr("192.168.9.1");
    char interface[] = "ens33";
    unsigned int ip;
    unsigned char mac[6] = {0};
    read_interface(interface, NULL, &ip, mac);

    printf("ip:%0x\n", ip, mac);
    printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);


    while (true)
    {
        printf("send arp\n");
        sendArp(test_ip, ip, mac, interface);
        sleep(1);
    }


    return 0;
}
