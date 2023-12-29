#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include "compat.h"

#define BOOTP_SIZE (236 + 312)
static uint8_t hwaddr[ETHER_ADDR_LEN];
static struct in_addr dst_addr;
static unsigned char dst_mac[ETHER_ADDR_LEN];
static unsigned int ifindex;


/* Fixed bootp header + 312 for optional */
static struct pkt {
    struct ether_header ethhdr;
    struct ip iphdr;
    struct udphdr udphdr;
    uint32_t bootp[BOOTP_SIZE / sizeof(uint32_t)];
} __attribute__((packed)) pkt;

/* pseudo header for udp calc */
static struct pseudohdr {
    unsigned long source_ip;
    unsigned long dest_ip;
    unsigned char reserved;
    unsigned char protocol;
    unsigned short udp_length;
    struct udphdr udphdr;
    unsigned char bootp[BOOTP_SIZE];
} __attribute__((packed)) pseudohdr;

void get_hw_addr(const char *ifname, unsigned char *hwaddr_in) {
    struct ifreq ifreq;

    memset(&ifreq, 0, sizeof(ifreq));
    strcpy(ifreq.ifr_name, ifname);
    if (ioctl(sock, SIOCGIFHWADDR, &ifreq)) err(1, "SIOCGIFHWADDR");

    memcpy(hwaddr, ifreq.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    memcpy(hwaddr_in, ifreq.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}

void create_timers(int recreate) {    /* timerfd survives a fork, don't need to recreate */
    if (recreate == 0)
        for (int i = 0; i < N_TIMERS; ++i) {
            timers[i] = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC);
            if (timers[i] == -1)
                err(1, "timerfd_create:");
        }
}

/* RFC 1071. */
static uint16_t chksum16(const void *buf, int count) {
    int32_t sum = 0, shift;
    const uint16_t *p = buf;

    while (count > 1) {
        sum += *p++;
        count -= 2;
    }

    if (count > 0)
        sum += *p;

    /*  Fold 32-bit sum to 16 bits */
    if ((shift = sum >> 16))
        sum = (sum & 0xffff) + shift;

    return ~sum;
}

/* open a socket */
void open_socket(const char *ifname) {
    int bcast = 1;

    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
        err(1, "socket:");

    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast)) == -1)
        err(1, "setsockopt broadcast:");

    struct ifreq ifreq;
    memset(&ifreq, 0, sizeof(ifreq));
    strcpy(ifreq.ifr_name, ifname);

    if (ioctl(sock, SIOCGIFINDEX, &ifreq))
        err(1, "SIOCGIFINDEX");
    ifindex = ifreq.ifr_ifindex;
}

void close_socket(void) {    /* We close the socket for performance reasons */
    if (sock != -1) {
        close(sock);
        sock = -1;
    }
}

ssize_t udpsend(void *data, size_t n, int broadcast) {
    if (sock == -1)
        open_socket(ifname);

    memset(&pkt, 0, sizeof(pkt));

    if (broadcast) {
        memset(pkt.ethhdr.ether_dhost, 0xff, ETHER_ADDR_LEN);
        pkt.iphdr.ip_dst.s_addr = INADDR_BROADCAST;
    } else {
        memcpy(&pkt.ethhdr.ether_dhost, dst_mac, ETHER_ADDR_LEN);
        pkt.iphdr.ip_dst = dst_addr;
        pkt.iphdr.ip_src = client;
    }

    memcpy(pkt.ethhdr.ether_shost, hwaddr, ETHER_ADDR_LEN);
    pkt.ethhdr.ether_type = ntohs(ETHERTYPE_IP);

    pkt.iphdr.ip_v = 4;
    pkt.iphdr.ip_hl = 5;
    pkt.iphdr.ip_tos = IPTOS_LOWDELAY;
    pkt.iphdr.ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + n);
    pkt.iphdr.ip_id = 0;
    pkt.iphdr.ip_off = htons(0x4000); /* DF set */
    pkt.iphdr.ip_ttl = 16;
    pkt.iphdr.ip_p = IPPROTO_UDP;
    pkt.iphdr.ip_sum = chksum16(&pkt.iphdr, 20);

    pkt.udphdr.uh_sport = PORT68;
    pkt.udphdr.uh_dport = PORT67;
    pkt.udphdr.uh_ulen = htons(sizeof(struct udphdr) + n);

    memcpy(&pkt.bootp, data, n);

    memset(&pseudohdr, 0, sizeof(pseudohdr));
    pseudohdr.source_ip = pkt.iphdr.ip_src.s_addr;
    pseudohdr.dest_ip = pkt.iphdr.ip_dst.s_addr;
    pseudohdr.protocol = pkt.iphdr.ip_p;
    pseudohdr.udp_length = htons(sizeof(struct udphdr) + n);

    memcpy(&pseudohdr.udphdr, &pkt.udphdr, sizeof(struct udphdr));
    memcpy(&pseudohdr.bootp, data, n);
    int header_len = sizeof(pseudohdr) - BOOTP_SIZE + n;
    pkt.udphdr.uh_sum = chksum16(&pseudohdr, header_len);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_halen = ETHER_ADDR_LEN;
    memcpy(sa.sll_addr, hwaddr, ETHER_ADDR_LEN);
    sa.sll_ifindex = ifindex;

    size_t len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + n;
    ssize_t sent;
    while ((sent = sendto(sock, &pkt, len, 0, (struct sockaddr *) &sa, sizeof(sa))) == -1)
        if (errno != EINTR)
            err(1, "sendto:");

    return sent;
}

ssize_t udprecv(void *data, size_t n) {
    struct pkt recv;
    int r;

    memset(&recv, 0, sizeof(recv));
    while ((r = read(sock, &recv, sizeof(recv))) == -1)
        if (errno != EINTR)
            err(1, "read");

    if (ntohs(recv.ethhdr.ether_type) != ETHERTYPE_IP)
        return -1; // not an IP packet

    if (recv.udphdr.uh_sport != PORT67 || recv.udphdr.uh_dport != PORT68)
        return -1; /* not a dhcp packet */

    r -= sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
    if (r < 236)
        return -1; /* too small to be a dhcp packet */
    if (r > (int) n)
        r = n;

    if (memcmp(recv.bootp + 7, hwaddr, ETHER_ADDR_LEN))
        return -1; /* not our mac */

    dst_addr = recv.iphdr.ip_src;
    memcpy(dst_mac, &recv.ethhdr.ether_shost, ETHER_ADDR_LEN);
    memcpy(data, &recv.bootp, r);

    return r;
}

int random_int() {
    srand(time(NULL)); // Seed the random number generator with current time
    return rand() % 1000000; // Generate a random number between 0 and 999999
}