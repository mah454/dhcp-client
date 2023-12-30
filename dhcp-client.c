#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <err.h>

#include "compat.h"

#define BROADCAST (1 << 7)

struct bootp {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;            // unused
    uint32_t xid;
    uint16_t secs;            // unused
    uint16_t flags;
    struct in_addr ciaddr;
    struct in_addr yiaddr;
    uint32_t siaddr;        // unused
    uint32_t giaddr;        // unused
    uint64_t chaddr;
    uint64_t chaddr2;        // unused
    uint8_t sname[64];        // unused
    uint8_t file[128];        // unused
    // optdata
    // we unroll as much as we can
    uint32_t magic;
    uint8_t type_id;
    uint8_t type_len;
    uint8_t type_data;
    uint8_t cid_id;
    uint8_t cid_len;
    uint8_t optdata[312 - 9];
} __attribute((packed));

_Static_assert(sizeof(struct bootp) == 548, "bootp size");

enum {
    DHCPdiscover = 1,
    DHCPoffer,
    DHCPrequest,
    DHCPdecline,
    DHCPack,
    DHCPnak,
    DHCPrelease,
    DHCPinform,

    Timeout0 = 200,
    Timeout1,
    Timeout2,

    OBpad = 0,
    OBmask = 1,
    OBrouter = 3,
    OBnameserver = 5,
    OBdnsserver = 6,
    OBhostname = 12,
    OBdomainname = 15,
    OBbaddr = 28,
    OBntp = 42,
    ODipaddr = 50, /* 0x32 */
    ODlease = 51,
    ODoverload = 52,
    ODtype = 53, /* 0x35 */
    ODserverid = 54, /* 0x36 */
    ODparams = 55, /* 0x37 */
    ODmessage = 56,
    ODmaxmsg = 57,
    ODrenewaltime = 58,
    ODrebindingtime = 59,
    ODvendorclass = 60,
    ODclientid = 61, /* 0x3d */
    ODtftpserver = 66,
    ODbootfile = 67,
    OBend = 255,
};

static struct bootp bp;

static const unsigned char params[] = {
        OBmask, OBrouter, OBdnsserver, OBdomainname, OBntp,
        ODlease, ODrenewaltime, ODrebindingtime
};

/* One socket to rule them all */
int sock = -1;

/* conf */
static uint64_t hwaddr64;
static char hostname[_POSIX_HOST_NAME_MAX + 1];
static int hostname_len;
const char *ifname ;
static unsigned char cid[24];
static int cid_len;
int timers[N_TIMERS];
/* sav */
struct in_addr client;
struct in_addr server;
static struct in_addr mask;
static struct in_addr router;
static char domainname[64];
static uint32_t renewaltime, rebindingtime, leasetime;

static void
optget(struct bootp *bp, void *data, int opt, int n) {
    unsigned char *p = &bp->type_id;
    unsigned char *top = ((unsigned char *) bp) + sizeof(*bp);
    int code, len;

    while (p < top) {
        code = *p++;
        if (code == OBpad)
            continue;
        if (code == OBend || p == top)
            break;
        len = *p++;
        if (len > top - p)
            break;
        if (code == opt) {
            memcpy(data, p, MIN(len, n));
            break;
        }
        p += len;
    }
}

static unsigned char *
optput(unsigned char *p, int opt, const void *data, size_t len) {
    *p++ = opt;
    *p++ = (unsigned char) len;
    memcpy(p, data, len);

    return p + len;
}

static void
dhcpsend(int type, uint16_t broadcast) {
    struct bootp bootp = {
            .op = 1,    // boot request
            .htype = 1,    // ethernet
            .hlen = ETHER_ADDR_LEN,
            .xid = random_int(),
            .flags = broadcast,
            .chaddr = hwaddr64,
            .magic = MAGIC,
            .type_id = ODtype,
            .type_len = 1,
            .type_data = type,
            .cid_id = ODclientid,
            .cid_len = cid_len,
    };

    memcpy(bootp.optdata, cid, cid_len);
    uint8_t *p = bootp.optdata + cid_len;
    p = optput(p, OBhostname, (unsigned char *) hostname, hostname_len);

    switch (type) {
        case DHCPdiscover:
            break;
        case DHCPrequest:
            p = optput(p, ODipaddr, &client, sizeof(client));
            p = optput(p, ODserverid, &server, sizeof(server));
            p = optput(p, ODparams, params, sizeof(params));
            break;
        case DHCPrelease:
            bootp.ciaddr = client;
            p = optput(p, ODipaddr, &client, sizeof(client));
            p = optput(p, ODserverid, &server, sizeof(server));
            break;
    }
    *p++ = OBend;

    udpsend(&bootp, p - (uint8_t *) &bootp, BROADCAST);
}

static int
dhcprecv(void) {
    unsigned char type;
    struct pollfd pfd[] = {
            {.fd = sock, .events = POLLIN},
            {.fd = timers[0], .events = POLLIN},
            {.fd = timers[1], .events = POLLIN},
            {.fd = timers[2], .events = POLLIN},
    };
    uint64_t n;

    again:
    while (poll(pfd, LEN(pfd), -1) == -1)
        if (errno != EINTR)
            err(1, "poll:");
    if (pfd[0].revents) {
        memset(&bp, 0, sizeof(bp));
        if (udprecv(&bp, sizeof(bp)) == -1)
            /* Not our packet */
            goto again;
        optget(&bp, &type, ODtype, sizeof(type));
        return type;
    }
    if (pfd[1].revents) {
        type = Timeout0;
        read(timers[0], &n, sizeof(n));
    }
    if (pfd[2].revents) {
        type = Timeout1;
        read(timers[1], &n, sizeof(n));
    }
    if (pfd[3].revents) {
        type = Timeout2;
        read(timers[2], &n, sizeof(n));
    }
    return type;
}

static void
settimeout(int n, uint32_t seconds) {
    const struct itimerspec ts = {.it_value.tv_sec = seconds};
    if (timerfd_settime(timers[n], 0, &ts, NULL) < 0)
        err(1, "timerfd_settime:");
}

/* sets timer t to expire halfway to the expiration of timer n, minimum of 60 seconds */
static void
calctimeout(int n, int t) {
    struct itimerspec ts;

    if (timerfd_gettime(timers[n], &ts) < 0)
        err(1, "timerfd_gettime:");
    ts.it_value.tv_nsec /= 2;
    if (ts.it_value.tv_sec % 2)
        ts.it_value.tv_nsec += 500000000;
    ts.it_value.tv_sec /= 2;
    if (ts.it_value.tv_sec < 60) {
        ts.it_value.tv_sec = 60;
        ts.it_value.tv_nsec = 0;
    }
    if (timerfd_settime(timers[t], 0, &ts, NULL) < 0)
        err(1, "timerfd_settime:");
}

static void
parse_reply(void) {
    optget(&bp, &mask, OBmask, sizeof(mask));
    optget(&bp, &router, OBrouter, sizeof(router));
    optget(&bp, domainname, OBdomainname, sizeof(domainname));
    optget(&bp, &leasetime, ODlease, sizeof(leasetime));
    leasetime = ntohl(leasetime);

    /* Renew and rebind times are optional. It is faster to just
     * calculate the times. Assumes: lease > 4s and < ~20 years.
     */
    renewaltime = leasetime / 2;
    rebindingtime = leasetime * 7 / 8;
}

static void run() {
    uint32_t t;
    goto Requesting;
    Init:
    printf("Init\n");
    client.s_addr = 0;
    server.s_addr = 0;
    dhcpsend(DHCPdiscover, BROADCAST);
    settimeout(0, 1);
    goto Selecting;
    Selecting:
    printf("Selecting\n");
    for (;;) {
        switch (dhcprecv()) {
            case DHCPoffer:
                client = bp.yiaddr;
                optget(&bp, &server, ODserverid, sizeof(server));
                goto Requesting;
            case Timeout0:
                goto Init;
        }
    }
    Requesting:
    printf("Requesting\n");
    for (t = 4; t <= 64; t *= 2) {
        dhcpsend(DHCPrequest, BROADCAST);
        settimeout(0, t);
        for (;;) {
            switch (dhcprecv()) {
                case DHCPack:
                    goto Bound;
                case DHCPnak:
                    goto Init;
                case Timeout0:
                    break;
                default:
                    continue;
            }
            break;
        }
    }
    /* no response from DHCPREQUEST after several attempts, go to INIT */
    goto Init;
    Bound:
    printf("Bound\n");
    close_socket(); /* currently raw sockets only */
    parse_reply();

    char *ip_str = inet_ntoa(client);
    printf("Client: %s\n", ip_str);

    ip_str = inet_ntoa(server);
    printf("Server: %s\n", ip_str);

    ip_str = inet_ntoa(mask);
    printf("Mask: %s\n", ip_str);

    if (fork()) exit(0);

    Renewed:
    printf("Renewed\n");
    settimeout(0, renewaltime);
    settimeout(1, rebindingtime);
    settimeout(2, leasetime);
    for (;;) {
        switch (dhcprecv()) {
            case Timeout0: /* t1 elapsed */
                goto Renewing;
            case Timeout1: /* t2 elapsed */
                goto Rebinding;
            case Timeout2: /* lease expired */
                goto Init;
        }
    }
    Renewing:
    printf("Renewing\n");
    dhcpsend(DHCPrequest, 0);
    calctimeout(1, 0);
    for (;;) {
        switch (dhcprecv()) {
            case DHCPack:
                parse_reply();
                close_socket(); /* currently raw sockets only */
                goto Renewed;
            case Timeout0: /* resend request */
                goto Renewing;
            case Timeout1: /* t2 elapsed */
                goto Rebinding;
            case Timeout2:
            case DHCPnak:
                goto Init;
        }
    }
    Rebinding:
    printf("Rebinding\n");
    calctimeout(2, 0);
    dhcpsend(DHCPrequest, BROADCAST);
    for (;;) {
        switch (dhcprecv()) {
            case DHCPack:
                goto Bound;
            case Timeout0: /* resend request */
                goto Rebinding;
            case Timeout2: /* lease expired */
            case DHCPnak:
                goto Init;
        }
    }
}

static void
cleanexit(int unused) {
    (void) unused;
    dhcpsend(DHCPrelease, 0);
    _exit(0);
}

int discover_dhcp_ip(const char* interface_name) {
    ifname = interface_name; /* interface name */
    if (strlen(ifname) >= IF_NAMESIZE) {
        fprintf(stderr, "Interface %s too big\n", ifname);
        exit(1);
    }

    signal(SIGTERM, cleanexit);

    if (gethostname(hostname, sizeof(hostname)) == -1)
        err(1, "gethostname:");
    hostname_len = strlen(hostname);

    open_socket(ifname);

    unsigned char hwaddr[ETHER_ADDR_LEN];
    get_hw_addr(ifname, hwaddr);
    memcpy(&hwaddr64, hwaddr, sizeof(hwaddr));

    if (cid_len == 0) {
        cid[0] = 1;
        memcpy(cid + 1, hwaddr, ETHER_ADDR_LEN);
        cid_len = ETHER_ADDR_LEN + 1;
    }

    create_timers(0);

    run();

    return 0;
}

int main() {
    discover_dhcp_ip("wlan0");
}
