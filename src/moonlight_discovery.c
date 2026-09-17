/*
 * moonlight_discovery.c
 *
 * LAN autodiscovery of Sunshine servers via mDNS, for PS3-Moonlight
 * (PSL1GHT, BSD sockets over native sys_net/LV2 syscalls -- not lwIP).
 *
 * Logic derived from ProsperoLight (src/moonlight_discovery.cpp,
 * blackbearreloaded/ProsperoLight, GPL-3.0-or-later), rewritten for the
 * socket() / sendto() / recvfrom() / setsockopt() APIs exposed by PSL1GHT
 * instead of the proprietary sceNet* calls of the PS5 Payload SDK.
 * Key difference from earlier versions: the host IP is NOT extracted from
 * an A record in the mDNS payload, but from the source address of the UDP
 * response packet -- the same approach used by ProsperoLight, and more
 * robust because it avoids having to match A records to PTR/SRV records
 * across different hosts.
 *
 * NOTE: SO_RCVTIMEO (via setsockopt) is used for receive timeouts instead
 * of select(). On this PSL1GHT SDK (direct sys_net/LV2 syscalls), select()
 * with a timeout is NOT honoured and blocks indefinitely even with an
 * explicit timeval -- a bug confirmed on real hardware, not just theoretical.
 * SO_RCVTIMEO works correctly and is used throughout.
 */

#include "moonlight_discovery.h"

#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* struct timeval is not exposed globally in this PSL1GHT SDK: it is only
 * declared inside the sysNetSelect prototype in sys/socket.h, making it
 * invisible to external code. We define it explicitly -- the layout is
 * identical to the standard and the kernel accepts it correctly
 * (verified: SO_RCVTIMEO with this struct works on real hardware). */
struct timeval {
    long tv_sec;
    long tv_usec;
};

#define MDNS_ADDR        "224.0.0.251"
#define MDNS_PORT        5353
#define MDNS_SERVICE     "_nvstream._tcp.local"
#define MDNS_WAIT_US     150000  /* same step as ProsperoLight: 150 ms */
#define MDNS_WAIT_ROUNDS 5       /* 5 rounds = ~750 ms total listen time */

#define DNS_HEADER_SIZE 12u
#define DNS_TYPE_PTR    12u

/* Pre-built mDNS PTR query for "_nvstream._tcp.local", with the
 * "unicast-response desired" bit set in QCLASS (0x8001), matching
 * ProsperoLight. ID=0, flags=0, QDCOUNT=1, ANCOUNT/NSCOUNT/ARCOUNT=0. */
static const uint8_t mld_query[] = {
    0x00, 0x00,                         /* ID */
    0x00, 0x00,                         /* flags */
    0x00, 0x01,                         /* QDCOUNT = 1 */
    0x00, 0x00,                         /* ANCOUNT */
    0x00, 0x00,                         /* NSCOUNT */
    0x00, 0x00,                         /* ARCOUNT */
    0x09, '_','n','v','s','t','r','e','a','m',
    0x04, '_','t','c','p',
    0x05, 'l','o','c','a','l',
    0x00,                               /* end of name */
    0x00, 0x0c,                         /* QTYPE = PTR */
    0x80, 0x01                          /* QCLASS = IN | unicast-response bit */
};

static uint16_t mld_read_u16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static int mld_ascii_equal_ci(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + ('a' - 'A'));
        if (ca != cb) return 0;
    }
    return *a == *b;
}

/* Reads a DNS name starting at '*cursor', following compression pointers
 * (0xC0xx) as needed. Updates '*cursor' to the position immediately after
 * the name in the ORIGINAL stream. Returns 1 on success, 0 on error. */
static int mld_read_name(const uint8_t *pkt, size_t len, size_t *cursor,
                          char *out, size_t out_size)
{
    size_t pos = *cursor;
    size_t return_pos = 0;
    size_t written = 0;
    unsigned jumps = 0;

    if (out_size == 0)
        return 0;

    while (pos < len && jumps <= len) {
        uint8_t label_len = pkt[pos++];

        if (label_len == 0) {
            if (!return_pos) return_pos = pos;
            out[written] = '\0';
            *cursor = return_pos;
            return 1;
        }

        if ((label_len & 0xc0u) == 0xc0u) {
            if (pos >= len) return 0;
            uint16_t ptr = (uint16_t)(((label_len & 0x3fu) << 8) | pkt[pos++]);
            if (ptr >= len) return 0;
            if (!return_pos) return_pos = pos;
            pos = ptr;
            if (++jumps > 16) return 0; /* guard against infinite loops */
            continue;
        }

        if ((label_len & 0xc0u) != 0 || pos + label_len > len)
            return 0;

        if (written && written + 1 < out_size)
            out[written++] = '.';
        while (label_len--) {
            if (written + 1 < out_size)
                out[written++] = (char)pkt[pos];
            pos++;
        }
    }
    return 0;
}

/* Parses a response packet and, if it contains a PTR record for
 * "_nvstream._tcp.local", writes the short hostname (truncated at the
 * first '.') into 'name'. Returns 1 on success, 0 if no match. */
static int mld_response_name(const uint8_t *pkt, size_t len, char name[MLD_NAME_MAX])
{
    char owner[128];
    char target[128];
    size_t cursor = DNS_HEADER_SIZE;
    uint32_t records;
    uint16_t questions;

    if (len < DNS_HEADER_SIZE)
        return 0;
    if (!(mld_read_u16(pkt + 2) & 0x8000u)) /* QR bit: must be a response */
        return 0;

    questions = mld_read_u16(pkt + 4);
    records = (uint32_t)mld_read_u16(pkt + 6)
            + mld_read_u16(pkt + 8)
            + mld_read_u16(pkt + 10);

    for (uint16_t i = 0; i < questions; i++) {
        if (!mld_read_name(pkt, len, &cursor, owner, sizeof(owner)) || cursor + 4 > len)
            return 0;
        cursor += 4;
    }

    for (uint32_t i = 0; i < records; i++) {
        if (!mld_read_name(pkt, len, &cursor, owner, sizeof(owner)) || cursor + 10 > len)
            return 0;

        uint16_t type = mld_read_u16(pkt + cursor);
        uint16_t data_len = mld_read_u16(pkt + cursor + 8);
        cursor += 10;
        if (cursor + data_len > len)
            return 0;

        if (type == DNS_TYPE_PTR && mld_ascii_equal_ci(owner, MDNS_SERVICE)) {
            size_t data_cursor = cursor;
            if (!mld_read_name(pkt, len, &data_cursor, target, sizeof(target)))
                return 0;
            char *dot = strchr(target, '.');
            if (dot) *dot = '\0';
            snprintf(name, MLD_NAME_MAX, "%s", target[0] ? target : "Sunshine PC");
            return 1;
        }
        cursor += data_len;
    }
    return 0;
}

static int mld_add_host(mld_host_t *hosts, int *count, int capacity,
                         const struct sockaddr_in *source, const char *name)
{
    char address[MLD_IP_STR_MAX];
    snprintf(address, sizeof(address), "%s", inet_ntoa(source->sin_addr));

    for (int i = 0; i < *count; i++)
        if (strcmp(hosts[i].address, address) == 0)
            return 0; /* host already present, skip duplicate */

    if (*count >= capacity)
        return 0;

    snprintf(hosts[*count].address, sizeof(hosts[*count].address), "%s", address);
    snprintf(hosts[*count].name, sizeof(hosts[*count].name), "%s",
             (name && name[0]) ? name : "Sunshine PC");
    (*count)++;
    return 1;
}

int mld_scan(mld_host_t *out_hosts, int max_hosts, int timeout_ms)
{
    (void)timeout_ms; /* fixed timing used instead: 5 x 150 ms, as in ProsperoLight */

    if (!out_hosts || max_hosts <= 0)
        return -1;
    memset(out_hosts, 0, sizeof(*out_hosts) * (size_t)max_hosts);

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
        return -1;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(MDNS_PORT);

    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        close(sock);
        return -1;
    }

    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        close(sock);
        return -1;
    }

    /* Per-socket receive timeout -- see the note at the top of this file
     * for why select() is not used here. */
    struct timeval rcv_timeout;
    rcv_timeout.tv_sec = 0;
    rcv_timeout.tv_usec = MDNS_WAIT_US;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof(rcv_timeout)) < 0) {
        setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
        close(sock);
        return -1;
    }

    struct sockaddr_in mdns_addr;
    memset(&mdns_addr, 0, sizeof(mdns_addr));
    mdns_addr.sin_family = AF_INET;
    mdns_addr.sin_addr.s_addr = inet_addr(MDNS_ADDR);
    mdns_addr.sin_port = htons(MDNS_PORT);

    sendto(sock, mld_query, sizeof(mld_query), 0,
           (struct sockaddr *)&mdns_addr, sizeof(mdns_addr));

    int count = 0;

    for (int round = 0; round < MDNS_WAIT_ROUNDS; round++) {
        uint8_t packet[1500];
        struct sockaddr_in source;
        socklen_t source_len = sizeof(source);

        int received = recvfrom(sock, packet, sizeof(packet), 0,
                                 (struct sockaddr *)&source, &source_len);
        if (received > 0) {
            char name[MLD_NAME_MAX];
            if (mld_response_name(packet, (size_t)received, name))
                mld_add_host(out_hosts, &count, max_hosts, &source, name);

            if (count >= max_hosts)
                break;
        }
        /* received <= 0: timeout elapsed (no packet this round) or error --
         * in both cases move on to the next round. */
    }

    setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    close(sock);
    return count;
}
