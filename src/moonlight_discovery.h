/*
 * moonlight_discovery.h
 *
 * LAN autodiscovery of Sunshine/GameStream servers via mDNS
 * (service type "_nvstream._tcp.local").
 *
 * Designed for PS3-Moonlight (PSL1GHT / sys_net). Has no dependency on
 * Tiny3D or any rendering subsystem: pure networking, to be called from
 * the menu before showing the host list or the manual IP fallback.
 */

#ifndef MOONLIGHT_DISCOVERY_H
#define MOONLIGHT_DISCOVERY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MLD_MAX_HOSTS    8    /* maximum number of hosts kept in the list */
#define MLD_NAME_MAX     64
#define MLD_IP_STR_MAX   16

/*
 * Note: port is not included. As in ProsperoLight, mDNS only tells us
 * "who is there" (name + IP, the latter taken from the UDP source address
 * of the response packet, not from an A record). The default GameStream
 * port is used by the existing pairing code.
 */
typedef struct {
    char name[MLD_NAME_MAX];      /* announced hostname (e.g. "DESKTOP-PC") */
    char address[MLD_IP_STR_MAX]; /* IPv4 in dotted notation "192.168.1.50" */
} mld_host_t;

/*
 * Performs a blocking mDNS scan for approximately 750 ms (5 rounds x 150 ms
 * via SO_RCVTIMEO). Fills 'out_hosts' (capacity 'max_hosts') with discovered
 * hosts and returns the number found (0 = none, <0 = socket error).
 * The timeout_ms parameter is ignored (fixed timing derived from ProsperoLight).
 *
 * Assumes the network is already up (netCtlGetState == NET_CTL_STATE_IPObtained).
 */
int mld_scan(mld_host_t *out_hosts, int max_hosts, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* MOONLIGHT_DISCOVERY_H */
