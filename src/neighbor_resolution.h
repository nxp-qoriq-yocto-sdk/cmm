/*
*   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
*   Copyright 2016 NXP
*
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*
*/

#ifndef __NEIGHBOR_H__
#define __NEIGHBOR_H__

#include <net/ethernet.h>

#include "jhash.h"

	#define APP_SOLICIT_IPV4_PATH "/proc/sys/net/ipv4/neigh/default/app_solicit"
	#define APP_SOLICIT_IPV4_WAN_PATH "/proc/sys/net/ipv4/neigh/" WAN_INTERFACE_NAME "/app_solicit"
	#define APP_SOLICIT_IPV4_LAN_PATH "/proc/sys/net/ipv4/neigh/" LAN_INTERFACE_NAME "/app_solicit"
	#define APP_SOLICIT_IPV6_PATH "/proc/sys/net/ipv6/neigh/default/app_solicit"
	#define APP_SOLICIT_IPV6_WAN_PATH "/proc/sys/net/ipv6/neigh/" WAN_INTERFACE_NAME "/app_solicit"
	#define APP_SOLICIT_IPV6_LAN_PATH "/proc/sys/net/ipv6/neigh/" LAN_INTERFACE_NAME "/app_solicit"

#ifndef NUD_VALID
	#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
#endif

	#define NEIGHBOR_HASH_TABLE_SIZE	2048

	#define MAX_UCAST_SOLICIT 3
	#define MAX_MCAST_SOLICIT 3
	extern pthread_mutex_t neighMutex;

	extern struct list_head neigh_table[2 * NEIGHBOR_HASH_TABLE_SIZE];
	extern struct list_head neigh_table_by_mac[NEIGHBOR_HASH_TABLE_SIZE];
	extern struct list_head neigh_state_table;

	/*Structure representing  an arp/neighbor entry (internally to cmm)*/
	struct NeighborEntry {
		struct list_head list;
		struct list_head list_by_state;

		int count;						/*Number of time the arp is used*/

		struct list_head list_by_mac;

		unsigned char macAddr[ETH_ALEN];
		unsigned int ipAddr[4];
		unsigned short ipAddrLen;
		unsigned short state;
		int family;
		int ifindex;
		int port;
		int flags;
		int nr_probes;
	};

	struct neighReq {
		struct neighReq *next;
		int family;
		int ifindex;
		int dst_mac_null;
		unsigned int dst_ip[4];
		unsigned char dst_mac[6];
	}; 

	int cmmNeighborSolicitation(int ifindex, unsigned int *dst_ip, unsigned char *dst_mac);

	int cmmArpRequest(int ifindex, unsigned int dst_ip, unsigned char *dst_mac);
	
	void __cmmNeighUpdateAllMacs(int ifindex, unsigned char *macAddr, int port);
	struct NeighborEntry *__cmmNeighFind(int family, const unsigned int *ipAddr, int ifindex);
	void __cmmNeighRemove(struct NeighborEntry *neigh);
	void __cmmNeighPut(struct NeighborEntry *neigh);
	struct NeighborEntry *__cmmNeighAdd(int family, const unsigned int *ipAddr, int ifindex);
	struct NeighborEntry *__cmmNeighGet(int family, const unsigned int *ipAddr, int ifindex);

	int cmmRtnlNeigh(const struct sockaddr_nl *who, struct nlmsghdr *nlh, void *arg);

	int cmmNeighShow(struct cli_def * cli, char *command, char *argv[], int argc);


static inline u_int32_t HASH_NEIGHBOR(int family, const u_int32_t *ipaddr)
{
	u_int32_t key;

	if (family == AF_INET6)
	{
		key = ipaddr[0] ^ ipaddr[1] ^ ipaddr[2] ^ ipaddr[3];

		return (jhash_1word(key, 0x12345678) & (NEIGHBOR_HASH_TABLE_SIZE - 1)) + NEIGHBOR_HASH_TABLE_SIZE;
	}
	else
	{
		key = ipaddr[0];

		return (jhash_1word(key, 0x12345678) & (NEIGHBOR_HASH_TABLE_SIZE - 1));
	}
}

static inline u_int32_t HASH_MAC(const u_int8_t *macaddr)
{
	u_int32_t key;

	key = ((u_int32_t *)macaddr)[0] ^ ((u_int16_t *)macaddr)[2];

	return (jhash_1word(key, 0x12345678) & (NEIGHBOR_HASH_TABLE_SIZE - 1));
}

#endif
