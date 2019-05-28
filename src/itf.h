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

#ifndef __CMM_ITF_H
#define __CMM_ITF_H

#include <stdio.h>
#include <libfci.h>
#include <net/ethernet.h>
#include <linux/ip6_tunnel.h>
#include <linux/if_tunnel.h>

#include "rtnl.h"
#include "list.h"

#ifdef LS1043
#define GEM_PORTS 7
#elif defined(COMCERTO_2000) && !defined(LS1012A)
#define GEM_PORTS 3
#elif LS1012A
#define GEM_PORTS 2
#elif LS1088
#define GEM_PORTS 3
#else
#define GEM_PORTS 2
#endif

/* default value for WAN interface is eth0, and LAN interface is eth2 */
#define GEMAC0_PORT	0 //do not change !
#define GEMAC1_PORT	1 //do not change !
#define GEMAC2_PORT	2 //do not change !

struct gemac_port {
	char ifname[IFNAMSIZ];
	char logical_name[IFNAMSIZ];
	int  type;
	int  ifindex;
	int  port_id;
	int  enable;
};

#define GEMAC_PORT_TYPE_LAN	0x0
#define GEMAC_PORT_TYPE_WAN	0x1

#define LO_INTERFACE_NAME	"lo"

#ifdef WIFI_ENABLE
#define WIFI_PORT0	GEM_PORTS //do not change !
#endif

extern struct gemac_port port_table[GEM_PORTS];
static inline int is_wan_port_ifindex(int ifindex)
{
	int ii;

	for (ii = 0; ii < GEM_PORTS; ii++)
		if ((port_table[ii].ifindex == ifindex) && (port_table[ii].type == GEMAC_PORT_TYPE_WAN))
			return 1;

	return 0;
}

static inline int is_wan_port_id(int port_id)
{
	int ii;

	for (ii = 0; ii < GEM_PORTS; ii++)
		if ((port_table[ii].port_id == port_id) && (port_table[ii].type == GEMAC_PORT_TYPE_WAN))
			return 1;
	return 0;
}

static inline void print_all_gemac_ports(char *buf, int buf_len)
{
	int len = 0, ii;

	for (ii = 0; ii < GEM_PORTS; ii++){

		if (!port_table[ii].enable)
			continue;

		len += snprintf(&buf[len], buf_len, "%s|", port_table[ii].ifname);
		buf_len = buf_len > len ? buf_len - len : 0;
	}

	for (ii = 0; ii < GEM_PORTS; ii++) {

		if (!port_table[ii].enable)
			continue;

		len += snprintf(&buf[len], buf_len, "%s|", port_table[ii].logical_name);
		buf_len = buf_len > len ? buf_len - len : 0;
	}

	buf[strlen(buf) - 1] = '\0';
}

static inline int get_port_id(char *name)
{
	int ii;

	for (ii = 0; ii < GEM_PORTS; ii++)
	{
		if (!port_table[ii].enable)
			continue;

		if (!strcmp(name, port_table[ii].ifname) || !strcmp(name, port_table[ii].logical_name))
			return port_table[ii].port_id;
	}

	return -1;
}

static inline int get_port_ifindex(char *name)
{
	int ii;

	for (ii = 0; ii < GEM_PORTS; ii++)
	{
		if (!strcmp(name, port_table[ii].ifname) || !strcmp(name, port_table[ii].logical_name))
			return port_table[ii].ifindex;
	}

	return -1;
}

static inline char *get_port_name(int port_id, char *buf, int buf_size)
{
	int ii;

	buf[0] = '\0';

	for (ii = 0; ii < GEM_PORTS; ii++)
	{
		if (!port_table[ii].enable)
			continue;

		if (port_table[ii].port_id == port_id)
			snprintf(buf, buf_size, "%s",  port_table[ii].ifname);
	}

	return buf;
}

#define ITF_HASH_TABLE_SIZE	64
#define MAX_BRIDGES	64
#define MAX_PORTS	64

#define ITF_BRIDGE		(1 << 0)
#define ITF_VLAN		(1 << 1)
#define ITF_BRIDGED		(1 << 2)
#define ITF_TUNNEL		(1 << 3)
#define ITF_PPPOE_SESSION_UP    (1 << 4)
#define ITF_PPPOE_AUTO_MODE     (1 << 5)
#define ITF_MACVLAN 	(1 << 6)
#ifdef WIFI_ENABLE
#define ITF_WIFI	(1 << 7)
#endif
#define ITF_L2TP	(1 << 8)
#define ITF_LRO		(1 << 9)

#ifndef SAM_LEGACY

#ifndef RTM_NEW4RD
#define RTM_NEW4RD 80 /* If RTM_NEW4RD is not defined we can safely assume that RTM_DEL4RD and RTM_GET4RD will also not be defined */
#define RTM_DEL4RD 81
#define RTM_GET4RD 82
struct ip6_4rd_map_msg {
	__u32 reset;
	__u32 ifindex;
	__be32 prefix;
	__u16 prefixlen;
	struct in6_addr relay_prefix;
	struct in6_addr relay_suffix;
	__u16 relay_prefixlen;
	__u16 relay_suffixlen;
	__u16 psid_offsetlen;
	__u16 eabit_len;
	__u16 entry_num;
};
#endif
#endif

#define LINK_KIND_MACVLAN	"macvlan"
#define LINK_KIND_GRE6		"ip6gretap"

#ifndef SIOCGET6RD
#define SIOCGET6RD	(SIOCDEVPRIVATE + 8)

struct ip_tunnel_6rd {
	struct in6_addr		prefix;
	u_int32_t		relay_prefix;
	u_int16_t		prefixlen;
	u_int16_t		relay_prefixlen;
};
#endif

#ifndef SIOCISETHIPV4TUNNEL
#define SIOCISETHIPV4TUNNEL  (SIOCDEVPRIVATE + 15)
#endif

struct l2tp_itf_info {
	u_int16_t local_tun_id;
	u_int16_t peer_tun_id;
	u_int16_t local_ses_id;
	u_int16_t peer_ses_id;
	u_int16_t options;
	struct socket *sock;
};

struct interface_addr {
	struct list_head list;
	unsigned int address[4];
	unsigned short len;
	int family;
	unsigned char scope;
	unsigned char prefixlen;
};

struct interface {
	struct list_head list;

	/* netlink address information */
	struct list_head addr_list;

	char ifname[IFNAMSIZ];

	/* netlink link information */
	int ifindex;
	unsigned short type;	/* ARPHRD_* */
	char link_kind[16];
	unsigned char macaddr[ETH_ALEN];
	int macaddr_len;
	unsigned ifi_flags;	/* IFF_* flags */
	unsigned int mtu;

	/* cmm information */
	unsigned int itf_flags; /* bit field with ITF_xxx flags */

	int phys_ifindex;	/* physical interface index, if vlan/pppoe */

	u_int16_t session_id; /* session id if pppoe interface */
	int		unit;				/* PPPoE unit number */
	unsigned char dst_macaddr[ETH_ALEN]; /* peer mac address if pppoe interface */

	u_int16_t vlan_id;	/* vlan id if vlan interface */

	int ifindices[MAX_PORTS];	/* list of bridge ports if bridge interface */

	struct ct_route rt;		/* Route information if tunnel interface */

	struct FlowEntry *flow_orig;	/* Flow information for outgoing traffic */
	struct FlowEntry *flow_rep;	/* Flow information for incoming traffic */
	union {
		struct ip6_tnl_parm tunnel_parm6;
		struct ip_tunnel_parm tunnel_parm4;
	};
	struct ip_tunnel_6rd tunnel_parm6rd;

	int tunnel_flags;
	int tunnel_family;
	int tunnel_enabled;

	int count;
	int flags;
#ifdef WIFI_ENABLE
	struct wifi_ff_entry *wifi_if;
#endif
#ifdef SAM_LEGACY
	u_int16_t sam_enable;
#else
	struct list_head mr_list; /* netlink mapping rule information */
#endif
	/* If L2TP interface */
	struct l2tp_itf_info l2tp;
};

struct interface_table {
	pthread_mutex_t lock;
	struct list_head hash[ITF_HASH_TABLE_SIZE];
	FILE *fp;
	int fd;
	struct rtnl_handle rth;
	FCI_CLIENT *fci_handle;
	FCI_CLIENT *fci_key_handle;
};

extern struct interface_table itf_table;
extern int LO_IFINDEX;
struct gemac_port ;

struct interface *__itf_get(int ifindex);
void __itf_put(struct interface *itf);
struct interface *__itf_find(int ifindex);

int itf_table_init(struct interface_table *ctx);
int itf_get_ipaddr(int ifindex, int family, unsigned char scope, unsigned int *ipaddr, unsigned int *target);
int __itf_get_macaddr(struct interface *itf, unsigned char *macaddr);
int itf_get_macaddr(int ifindex, unsigned char *macaddr);
int __itf_get_mtu(int ifindex);
int ____itf_get_name(struct interface *itf, char *ifname, int len);
int __itf_get_name(int ifindex, char *ifname, int len);
int __itf_is_bridge(int ifindex);
int __itf_is_vlan(struct interface *itf);
int __itf_is_macvlan(struct interface *itf);
int __itf_is_pointopoint(struct interface *itf);
int __itf_is_pppoe(struct interface *itf);
int __itf_is_noarp(int ifindex);
int __itf_is_up(struct interface *itf);
int __itf_is_tunnel(struct interface *itf);
int __itf_is_l2tp(struct interface *itf);
int __itf_get_from_bridge_port(int ifindex, int port);
int ____itf_is_programmed(struct interface *itf);
int __itf_is_programmed(int ifindex);
int itf_is_programmed(int ifindex);
 int ____itf_is_4o6_tunnel(struct interface *itf);
int ____itf_is_floating_sit_tunnel(struct interface *itf);
int __itf_is_floating_sit_tunnel(int ifindex);
int itf_name_update(FCI_CLIENT *fci_handle, struct gemac_port *port);
int itf_match_src_ipaddr(int ifindex, int family, unsigned int *ipaddr);

int cmmRtnlLink(const struct sockaddr_nl *who, struct nlmsghdr *nlh, void *arg);
int cmmRtnlIfAddr(const struct sockaddr_nl *who, struct nlmsghdr *nlh, void *arg);

#ifdef WIFI_ENABLE
int __itf_is_wifi_ff_if(struct interface *itf);
int __itf_is_wifi(struct interface *itf);
#else
static inline int __itf_is_wifi(struct interface *itf){ return 0;}
#endif
static inline u_int32_t HASH_ITF(int ifindex)
{
	return ifindex & (ITF_HASH_TABLE_SIZE - 1);
}
#endif /* __CMM_ITF_H */
