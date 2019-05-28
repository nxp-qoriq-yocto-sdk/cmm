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

#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

	#include <stdio.h>
	#include <errno.h>
	#include <stdlib.h>
	#include "cmm.h"
	#include "jhash.h"
	#include "list.h"
	#include "neighbor_resolution.h"
	#include "route_cache.h"

	#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

	/******************************
	 * Structures
	 *
	 ******************************/
	#define MAX_CT_ID 8

	struct ctTable
	{
		struct list_head list;

		struct list_head list_by_rep;

		struct list_head list_by_orig_route;

		struct list_head list_by_rep_route;

		struct list_head list_by_orig_tunnel_route;

		struct list_head list_by_rep_tunnel_route;

		struct nf_conntrack * ct;

		struct ct_route		orig;
		struct FlowEntry	*fEntryOrigOut;
		struct FlowEntry	*fEntryOrigFwd;

		struct ct_route		rep;
		struct FlowEntry	*fEntryRepOut;
		struct FlowEntry	*fEntryRepFwd;

		struct ct_route		orig_tunnel;

		struct ct_route		rep_tunnel;
		
                int timeout;
		time_t tlast;

		int family;

		int dir;

		int fpp_dir;

		int flags;

		int dir_filter;

		u_int32_t ids[MAX_CT_ID];

		int n_id;
	};

	struct conntrack_stats
	{
		int current;
		unsigned long long created;
		unsigned long long removed;
		unsigned long long destroyed;
	};

	/******************************
	 * Defines
	 *
	 ******************************/

	#define CONNTRACK_HASH_TABLE_SIZE 16384			/* must be power of 2 */

	#define CT_KERNEL_TIMEOUT_PERMANENT          1000

	#define CONNTRACK_MAX		65536		/* hard limit on the number of conntracks allowed in cmm,
							   used to avoid consuming too much memory. Should be higher
							   than or equal to the maximum kernel conntracks configured through
							   "/proc/sys/net/nf_conntrack_max" */

	#define TCP_BE_LIBERAL_PATH "/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal"
	
	#define ORIGINATOR		(1 << 0)
	#define REPLIER			(1 << 1)

	#define FLOWFLAG_FLOATING_TUNNEL	(1 << 0)
	#define FLOWFLAG_IGNORE_NEIGH		(1 << 1)
	#define FLOWFLAG_SOCKET_ROUTE		(1 << 2)
	#define FLOWFLAG_LOCAL			(1 << 3)
	#define FLOWFLAG_SA_ROUTE		(1 << 4)

	extern struct list_head ct_table[CONNTRACK_HASH_TABLE_SIZE];
	extern struct list_head ct_table_by_rep[CONNTRACK_HASH_TABLE_SIZE];
	extern struct list_head ct_table_by_orig_route[2 * ROUTE_HASH_TABLE_SIZE];
	extern struct list_head ct_table_by_rep_route[2 * ROUTE_HASH_TABLE_SIZE];
	extern struct list_head ct_table_by_orig_tunnel_route[2 * ROUTE_HASH_TABLE_SIZE];
	extern struct list_head ct_table_by_rep_tunnel_route[2 * ROUTE_HASH_TABLE_SIZE];
	
	extern pthread_mutex_t ctMutex;

	extern struct conntrack_stats ct_stats;

	struct cmm_ct;

	int cmmCtInit(struct cmm_ct *ctx);
	void cmmCtExit(struct cmm_ct *ctx);
	int __cmmRouteRegister(struct ct_route *rt, struct flow *flow, const char *dir);
	int ____cmmCtRegister(FCI_CLIENT *fci_handle, struct ctTable *ctEntry);
	void __cmmCtUpdateWithRoute(FCI_CLIENT *fci_handle, struct RtEntry *route);
	int cmmCtNetlinkRemove(struct nfct_handle * handler, struct nf_conntrack *ct);
	int cmmCtHandle(FCI_CLIENT *fci_handle, int function_code, u_int8_t *cmd_buf, u_int16_t cmd_len, u_int16_t *res_buf, u_int16_t *res_len);

	int cmmCtShow(struct cli_def * cli, char *command, char *argv[], int argc);
	int cmmFlowLocalShow(struct cli_def * cli, char *command, char *argv[], int argc);

	struct ctTable *__cmmCtFind(struct nf_conntrack *ctTemp);
	void __cmmNeighDeregister(FCI_CLIENT *fci_handle, struct NeighborEntry *neigh, const char *dir);
	void __cmmRouteDeregister(FCI_CLIENT *fci_handle, struct ct_route *rt, const char *dir);
	void ____cmmRouteDeregister(struct RtEntry *route, const char *dir);
	void __cmmFPPRouteDeregister(FCI_CLIENT *fci_handle, struct fpp_rt *fpp_route, const char *dir);
	void __cmmCheckFPPRouteIdUpdate(struct ct_route *rt, int *flags);
	void __cmmCtRemove(struct ctTable *ctEntry);
	int ____cmmCtDeregister(FCI_CLIENT *fci_handle, FCI_CLIENT *fci_key_handle, struct ctTable *ctEntry);
	struct ctTable *__cmmCtFindFromFlow(int family, unsigned int *saddr, unsigned int *daddr, unsigned short sport, unsigned short dport, unsigned char proto, char *orig, int local);
	struct ctTable *__cmmCtFindLocalCtFromFlow(struct flow *flow);

/*Hash calculation*/
static __inline u_int32_t HASH_CT(int family, const u_int32_t *Saddr, const u_int32_t *Daddr, u_int16_t Sport, u_int16_t Dport, u_int16_t Proto)
{
	unsigned int a, b;

	if (family == AF_INET)
	{
		a = jhash((void *)Saddr, 4, (Proto << 16) | Proto);
		b = jhash((void *)Daddr, 4, (Sport << 16) | Dport);
	}
	else
	{
        	a = jhash((void *)Saddr, 16, (Proto << 16) | Proto);
        	b = jhash((void *)Daddr, 16, (Sport << 16) | Dport);
	}

	return jhash_2words(a, b, 0x48375934) % CONNTRACK_HASH_TABLE_SIZE;
}

#ifdef C2000_DPI

#define DPI_UNKNOWN_CMD     0
#define DPI_ENABLE_CMD      1

int cmmDPIFlagSetProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
int cmmDPIEnableShow(struct cli_def * cli, char *command, char *argv[], int argc);
int cmmDPIFlagProcessClientCmd(u_int8_t *cmd_buf, u_int16_t *res_buf, u_int16_t *res_len);

#endif /*C2000_DPI*/

#ifdef LS1012A
#define  CONFIG_IPSEC_PASSTHRU 1
#endif


#ifdef CONFIG_IPSEC_PASSTHRU
/**
 *  FIXME : Below macro is origianlly written for local protocol support. And we are using same Macro
 *  for GRE/ESP/AH pass through also. Check if we need to define another Macro for FF protocols
 */

#define SUPPORTED_LOCAL_PROTO(l4proto)  ((l4proto == IPPROTO_IPIP) ||\
					   (l4proto == IPPROTO_IPV6) || (l4proto == IPPROTO_ETHERIP) ||\
					    (l4proto == IPPROTO_GRE) || (l4proto == IPPROTO_ESP) || (l4proto == IPPROTO_AH))
#else
#define SUPPORTED_LOCAL_PROTO(l4proto)  ((l4proto == IPPROTO_IPIP) ||\
					   (l4proto == IPPROTO_IPV6) || (l4proto == IPPROTO_ETHERIP) ||\
					    (l4proto == IPPROTO_GRE))
#endif

#define ASYMFF_UNKNOWN_CMD     0
#define ASYMFF_ENABLE_CMD      1
int cmmAsymFFSetProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
int cmmAsymFFEnableShow(struct cli_def * cli, char *command, char *argv[], int argc);
int cmmAsymFFProcessClientCmd(u_int8_t *cmd_buf, u_int16_t *res_buf, u_int16_t *res_len);
#endif

