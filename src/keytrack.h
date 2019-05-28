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

#ifndef __KEYTRACK_H__
#define __KEYTRACK_H__

#include <linux/version.h>
#include "list.h"
#include "conntrack.h"


#define MAX_SA_BUNDLE 4
#define FLOW_HASH_TABLE_SIZE	CONNTRACK_HASH_TABLE_SIZE	// uses HASH_CT macros for keys

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
struct flowi_tunnel {
        __u64                  tun_id;
};
#endif

struct flowi_common {
	int	flowic_oif;
	int	flowic_iif;
	__u32	flowic_mark;
	__u8	flowic_tos;
	__u8	flowic_scope;
	__u8	flowic_proto;
	__u8	flowic_flags;
	#define FLOWI_FLAG_ANYSRC		0x01
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	#define FLOWI_FLAG_KNOWN_NH		0x02
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	#define FLOWI_FLAG_SKIP_NH_OIF          0x04
#endif
#else
	#define FLOWI_FLAG_PRECOW_METRICS	0x02
	#define FLOWI_FLAG_CAN_SLEEP		0x04
#endif
	__u32	flowic_secid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	struct flowi_tunnel flowic_tun_key;
#endif
};

union flowi_uli {
	struct {
		__be16	dport;
		__be16	sport;
	} ports;
	
	struct {
		__u8	type;
		__u8	code;
	} icmpt;
	
	struct {
		__le16	dport;
		__le16	sport;
	} dnports;
	
	__be32		spi;
	__be32		gre_key;
	
	struct {
		__u8	type;
	} mht;
};

struct flowi4 {
	struct flowi_common	__fl_common;
	#define flowi4_oif		__fl_common.flowic_oif
	#define flowi4_iif		__fl_common.flowic_iif
	#define flowi4_mark		__fl_common.flowic_mark
	#define flowi4_tos		__fl_common.flowic_tos
	#define flowi4_scope		__fl_common.flowic_scope
	#define flowi4_proto		__fl_common.flowic_proto
	#define flowi4_flags		__fl_common.flowic_flags
	#define flowi4_secid		__fl_common.flowic_secid
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	#define flowi4_tun_key          __fl_common.flowic_tun_key
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	/* (saddr,daddr) must be grouped, same order as in IP header */
	__be32			saddr;
	__be32			daddr;
#else
	__be32			daddr;
	__be32			saddr;
#endif
	union flowi_uli		uli;
	#define fl4_sport		uli.ports.sport
	#define fl4_dport		uli.ports.dport
	#define fl4_icmp_type		uli.icmpt.type
	#define fl4_icmp_code		uli.icmpt.code
	#define fl4_ipsec_spi		uli.spi
	#define fl4_mh_type		uli.mht.type
	#define fl4_gre_key		uli.gre_key
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
}__attribute__((__aligned__(8)));
#else
};
#endif

struct flowi6 {
	struct flowi_common	__fl_common;
	#define flowi6_oif		__fl_common.flowic_oif
	#define flowi6_iif		__fl_common.flowic_iif
	#define flowi6_mark		__fl_common.flowic_mark
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,2,0)
	#define flowi6_tos		__fl_common.flowic_tos
#endif
	#define flowi6_scope		__fl_common.flowic_scope
	#define flowi6_proto		__fl_common.flowic_proto
	#define flowi6_flags		__fl_common.flowic_flags
	#define flowi6_secid		__fl_common.flowic_secid
	struct in6_addr		daddr;
	struct in6_addr		saddr;
	__be32			flowlabel;
	union flowi_uli		uli;
	#define fl6_sport		uli.ports.sport
	#define fl6_dport		uli.ports.dport
	#define fl6_icmp_type		uli.icmpt.type
	#define fl6_icmp_code		uli.icmpt.code
	#define fl6_ipsec_spi		uli.spi
	#define fl6_mh_type		uli.mht.type
	#define fl6_gre_key		uli.gre_key
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
}__attribute__((__aligned__(8)));
#else
};
#endif

struct flowidn {
	struct flowi_common	__fl_common;
	#define flowidn_oif		__fl_common.flowic_oif
	#define flowidn_iif		__fl_common.flowic_iif
	#define flowidn_mark		__fl_common.flowic_mark
	#define flowidn_scope		__fl_common.flowic_scope
	#define flowidn_proto		__fl_common.flowic_proto
	#define flowidn_flags		__fl_common.flowic_flags
	__le16			daddr;
	__le16			saddr;
	union flowi_uli		uli;
	#define fld_sport		uli.ports.sport
	#define fld_dport		uli.ports.dport
};

struct flowi {
	union {
		struct flowi_common	__fl_common;
		struct flowi4		ip4;
		struct flowi6		ip6;
		struct flowidn		dn;
	} u;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,2,0)
#ifndef ARCH_ARM32
	/*In kernel this structure has attribute
	 * __attribute__((__aligned__(BITS_PER_LONG/8)))
	 * This is making 64bit aligned for 64Bit arch
	 * as WA following reserved feild added.
	 */
	unsigned int res;
#endif
#endif
	#define flowi_oif	u.__fl_common.flowic_oif
	#define flowi_iif	u.__fl_common.flowic_iif
	#define flowi_mark	u.__fl_common.flowic_mark
	#define flowi_tos	u.__fl_common.flowic_tos
	#define flowi_scope	u.__fl_common.flowic_scope
	#define flowi_proto	u.__fl_common.flowic_proto
	#define flowi_flags	u.__fl_common.flowic_flags
	#define flowi_secid	u.__fl_common.flowic_secid
};


struct FlowEntry
{
	struct list_head list;
	struct flowi  fl;
	unsigned char sa_nr;
	unsigned short family;
	unsigned short dir;
	unsigned short ignore_neigh;
	int flags;
	unsigned short sa_handle[MAX_SA_BUNDLE];
	unsigned int ref_count;
};

typedef struct netkey_sa_update_cmd{
	unsigned short sagd;
	unsigned short rsvd;
	unsigned long long bytes;
	unsigned long long packets;
}netkey_sa_update_cmd_t;

/* Maximum only 2 SAs are supported per flow,
whether they are both encrypted flows or both decrypted flows
or one encrypted and one decrypted flow */
#define MAX_SA_PER_FLOW 2
/* The following definitions for directions present in "include/net/flow.h" in
 * kernel */
#define FLOW_DIR_IN     0  //  Input flow  for all local traffic
#define FLOW_DIR_OUT    1  // Output flow to be sent out with ipsec policy applied 
#define FLOW_DIR_FWD    2  // Forwarded flow for all traffic getting forwarded

#define FLOW_DIR_IN_BITVAL (1 << FLOW_DIR_IN)
#define FLOW_DIR_OUT_BITVAL (1 << FLOW_DIR_OUT)
#define FLOW_DIR_FWD_BITVAL (1 << FLOW_DIR_FWD)

#define SAQUERY_UNKNOWN_CMD	0
#define SAQUERY_ENABLE_CMD	1
#define SAQUERY_TIMER_CMD	2

#define NETKEY_CMD_SA_INFO_UPDATE	0x0a0c

extern pthread_mutex_t flowMutex;
extern struct  list_head flow_table[FLOW_HASH_TABLE_SIZE];

int cmmKeyCatch(unsigned short fcode, unsigned short len, unsigned short *payload);
int cmmKeyEnginetoIPSec(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload);
int cmmIPSectoKeyEngine(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload);
int cmmFlowKeyEngineRemove(FCI_CLIENT *fci_handle, struct FlowEntry *fentry);

struct FlowEntry *__cmmFlowFind(int family, const unsigned int *Saddr, const unsigned int *Daddr, unsigned short Sport, unsigned short Dport, unsigned char proto, unsigned short dir);
void __cmmFlowRemove(struct FlowEntry *flow);
struct FlowEntry *__cmmFlowAdd(int family, struct flowi *fl, unsigned char sa_nr, unsigned short *sa_handle, unsigned short dir);
struct FlowEntry *__cmmFlowGet(int family, const unsigned int *Saddr, const unsigned int *Daddr, unsigned short Sport, unsigned short Dport, unsigned char proto, unsigned short dir);
void __cmmFlowPut(struct FlowEntry *flow);

int cmmDPDSaQuerySetProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
int cmmSaQueryTimerShow(struct cli_def * cli, char *command, char *argv[], int argc);
int cmmDPDSAQUERYProcessClientCmd(u_int8_t *cmd_buf, u_int16_t *res_buf, u_int16_t *res_len);
#endif
