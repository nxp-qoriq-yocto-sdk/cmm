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


#ifndef __MODULE_RX_H__
#define __MODULE_RX_H__

#define L2FLOW_HASH_TABLE_SIZE 1024

/* L2flow definition*/
struct l2flow
{
	unsigned char saddr[ETH_ALEN];
	unsigned char daddr[ETH_ALEN];
	unsigned short ethertype;
	unsigned short session_id;
	unsigned short svlan_tag; /* S TCI */
	unsigned short cvlan_tag; /* C TCI */
	/* L3 info optional */
	struct{
		union {
			unsigned int all[4];
			unsigned int ip;
			unsigned int ip6[4];
		}saddr;
		union {
			unsigned int all[4];
			unsigned int ip;
			unsigned int ip6[4];
		}daddr;
		unsigned char proto;
	}l3;
	struct{
		/* L4 info optional */
		unsigned short sport;
		unsigned short dport;
	}l4;
};


/* L2flow table entry definition*/
struct l2flowTable
{
	struct list_head list;
	int flags;
	char status;
	unsigned int idev_ifi;
	unsigned int odev_ifi;
	unsigned short mark;
	struct l2flow l2flow;
};

int parse_icc_interface(char *pstring, unsigned short *pinterface_number, int num_interfaces);

int cmmL2BridgeProcessClientCmd(FCI_CLIENT* fci_handle, int fc, u_int8_t *cmd_buf, u_int16_t cmd_len, u_int16_t *res_buf, u_int16_t *res_len);
int cmmRxSetProcess(char ** keywords, int tabSize, daemon_handle_t daemon_handle);
int cmmRxShowProcess(char ** keywords, int tabSize, daemon_handle_t daemon_handle);
int cmmRxQueryProcess(char ** keywords, int tabSize, daemon_handle_t daemon_handle);
int parse_macaddr(char *pstring, unsigned char *pmacaddr);

extern struct list_head l2flow_table[L2FLOW_HASH_TABLE_SIZE];
extern pthread_mutex_t brMutex;

static inline unsigned int l2flow_hash(struct l2flow *l2flowtmp)
{	
	return (jhash(l2flowtmp, sizeof(struct l2flow), 0x12345678) & (L2FLOW_HASH_TABLE_SIZE - 1));
}
static inline int cmm_l2flow_cmp(struct l2flow *flow_a, struct l2flow *flow_b)
{
	return memcmp(flow_a, flow_b, sizeof(struct l2flow));
}
int cmm_l2flow_netlink_rcv(const struct sockaddr_nl *who, struct nlmsghdr *nlh, void *arg);
int __cmm_l2flow_deregister(FCI_CLIENT* fci_handler, struct l2flow *l2flow_tmp);
int __cmm_l2flow_register(FCI_CLIENT* fci_handler, char action, struct l2flow *l2flow_tmp, int iifi_idx, int oifi_idx, int flags, short mark);
int __cmm_l2flow_reset(FCI_CLIENT* fci_handler);
int cmm_l2flow_abm_notify(char action, int flags, struct l2flow *l2flow);
void cmm_l2flow_print(int level, struct l2flow *l2flow_tmp, char nl);
int cmmBridgeInit(struct cmm_ct *ctx);
int cmmBridgeControlProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
#endif

