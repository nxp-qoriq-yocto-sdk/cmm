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

#include "client_daemon.h"

#ifndef __MODULE_IPSEC_H__
#define __MODULE_IPSEC_H__


#define SA_HASH_TABLE_SIZE 32
#define IPSEC_MAX_KEY_SIZE (256 /8)
#define IPSEC_MAX_NUM_KEYS 2

#define PROTO_FAMILY_IPV4 2
#define PROTO_FAMILY_IPV6 10

#define IPV6_HDR_SIZE           40
#define IPV4_HDR_SIZE           20


extern struct list_head sa_table[SA_HASH_TABLE_SIZE];
extern pthread_mutex_t sa_lock;

typedef struct  IPv4_HDR_STRUCT
{
        unsigned char Version_IHL;
        unsigned char TypeOfService;
        unsigned short TotalLength;
        unsigned short Identification;
        unsigned short Flags_FragmentOffset;
        unsigned char  TTL;
        unsigned char  Protocol;
        unsigned short HeaderChksum;
        unsigned int SourceAddress;
        unsigned int DestinationAddress;
}  ipv4_hdr_t;

typedef struct IPv6_HDR_STRUCT
{
        unsigned short Version_TC_FLHi;
        unsigned short FlowLabelLo;
        unsigned short TotalLength;
        unsigned char  NextHeader;
        unsigned char  HopLimit;
        unsigned int SourceAddress[4];
        unsigned int DestinationAddress[4];
} ipv6_hdr_t;

typedef struct _tIPSec_said {
        unsigned int spi;
        unsigned char sa_type;
        unsigned char proto_family;
        unsigned char replay_window;
        unsigned char flags;
        unsigned int dst_ip[4];
        unsigned int src_ip[4];         // added for NAT-T transport mode
        unsigned short mtu;
        unsigned short dev_mtu;
}IPSec_said, *PIPSec_said;

typedef struct _tIPSec_key_desc {
        unsigned short key_bits;
        unsigned char key_alg;
        unsigned char  key_type;
        unsigned char key[IPSEC_MAX_KEY_SIZE];
}IPSec_key_desc, *PIPSec_key_desc;

typedef struct _tIPSec_lifetime {
        unsigned int allocations;
        unsigned int bytes[2];
}IPSec_lifetime, *PIPSec_lifetime;

typedef struct _tIPSec_sainfo {
	unsigned short		sagd;
	unsigned short		state;
        IPSec_said         	id;             // SA 3-tuple

	unsigned char proto_family;
	unsigned char rsvd;	
	unsigned short rsvd1;
        union {
                ipv4_hdr_t   ipv4h;
                ipv6_hdr_t   ipv6h;
        } tunnel;
#if 0
	struct {
		unsigned short num_keys;
		IPSec_key_desc keys[IPSEC_MAX_NUM_KEYS];
	}key;

	struct {
                unsigned short sport;
                unsigned short dport;
        }natt;

	struct
        {
                IPSec_lifetime  hard_time;
                IPSec_lifetime  soft_time;
                IPSec_lifetime  current_time;

        }lifetime;

#endif

}IPSec_sainfo, *pIPSec_sainfo;

struct SATable {
	struct list_head 	list_by_h;
	IPSec_sainfo		SAInfo;	
	
	struct ct_route         tnl_rt;
	int			flags;
};


/********* CMM structures passed to PFE_CTRL ***********************************/
typedef struct _tCommandIPSecCreateSA {
        unsigned short sagd;
        unsigned short rsvd;
        IPSec_said said;
}CommandIPSecCreateSA, *PCommandIPSecCreateSA;

typedef struct _tCommandIPSecDeleteSA {
        unsigned short sagd;
        unsigned short rsvd;
}CommandIPSecDeleteSA, *PCommandIPSecDeleteSA;

typedef struct _tCommandIPSecSetKey {
        unsigned short sagd;
        unsigned short rsvd;
        unsigned short num_keys;
        unsigned short rsvd2;
        IPSec_key_desc keys[IPSEC_MAX_NUM_KEYS];
}CommandIPSecSetKey, *PCommandIPSecSetKey;

typedef struct _tCommandIPSecSetNatt {
        unsigned short sagd;
        unsigned short sport;
        unsigned short dport;
        unsigned short rsvd;
}CommandIPSecSetNatt, *PCommandIPSecSetNatt;

typedef struct _tCommandIPSecSetState {
        unsigned short sagd;
        unsigned short rsvd;
        unsigned short state;
        unsigned short rsvd2;
}CommandIPSecSetState, *PCommandIPSecSetState;

typedef struct _tCommandIPSecSetTunnel {
        unsigned short sagd;
        unsigned char rsvd;
        unsigned char proto_family;
        union {
                ipv4_hdr_t   ipv4h;
                ipv6_hdr_t   ipv6h;
        } h;
}CommandIPSecSetTunnel, *PCommandIPSecSetTunnel;

typedef struct _tCommandIPSecSetTunnelRoute {
        unsigned short sagd;
	unsigned short route_id;
}CommandIPSecSetTunnelRoute, *PCommandIPSecSetTunnelRoute;


typedef struct _tCommandIPSecSetLifetime{
        unsigned short sagd;
        unsigned short rsvd;
        IPSec_lifetime  hard_time;
        IPSec_lifetime  soft_time;
        IPSec_lifetime  current_time;
}CommandIPSecSetLifetime, *PCommandIPSecSetLifetime;


int __cmmSATunnelRegister(FCI_CLIENT *fci_handle, struct SATable* SAEntry);
void __cmmSAUpdateWithRoute(FCI_CLIENT *fci_handle, struct RtEntry *route);
int cmmSAShow(struct cli_def * cli, char *command, char *argv[], int argc);
int cmmSACreate(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload);
int cmmSADelete(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload);
int cmmSAFlush(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload);
int cmmSASetTunnel(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload);
int __cmmRouteIsSA(int family, const unsigned int* daddr, struct SATable* sa, int prefix_match, int prefix_len);
#endif
