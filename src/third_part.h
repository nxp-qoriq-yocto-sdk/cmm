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

#ifndef __THIRD_PART_H__
#define __THIRD_PART_H__

#define	CMM_CB_CT_TO_QUEUE	0x0001

struct cmm_ct_to_queue_t {
    /* originate and replier common information */
    u_int16_t	state;		/* conntrack state bit (bit0=originator, bit1=replier) */
    u_int16_t	ip_family;	/* IP family (AF_INET=IPv4, AF_INET6 = IPv6) */
    u_int16_t	proto;		/* IP protocol (17=UDP, 6=TCP) */
    u_int32_t	mark;		/* connection mark */
            
    /* originate side information valid if state bit0 is set */
    u_int32_t	orig_saddr[4];	/* source IP address */
    u_int32_t	orig_daddr[4];	/* destination IP address */
    u_int16_t	orig_sport; 	/* source port */
    u_int16_t	orig_dport; 	/* destination port */
    u_int8_t	orig_gw_mac[6]; /* destination MAC address */
    u_int8_t	orig_output;	/* output interface (0=LAN, 1=WAN) */
            
    /* replier side information valid if state bit1 is set */
    u_int32_t	repl_saddr[4];	/* source IP address */
    u_int32_t	repl_daddr[4];	/* destination IP address */
    u_int16_t	repl_sport; 	/* source port */
    u_int16_t	repl_dport; 	/* destination port */
    u_int8_t	repl_gw_mac[6]; /* destination MAC address */
    u_int8_t	repl_output;	/* output interface (0=LAN, 1=WAN) */
};

void cmm_third_part_update(struct ctTable *ctEntry, int dir);
void cmm_third_part_exit(void *priv_data);
int * cmm_third_part_init(void);

#endif

