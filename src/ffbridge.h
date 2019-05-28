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


#ifndef __FFBRIDGE_H__
#define __FFBRIDGE_H__

	#include "cmm.h"
	#include <linux/if_bridge.h>

	/* Macros */
	#define CHUNK	256

	/* Structures */
	struct fdb_entry
	{
		u_int8_t mac_addr[ETH_ALEN];
		u_int16_t port_no;
		unsigned char is_local;
	};

	/* Functions */
	void __cmmGetBridges(int fd);
	int cmmBrToFF(struct RtEntry *route);
	int cmmBrGetPhysItf(int br_ifindex, unsigned char* fdb_mac);

#endif
