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


#ifndef __MODULE_WIFI__
#define __MODULE_WIFI__
#include "itf.h"

#define WIFI_FF_SYSCTL_PATH "/proc/sys/net/"
#define WIFI_FF_SYSCTL_ENTRY "wifi_fast_path_enable"

typedef struct vwd_cmd_s {
	int32_t		action;
	int32_t		ifindex;
	int16_t		vap_id;
	int16_t		direct_path_rx;
	char		ifname[IFNAMSIZ];
	u_int8_t	macaddr[6];
} __attribute__((__packed__)) vwd_cmd_t;

void __cmmGetWiFi(int fd, struct interface *itf);
struct interface *cmmFeWiFiGetRootIf();
int cmmFeWiFiUpdate(FCI_CLIENT *fci_handle, int fd, int request, struct interface *itf);
int cmmFeWiFiEnable( FCI_CLIENT *fci_handle, int fd, struct interface *witf );
int cmmFeWiFiDisable( FCI_CLIENT *fci_handle, int fd, struct interface *itf );
int cmmFeWiFiBridgeUpdate( FCI_CLIENT *fci_handle, int fd, int request, struct interface *bitf);
void cmmWiFiReset(FCI_CLIENT *fci_handle);

#endif //__MODULE_WIFI__
