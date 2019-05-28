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


#include "cmm.h"
#include "ffbridge.h"
#include "itf.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <ctype.h>

static void __cmmGetBridgePorts(int fd, struct interface *bridge)
{
	unsigned long args[4] = {BRCTL_GET_PORT_LIST, (unsigned long)bridge->ifindices, MAX_PORTS, 0};
	struct ifreq ifr;
	int max_ports;

	memset(bridge->ifindices, 0, MAX_PORTS * sizeof(int));
	if (____itf_get_name(bridge, ifr.ifr_name, sizeof(ifr.ifr_name)) < 0)
	{
		cmm_print(DEBUG_ERROR, "%s::%d: ____itf_get_name(%d) failed\n", __func__, __LINE__, bridge->ifindex);

		goto out;
	}

	ifr.ifr_data = (char *) &args;

	if ((max_ports = ioctl(fd, SIOCDEVPRIVATE, &ifr)) < 0)
	{
		cmm_print(DEBUG_ERROR, "%s::%d: ioctl() %s\n", __func__, __LINE__, strerror(errno));
		goto out;
	}
out:
	return;
}

void __cmmGetBridges(int fd)
{
	int ifindices[MAX_BRIDGES];
	unsigned long args[3] = {BRCTL_GET_BRIDGES, (unsigned long)ifindices, MAX_BRIDGES};
	struct interface *itf;
	char ifname[IFNAMSIZ];
	int ifindex;
	int num, i;

	num = ioctl(fd, SIOCGIFBR, args);
	if (num < 0)
	{
		cmm_print(DEBUG_ERROR, "%s::%d: ioctl() %s\n", __func__, __LINE__, strerror(errno));

		goto out;
	}

	for (i = 0; i < num; i++)
	{
		ifindex = ifindices[i];

		itf = __itf_find(ifindex);
		if (!itf)
			continue;

		itf->itf_flags |= ITF_BRIDGE;

		__cmmGetBridgePorts(fd, itf);

		cmm_print(DEBUG_INFO, "%s::%d: %s is a bridge\n", __func__, __LINE__, if_indextoname(itf->ifindex, ifname));
	}

out:
	return;
}

static void cmmBrgetAllMacPort(int br_ifindex)
{
	struct __fdb_entry fe[CHUNK];
	int i, n;
	unsigned long args[4];
	struct ifreq ifr;
	int retries;
	int fd;

	cmm_print(DEBUG_INFO, "%s(%d)\n", __func__, br_ifindex);

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		cmm_print(DEBUG_ERROR, "%s::%d: socket() %s\n", __func__, __LINE__, strerror(errno));
		goto err;
	}

	args[0] = BRCTL_GET_FDB_ENTRIES;
	args[1] = (unsigned long) fe;
	args[2] = CHUNK;
	args[3] = 0;

	if (__itf_get_name(br_ifindex, ifr.ifr_name, sizeof(ifr.ifr_name)) < 0)
	{
		cmm_print(DEBUG_ERROR, "%s::%d: __itf_get_name(%d) failed\n", __func__, __LINE__, br_ifindex);

		goto close;
	}

	ifr.ifr_data = (char *) args;

	while (1) {
		retries = 0;

	retry:
		n = ioctl(fd, SIOCDEVPRIVATE, &ifr);
		/* table can change during ioctl processing */
		if (n < 0)
		{
			if (errno == EAGAIN)
			{
				if (++retries < 10)
					goto retry;
				else
					goto close;
			}

			cmm_print(DEBUG_ERROR, "%s::%d: ioctl() %s\n", __func__, __LINE__, strerror(errno));
			goto close;

		} else if (n == 0)
			goto close;

		for (i = 0; i < n; i++) {
			if (fe[i].is_local)
				continue;

			__cmmNeighUpdateAllMacs(br_ifindex, fe[i].mac_addr, fe[i].port_no);
		}

		args[3] += n;
	}

close:
	close(fd);

err:
	return;
}


int cmmBrToFF(struct RtEntry *route)
{
	int ifindex;
	char brname[IFNAMSIZ], ifname[IFNAMSIZ];

	if (!route->neighEntry)
	{
		cmm_print(DEBUG_ERROR, "%s: neighbor entry not set in route\n", __func__);
		goto err;
	}

	/* FIXME Update also if more than N seconds have passed since last update */
	if (route->neighEntry->port < 0)
		cmmBrgetAllMacPort(route->oifindex);

	if (route->neighEntry->port < 0)
		goto err;

	ifindex = __itf_get_from_bridge_port(route->oifindex, route->neighEntry->port);
	if (ifindex <= 0)
		goto err;

	if (route->phys_oifindex != ifindex)
	{
		route->phys_oifindex = ifindex;
	}

	cmm_print(DEBUG_INFO, "%s::%d: if:%s br:%s port:%d mac:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			__func__, __LINE__,
			if_indextoname(route->phys_oifindex, ifname),
			if_indextoname(route->oifindex, brname),
			route->neighEntry->port,
			route->neighEntry->macAddr[0], route->neighEntry->macAddr[1],
			route->neighEntry->macAddr[2], route->neighEntry->macAddr[3],
			route->neighEntry->macAddr[4], route->neighEntry->macAddr[5]);

	return 0;

err:
	return -1;
}


/* This function gets the physical port information from the bridge_port */
int cmmBrGetPhysItf(int br_ifindex, unsigned char *fdb_mac)
{
	struct __fdb_entry fe[CHUNK];
	int i, n;
	unsigned long args[4];
	struct ifreq ifr;
	int retries;
	int fd, phys_ifindex = -1;

	cmm_print(DEBUG_INFO, "%s(%d)\n", __func__, br_ifindex);

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		cmm_print(DEBUG_ERROR, "%s::%d: socket() %s\n", __func__, __LINE__, strerror(errno));
		goto err;
	}

	args[0] = BRCTL_GET_FDB_ENTRIES;
	args[1] = (unsigned long) fe;
	args[2] = CHUNK;
	args[3] = 0;

	if (__itf_get_name(br_ifindex, ifr.ifr_name, sizeof(ifr.ifr_name)) < 0)
	{
		cmm_print(DEBUG_ERROR, "%s::%d: __itf_get_name(%d) failed\n", __func__, __LINE__, br_ifindex);

		goto close;
	}

	ifr.ifr_data = (char *) args;

	while (1) {
		retries = 0;

	retry:
		n = ioctl(fd, SIOCDEVPRIVATE, &ifr);
		/* table can change during ioctl processing */
		if (n < 0)
		{
			if (errno == EAGAIN)
			{
				if (++retries < 10)
					goto retry;
				else
					goto close;
			}

			cmm_print(DEBUG_ERROR, "%s::%d: ioctl() %s\n", __func__, __LINE__, strerror(errno));
			goto close;

		} else if (n == 0)
			goto close;

		for (i = 0; i < n; i++) {
			if (fe[i].is_local)
				continue;

			if (memcmp(fdb_mac, fe[i].mac_addr, 6) == 0)
			{
				cmm_print(DEBUG_INFO, "%s(%d) Found mac\n", __func__, fe[i].port_no);
				phys_ifindex = __itf_get_from_bridge_port(br_ifindex, fe[i].port_no);
				goto close;
			}
		}

		args[3] += n;
	}

close:
	close(fd);

err:
	return (phys_ifindex);
}


