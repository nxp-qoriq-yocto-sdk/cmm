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

#include <signal.h>
#include <net/if.h>
#include <sys/time.h>

#include "cmm.h"
#include "module_ipsec.h"



struct list_head sa_table[SA_HASH_TABLE_SIZE];
pthread_mutex_t sa_lock = PTHREAD_MUTEX_INITIALIZER;


static inline unsigned short  getSAHash(unsigned short id)
{
	return (id  & (SA_HASH_TABLE_SIZE -1));
}


int cmmSAShow(struct cli_def * cli, char *command, char *argv[], int argc)
{
	int i, count = 0;
	struct SATable *pSAEntry;
	struct list_head *entry;
	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];
	__pthread_mutex_lock(&sa_lock);
	for (i = 0; i < SA_HASH_TABLE_SIZE; i++)
	{
		for(entry = list_first(&sa_table[i]); entry != &sa_table[i]; entry = list_next(entry))	
		{
			count++;
			pSAEntry = container_of(entry, struct SATable, list_by_h);
			cli_print(cli, "Sagd: %d, SPI:0x%x, sa_type: %d, protocal: %d\n", pSAEntry->SAInfo.sagd, pSAEntry->SAInfo.id.spi, pSAEntry->SAInfo.id.sa_type, pSAEntry->SAInfo.id.proto_family);
			if(pSAEntry->SAInfo.proto_family != 0)
			{
				if(pSAEntry->SAInfo.proto_family == PROTO_FAMILY_IPV4)
					cli_print(cli, "IPv4 Tunnel Header Source: %s, Destination: %s \n", inet_ntop(AF_INET, &pSAEntry->SAInfo.tunnel.ipv4h.SourceAddress, sbuf, sizeof(sbuf)), inet_ntop(AF_INET, &pSAEntry->SAInfo.tunnel.ipv4h.DestinationAddress, dbuf, sizeof(dbuf)));
				else
					cli_print(cli, "IPv6 Tunnel Header Source: %s, Destination: %s \n", inet_ntop(AF_INET6, pSAEntry->SAInfo.tunnel.ipv6h.SourceAddress, sbuf, sizeof(sbuf)), inet_ntop(AF_INET6, pSAEntry->SAInfo.tunnel.ipv6h.DestinationAddress, dbuf, sizeof(dbuf)));
			}
		}
	}
	__pthread_mutex_unlock(&sa_lock);
	cli_print(cli, "Total SA count %d\n", count);
	return CLI_OK;
}


static struct SATable *__cmmSAFind(unsigned short handle)
{
	unsigned short hash = getSAHash(handle);
	struct SATable *SAEntry = NULL;
	struct list_head *entry;
	
	for(entry = list_first(&sa_table[hash]); entry != &sa_table[hash]; entry = list_next(entry))
	{
		SAEntry = container_of(entry, struct SATable, list_by_h);
		if (SAEntry->SAInfo.sagd == handle)
			return SAEntry;
	}

	return NULL;
}

static struct SATable *__cmmSAAdd(PCommandIPSecCreateSA pSA_info)
{
	struct SATable *newEntry;
	unsigned short hash;

	newEntry = (struct SATable*) calloc(1, sizeof(struct SATable));
	if (newEntry == NULL)
	{
		cmm_print(DEBUG_ERROR, "%s: malloc failed\n", __func__);
		goto err0;
	}

	newEntry->SAInfo.sagd = pSA_info->sagd;
	hash = getSAHash(newEntry->SAInfo.sagd);
	memcpy(&newEntry->SAInfo.id, &pSA_info->said, sizeof(newEntry->SAInfo.id));
	
	/* Add it to the hash table */
	list_add(&sa_table[hash], &newEntry->list_by_h);

err0:
	return newEntry;
}


int __cmmSATunnelRegister(FCI_CLIENT *fci_handle, struct SATable* SAEntry)
{
	struct flow flow;
	CommandIPSecSetTunnelRoute cmd_set_tnl_route;
	int rc = 0;
	flow.family = SAEntry->SAInfo.proto_family;
	
	if (SAEntry->SAInfo.proto_family == PROTO_FAMILY_IPV4)
	{
		flow.sAddr = &SAEntry->SAInfo.tunnel.ipv4h.SourceAddress;
		flow.dAddr = &SAEntry->SAInfo.tunnel.ipv4h.DestinationAddress;
	}
	else
	{
		flow.sAddr = SAEntry->SAInfo.tunnel.ipv6h.SourceAddress;
		flow.dAddr = SAEntry->SAInfo.tunnel.ipv6h.DestinationAddress;
	}
	
	flow.fwmark = 0;
	flow.iifindex = 0;
	flow.proto = 0;
	/* Eventhough SA is local connection, as the connection will not exist in kernel this is disabled */
	flow.flow_flags = FLOWFLAG_SA_ROUTE;

	rc = __cmmRouteRegister(&SAEntry->tnl_rt, &flow, "sa");	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
/* 
   In 3.19 kernel, neighbor entry in linux neighbor cache is not created during the creation of route entry
   in linux route cache as was done in previous versions. Consider a scenario where an SA is waiting for a
   neigbor 'X' and some other connection creates this neigbor entry 'X' in CMM. Now the neigbor creation
   event received by CMM will be ignored since neighbor entry is already present in CMM and no changes were
   made to neighbor entry. SA waiting for neighbor will never know the creation of neighbor entry 'X' in CMM.
   To fix this a dummy entry in created in CMM if the required neighbor entry is not present in linux neighbor cache. 
*/
	if(SAEntry->tnl_rt.route && !SAEntry->tnl_rt.route->neighEntry)
	{
		SAEntry->tnl_rt.route->neighEntry = __cmmNeighAdd(SAEntry->tnl_rt.route->family, SAEntry->tnl_rt.route->gwAddr, SAEntry->tnl_rt.route->oifindex);
		SAEntry->tnl_rt.route->neighEntry->count++;
	}
#endif
	if (rc < 0)
		goto program;

	cmm_print(DEBUG_INFO, "%s:Neighor resolved \n", __func__);
	cmmFeRouteUpdate(fci_handle, ADD | UPDATE, SAEntry->tnl_rt.fpp_route);

program:

	__cmmCheckFPPRouteIdUpdate(&SAEntry->tnl_rt, &SAEntry->flags);
	cmd_set_tnl_route.sagd = SAEntry->SAInfo.sagd;
	cmd_set_tnl_route.route_id = SAEntry->tnl_rt.fpp_route_id;

	/* Send the tunnel command to FPP */
	if (SAEntry->flags & FPP_NEEDS_UPDATE)
	{
		if (cmmKeyEnginetoIPSec(fci_handle, FPP_CMD_IPSEC_SA_TNL_ROUTE, sizeof(CommandIPSecSetTunnelRoute),(unsigned short*) &cmd_set_tnl_route) < 0)
		{
			cmm_print(DEBUG_ERROR, "%s:cmmKeyEnginetoIPSec failed while setting tunnel route:\n", __func__);
			return -1;
		}
	}

	SAEntry->flags &= ~FPP_NEEDS_UPDATE;

	return rc;
}


static void __cmmSARouteUpdate(FCI_CLIENT *fci_handle, struct SATable *s, struct RtEntry *route)
{
	struct ct_route rt = s->tnl_rt;

	cmm_print(DEBUG_INFO, "%s\n", __func__);

	if (route->flags & INVALID)
	{
		s->tnl_rt.route = NULL;
		s->tnl_rt.fpp_route = NULL;
	}
	else
	{
		rt.route = NULL;
		s->tnl_rt.fpp_route = NULL;
	}

	__pthread_mutex_lock(&sa_lock);
	__cmmSATunnelRegister(fci_handle, s);
	__pthread_mutex_unlock(&sa_lock);

	__cmmRouteDeregister(fci_handle, &rt, "sa");
}

void __cmmSAUpdateWithRoute(FCI_CLIENT *fci_handle, struct RtEntry *route)
{
	struct SATable *s;
	struct list_head *entry;
	int i;


	for (i = 0; i < SA_HASH_TABLE_SIZE; i++)
	{
		for (entry = list_first(&sa_table[i]); entry != &sa_table[i]; entry = list_next(entry))
		{
			s = container_of(entry, struct SATable, list_by_h);

			if (s->tnl_rt.route == route)
				 __cmmSARouteUpdate(fci_handle, s, route);
		}
	}

}

int __cmmRouteIsSA(int family, const unsigned int* daddr, struct SATable* sa, int prefix_match, int prefix_len)
{
	unsigned int* tunnel_daddr;
	int addr_len = IPADDRLEN(family);


	if (sa->tnl_rt.route)
		goto out;

	if (sa->SAInfo.proto_family != family)
		goto out;

	if (sa->SAInfo.proto_family == PROTO_FAMILY_IPV4)
		tunnel_daddr = &sa->SAInfo.tunnel.ipv4h.DestinationAddress;
	else
		tunnel_daddr = sa->SAInfo.tunnel.ipv6h.DestinationAddress;

	if (prefix_match)
	{
		if (cmmPrefixEqual(tunnel_daddr, daddr, prefix_len))
		return 1;
	}
	else
	{
		if (memcmp(tunnel_daddr, daddr, addr_len) == 0)
		return 1;
	}
out:
	return 0;
}

static int __cmmSARemove(FCI_CLIENT *fci_handle, struct SATable *SAEntry)
{
	unsigned short hash;
	hash = getSAHash(SAEntry->SAInfo.sagd);

	__cmmRouteDeregister(fci_handle, &SAEntry->tnl_rt, "sa");

        /* Remove it from the hash table */
	list_del(&SAEntry->list_by_h);
	free(SAEntry);

	return 0;
}


int cmmSACreate(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload)
{
	PCommandIPSecCreateSA pSA_cmd = (PCommandIPSecCreateSA)payload;
	struct SATable *pSAEntry;
	int rc = 0;
	if (len != sizeof(CommandIPSecCreateSA))
	{
		cmm_print(DEBUG_ERROR, "%s: command length doesn't match %d-%d\n", __func__, sizeof(CommandIPSecCreateSA), len);
		return -1;
	}

	cmm_print(DEBUG_INFO, "%s: fcode 0x%x len %d bytes\n", __func__, fcode, len);

	__pthread_mutex_lock(&sa_lock);
	pSAEntry = __cmmSAFind(pSA_cmd->sagd);

	if (pSAEntry)
	{
		cmm_print(DEBUG_ERROR, "%s: SA exists :%x \n", __func__, pSA_cmd->sagd);
		rc = -1;
		goto out;
	}
	
	pSAEntry = __cmmSAAdd(pSA_cmd);
	if(!pSAEntry)
	{
		rc = -1;
		goto out;
	}
	cmm_print(DEBUG_INFO, "%s: new SA added :%x \n", __func__, pSA_cmd->sagd);

out:
	__pthread_mutex_unlock(&sa_lock);
	return rc;


}

int cmmSADelete(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload)
{
	PCommandIPSecDeleteSA pSA_cmd = (PCommandIPSecDeleteSA)payload;
	struct SATable *pSAEntry;
	int rc = 0;
	if (len != sizeof(CommandIPSecDeleteSA))
	{
		cmm_print(DEBUG_ERROR, "%s: command length doesn't match %d-%d\n", __func__, sizeof(CommandIPSecDeleteSA), len);
		return -1;
	}
	__pthread_mutex_lock(&sa_lock);
	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);
	__pthread_mutex_lock(&flowMutex);

	pSAEntry = __cmmSAFind(pSA_cmd->sagd);
	if (!pSAEntry)
	{
		cmm_print(DEBUG_ERROR, "%s: SA doesn't exist :%x \n", __func__, pSA_cmd->sagd);
		rc = -1;
		goto out;
	}
	__cmmSARemove(fci_handle, pSAEntry);	

out:	
	__pthread_mutex_unlock(&flowMutex);
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&itf_table.lock);
	__pthread_mutex_unlock(&sa_lock);
	return rc;
}


int cmmSAFlush(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload)
{
	int i, rc = 0;
	struct SATable *pSAEntry;
	struct list_head *entry;

	__pthread_mutex_lock(&sa_lock);
	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);
	__pthread_mutex_lock(&flowMutex);
	
	for (i = 0; i < SA_HASH_TABLE_SIZE; i++)
	{
		for(entry = list_first(&sa_table[i]); entry != &sa_table[i]; )	
		{
			pSAEntry = container_of(entry, struct SATable, list_by_h);
			entry = list_next(entry);
			__cmmSARemove(fci_handle, pSAEntry);
		}
	}
	__pthread_mutex_unlock(&flowMutex);
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&itf_table.lock);
	__pthread_mutex_unlock(&sa_lock);
	return rc;
}

int cmmSASetTunnel(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, unsigned short *payload)
{
	PCommandIPSecSetTunnel pSA_cmd = (PCommandIPSecSetTunnel)payload;
	int rc = 0;
	struct SATable *pSAEntry;
	if (len != sizeof(CommandIPSecSetTunnel))
	{
		cmm_print(DEBUG_ERROR, "%s: command length doesn't match %d-%d\n", __func__, sizeof(CommandIPSecSetTunnel), len);
		return -1;
	}
	__pthread_mutex_lock(&sa_lock);
	__pthread_mutex_lock(&itf_table.lock);
	__pthread_mutex_lock(&rtMutex);
	__pthread_mutex_lock(&neighMutex);
	__pthread_mutex_lock(&flowMutex);
	pSAEntry = __cmmSAFind(pSA_cmd->sagd);

	if (!pSAEntry)
	{
		cmm_print(DEBUG_ERROR, "%s: SA doesn't exist :%x \n", __func__, pSA_cmd->sagd);
		rc = -1;
		goto out;
	}

	pSAEntry->SAInfo.proto_family = pSA_cmd->proto_family;
	if (pSA_cmd->proto_family == PROTO_FAMILY_IPV4)
		memcpy(&pSAEntry->SAInfo.tunnel.ipv4h, &pSA_cmd->h.ipv4h, IPV4_HDR_SIZE);
	else
		memcpy(&pSAEntry->SAInfo.tunnel.ipv6h, &pSA_cmd->h.ipv6h, IPV6_HDR_SIZE);

	/* Find the route for tunnel and corresponding neighbor here */
	rc = __cmmSATunnelRegister(fci_handle, pSAEntry);
out:	
	__pthread_mutex_unlock(&flowMutex);
	__pthread_mutex_unlock(&neighMutex);
	__pthread_mutex_unlock(&rtMutex);
	__pthread_mutex_unlock(&itf_table.lock);
	__pthread_mutex_unlock(&sa_lock);
	return rc;
}

