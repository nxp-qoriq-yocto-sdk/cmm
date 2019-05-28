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
#include "fpp.h"
#include <ctype.h>
#include <limits.h>

/************************************************************
 *
 *
 *
 ************************************************************/
void cmmQmShowPrintHelp()
{
	cmm_print(DEBUG_STDOUT, "show qm not yet supported\n");
}


/************************************************************
 *
 *
 *
 ************************************************************/
int cmmQmShowProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle)
{
	
//help:
	cmmQmShowPrintHelp();
	return -1;
}

int cmmQmExptRateQueryProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle)
{
#ifdef COMCERTO_2000
	int cpt = tabStart;
#endif
	int rcvBytes = 0;
	union u_rxbuf rxbuf;
	short rc;
	fpp_qm_expt_rate_cmd_t *pExptRateCmd = ( fpp_qm_expt_rate_cmd_t *)rxbuf.rcvBuffer;

#ifdef COMCERTO_2000
	if(!keywords[cpt])
		goto help;

	if (strcasecmp(keywords[cpt], "eth") == 0)
		pExptRateCmd->if_type = FPP_EXPT_TYPE_ETH;
	else if (strcasecmp(keywords[cpt], "wifi") == 0)
		pExptRateCmd->if_type = FPP_EXPT_TYPE_WIFI;
	else if (strcasecmp(keywords[cpt], "arp_ndp") == 0)
		pExptRateCmd->if_type = FPP_EXPT_TYPE_ARP;
	else if (strcasecmp(keywords[cpt], "pcap") == 0)
		pExptRateCmd->if_type = FPP_EXPT_TYPE_PCAP;
	else
		goto help;
#endif

   rcvBytes = cmmSendToDaemon(daemon_handle, FPP_CMD_QM_QUERY_EXPT_RATE , 
                            pExptRateCmd, sizeof(fpp_qm_expt_rate_cmd_t) , rxbuf.rcvBuffer);

   if (rcvBytes < sizeof( fpp_qm_expt_rate_cmd_t)  ) {
                rc = (rcvBytes < sizeof(unsigned short) ) ? 0 : rxbuf.result;
                if (rc == FPP_ERR_UNKNOWN_ACTION) {
                    cmm_print(DEBUG_STDERR, "ERROR: doess not support ACTION_QUERY\n");
                } else {
                    cmm_print(DEBUG_STDERR, "ERROR: Unexpected result returned from FPP rc:%d\n", rc);
                }
                return CLI_OK;
            }

   cmm_print(DEBUG_STDOUT, "QM Exception RATE (packets/sec): %d\n", 
					(pExptRateCmd->pkts_per_msec * 1000));

   return CLI_OK;
#ifdef COMCERTO_2000
help:
#endif
	cmm_print(DEBUG_STDOUT, "Usage: query qmexptrate {eth | wifi}\n");

	return CLI_OK;
}


#define NUM_INTERFACES GEM_PORTS


/************************************************************
 *
 *
 *
 ************************************************************/

static char *get_queue_list(char *buf, u_int32_t qmask)
{
	int qnum, firstq;
	if (qmask == 0)
		strcpy(buf, "No queues attached");
	else
	{
		strcpy(buf, "Queues:");
		for (qnum = 0; qnum < FPP_NUM_QUEUES; qnum++)
		{
			if ((qmask & (1 << qnum)) == 0)
				continue;
			firstq = qnum++;
			if (qnum == FPP_NUM_QUEUES || (qmask & (1 << qnum)) == 0)
			{
				sprintf(buf + strlen(buf), " %d", firstq);
			}
			else
			{
				for ( ; qnum < FPP_NUM_QUEUES; qnum++)
				{
					if ((qmask & (1 << qnum)) == 0)
						break;
				}
				sprintf(buf + strlen(buf), " %d-%d", firstq, qnum - 1);
			}
		}
	}
	return buf;
}

int cmmQmQueryProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle)
{
#if !defined(COMCERTO_2000) && !defined(LS1043)
        int rcvBytes = 0,i,j,k,len=0;
	union u_rxbuf rxbuf;
        short rc;
        fpp_qm_query_cmd_t *pQmQuery = ( fpp_qm_query_cmd_t *)rxbuf.rcvBuffer;
	char output_buf[256];


        cmm_print(DEBUG_STDOUT, "QM details:\n");
        cmm_print(DEBUG_STDOUT, "---------- \n");
        for (i = 0 ; i < NUM_INTERFACES; i++)
   	{
	    char ifname[IFNAMSIZ];

	    memset(rxbuf.rcvBuffer,0,256);

            pQmQuery->port = i;
            rcvBytes = cmmSendToDaemon(daemon_handle,FPP_CMD_QM_QUERY ,
                  pQmQuery, sizeof(fpp_qm_query_cmd_t) , rxbuf.rcvBuffer);

            if (rcvBytes != sizeof(fpp_qm_query_cmd_t) ) {
                rc = (rcvBytes < sizeof(unsigned short) ) ? 0 : rxbuf.result;
                if (rc == FPP_ERR_UNKNOWN_ACTION) {
                    cmm_print(DEBUG_STDERR, "ERROR: doess not support ACTION_QUERY\n");
                } else {
                    cmm_print(DEBUG_STDERR, "ERROR: Unexpected result returned from FPP rc:%d\n", rc);
                }
                return CLI_OK;
            }

	    cmm_print(DEBUG_STDOUT, "Interface : %s\n", get_port_name(pQmQuery->port, ifname, IFNAMSIZ));

	    if (pQmQuery->queue_qosenable_mask != 0) {
            	cmm_print(DEBUG_STDOUT, "QOS: Enabled on queue(s): \n");
		for (j=0; j < FPP_NUM_QUEUES; j++)
		{
			if(pQmQuery->queue_qosenable_mask & (1 << j))
				len += sprintf(output_buf+len, "%d  ", j);
		}
		cmm_print(DEBUG_STDOUT, "%s \n",output_buf);
	    }
	    else
            	cmm_print(DEBUG_STDOUT, "QOS: Disabled \n");


		cmm_print(DEBUG_STDOUT, "Maximum Tx Depth = %d \n", pQmQuery->max_txdepth);

		cmm_print(DEBUG_STDOUT, "Shaper details:\n");
        	cmm_print(DEBUG_STDOUT, "---------- \n");
		for (j =0; j < FPP_NUM_SHAPERS; j++)
		{
			len=0;
			cmm_print(DEBUG_STDOUT, "Shaper %d:\n", j);

			if(pQmQuery->shaper_qmask[j] == 0)
				cmm_print(DEBUG_STDOUT, "No Queues attached\n");
			else 
			{
				cmm_print(DEBUG_STDOUT, "The following queue(s) are attached: \n");
				for (k=0; k < FPP_NUM_QUEUES; k++)
				{
					if(pQmQuery->shaper_qmask[j] & (1 << k))
						len += sprintf(output_buf+len, "%d  ", k);  
				}
				cmm_print(DEBUG_STDOUT, "%s \n",output_buf);
			}

			cmm_print(DEBUG_STDOUT, "Tokens Per Clock Period %d \n", pQmQuery->tokens_per_clock_period[j]);
			cmm_print(DEBUG_STDOUT, "Bucket Size %d \n", pQmQuery->bucket_size[j]);

		}
		cmm_print(DEBUG_STDOUT, "---------- \n");

		cmm_print(DEBUG_STDOUT, "Scheduler details:\n");
        	cmm_print(DEBUG_STDOUT, "---------- \n");
		for (j =0; j < FPP_NUM_SCHEDULERS; j++)
		{
			len=0;
			cmm_print(DEBUG_STDOUT, "Scheduler %d:\n", j);

			if(pQmQuery->sched_qmask[j] == 0)
				cmm_print(DEBUG_STDOUT, "No Queues attached\n");
			else 
			{
				cmm_print(DEBUG_STDOUT, "The following queue(s) are attached: \n");
				for (k=0; k < FPP_NUM_QUEUES; k++)
				{
					if(pQmQuery->sched_qmask[j] & (1 << k))
						len += sprintf(output_buf+len, "%d  ", k);  						
				}
				cmm_print(DEBUG_STDOUT, "%s \n",output_buf);
			}

			switch (pQmQuery->sched_alg[j])
             		{
	       		case 0:
				cmm_print(DEBUG_STDOUT, "ALG : PQ \n");
				break;
	       		case 1:
				cmm_print(DEBUG_STDOUT, "ALG :CBWFQ \n");
				break;
	       		case 2:
				cmm_print(DEBUG_STDOUT, "ALG :DWRR \n");
				break;
			case 3:
				cmm_print(DEBUG_STDOUT, "ALG :RR \n");
				break;
			default:
				cmm_print(DEBUG_STDOUT, "ALG :NONE \n");
				break;
	    		}

		}
		cmm_print(DEBUG_STDOUT, "---------- \n");

		cmm_print(DEBUG_STDOUT, "Queue details:\n");
        	cmm_print(DEBUG_STDOUT, "---------- \n");
		for (j =0; j < FPP_NUM_QUEUES; j++)
		{
			len=0;
			len += sprintf(output_buf+len, "Queue %d: ", j);
			len += sprintf(output_buf+len, "Max Queue Depth %d  ", pQmQuery->max_qdepth[j]);
			cmm_print(DEBUG_STDOUT, "%s \n",output_buf);
		}
		cmm_print(DEBUG_STDOUT, "\n---------- \n");

   
	    
	    cmm_print(DEBUG_STDOUT,"--------------------------------------------------\n");
       }

#else // COMCERTO_2000
        int rcvBytes;
	int portnum, queuenum, shapernum, schednum;
        short rc;
	union u_rxbuf rxbuf;
	char output_buf[256];
	char ifname[IFNAMSIZ];
        fpp_qm_query_portinfo_cmd_t *pQmQueryPortInfo = ( fpp_qm_query_portinfo_cmd_t *)rxbuf.rcvBuffer;
        fpp_qm_query_queue_cmd_t *pQmQueryQueue = ( fpp_qm_query_queue_cmd_t *)rxbuf.rcvBuffer;
        fpp_qm_query_shaper_cmd_t *pQmQueryShaper = ( fpp_qm_query_shaper_cmd_t *)rxbuf.rcvBuffer;
        fpp_qm_query_sched_cmd_t *pQmQuerySched = ( fpp_qm_query_sched_cmd_t *)rxbuf.rcvBuffer;

        for (portnum = 0 ; portnum < NUM_INTERFACES; portnum++)
   	{
		memset(rxbuf.rcvBuffer, 0, 256);
#ifndef LS1043
		pQmQueryShaper->port = portnum;
#else
		strcpy(pQmQueryPortInfo->interface, port_table[portnum].ifname);
#endif
		rcvBytes = cmmSendToDaemon(daemon_handle, FPP_CMD_QM_QUERY_PORTINFO,
	    				pQmQueryPortInfo, sizeof(fpp_qm_query_portinfo_cmd_t), rxbuf.rcvBuffer);
		if (rcvBytes != sizeof(fpp_qm_query_portinfo_cmd_t))
		{
			rc = (rcvBytes < sizeof(unsigned short) ) ? 0 : rxbuf.result;
			cmm_print(DEBUG_STDERR, "ERROR: Unexpected result returned from FPP rc:%d\n", rc);
			return CLI_OK;
		}

		cmm_print(DEBUG_STDOUT, "Interface %s QoS Settings --\n", get_port_name(portnum, ifname, IFNAMSIZ));
		cmm_print(DEBUG_STDOUT, "Global QoS flag: %s\n", pQmQueryPortInfo->queue_qosenable_mask != 0 ? "Enabled" : "Disabled");

		/* If Qos disabled Ignore other configuration */
		if (!pQmQueryPortInfo->queue_qosenable_mask)
			continue;

		cmm_print(DEBUG_STDOUT, "\nShaper details:\n");
        	cmm_print(DEBUG_STDOUT, "IFG: %d\n", pQmQueryPortInfo->ifg);
		for (shapernum = -1; shapernum < FPP_NUM_SHAPERS; shapernum++)
		{
			memset(rxbuf.rcvBuffer, 0, 256);
#ifndef LS1043
			pQmQueryShaper->port = portnum;
#else
			strcpy(pQmQueryPortInfo->interface, port_table[portnum].ifname);
#endif
			pQmQueryShaper->shaper_num = shapernum;
			rcvBytes = cmmSendToDaemon(daemon_handle, FPP_CMD_QM_QUERY_SHAPER,
					pQmQueryShaper, sizeof(fpp_qm_query_shaper_cmd_t), rxbuf.rcvBuffer);
			if (rcvBytes != sizeof(fpp_qm_query_shaper_cmd_t))
			{
				rc = (rcvBytes < sizeof(unsigned short) ) ? 0 : rxbuf.result;
				cmm_print(DEBUG_STDERR, "ERROR: Unexpected result returned from FPP rc:%d\n", rc);
				return CLI_OK;
			}
			if (pQmQueryShaper->enabled)
			{
				if (shapernum < 0)
					cmm_print(DEBUG_STDOUT, "Port Shaper:\n");
				else
				{
					cmm_print(DEBUG_STDOUT, "Shaper %d:\n", shapernum);
					cmm_print(DEBUG_STDOUT, "    %s\n", get_queue_list(output_buf, pQmQueryShaper->qmask));
				}
				cmm_print(DEBUG_STDOUT, "    Rate (Kbps): %d\n", pQmQueryShaper->rate);
				if (pQmQueryShaper->bucket_size > 0)
					cmm_print(DEBUG_STDOUT, "    Bucket Size: %d\n", pQmQueryShaper->bucket_size);
			}
			else
			{
				if (shapernum < 0)
					cmm_print(DEBUG_STDOUT, "Port Shaper -- Disabled\n");
				else
					cmm_print(DEBUG_STDOUT, "Shaper %d -- Disabled\n", shapernum);
			}
		}

		cmm_print(DEBUG_STDOUT, "\nScheduler details:\n");
		for (schednum = 0; schednum < FPP_NUM_SCHEDULERS; schednum++)
		{
			char *alg = "None";
			memset(rxbuf.rcvBuffer, 0, 256);
#ifndef LS1043
			pQmQueryShaper->port = portnum;
#else
			strcpy(pQmQueryPortInfo->interface, port_table[portnum].ifname);
#endif
			pQmQuerySched->sched_num = schednum;
			rcvBytes = cmmSendToDaemon(daemon_handle, FPP_CMD_QM_QUERY_SCHED,
					pQmQuerySched, sizeof(fpp_qm_query_sched_cmd_t), rxbuf.rcvBuffer);
			if (rcvBytes != sizeof(fpp_qm_query_sched_cmd_t))
			{
				rc = (rcvBytes < sizeof(unsigned short) ) ? 0 : rxbuf.result;
				cmm_print(DEBUG_STDERR, "ERROR: Unexpected result returned from FPP rc:%d\n", rc);
				return CLI_OK;
			}
			cmm_print(DEBUG_STDOUT, "Scheduler %d:\n", schednum);
			cmm_print(DEBUG_STDOUT, "    %s\n", get_queue_list(output_buf, pQmQuerySched->qmask));
			switch (pQmQuerySched->alg)
             		{
	       		case 0:
				alg = "PQ";
				break;
	       		case 1:
				alg = "CBWFQ";
				break;
	       		case 2:
				alg = "DWRR";
				break;
			case 3:
				alg = "RR";
				break;
	    		}
			cmm_print(DEBUG_STDOUT, "    Algorithm: %s\n", alg);
		}

		cmm_print(DEBUG_STDOUT, "\nQueue details:\n");
		for (queuenum = 0; queuenum < FPP_NUM_QUEUES; queuenum++)
		{
			memset(rxbuf.rcvBuffer, 0, 256);
#ifndef LS1043
			pQmQueryShaper->port = portnum;
#else
			strcpy(pQmQueryPortInfo->interface, port_table[portnum].ifname);
#endif
			pQmQueryQueue->queue_num = queuenum;
			rcvBytes = cmmSendToDaemon(daemon_handle, FPP_CMD_QM_QUERY_QUEUE,
					pQmQueryQueue, sizeof(fpp_qm_query_queue_cmd_t), rxbuf.rcvBuffer);
			if (rcvBytes != sizeof(fpp_qm_query_queue_cmd_t))
			{
				rc = (rcvBytes < sizeof(unsigned short) ) ? 0 : rxbuf.result;
				cmm_print(DEBUG_STDERR, "ERROR: Unexpected result returned from FPP rc:%d\n", rc);
				return CLI_OK;
			}
			cmm_print(DEBUG_STDOUT, "Queue %d:\n", queuenum);
			if (pQmQueryQueue->qweight > 0)
				cmm_print(DEBUG_STDOUT, "    Weight: %d\n", pQmQueryQueue->qweight);
			cmm_print(DEBUG_STDOUT, "    Max Queue Depth: %d\n", pQmQueryQueue->max_qdepth);
		}

		cmm_print(DEBUG_STDOUT, "\n-----------------------------\n\n");
	}

#endif	// COMCERTO_2000

        return CLI_OK;

}


/************************************************************
 *
 *
 *
 ************************************************************/

#ifdef COMCERTO_2000
#define QRANGE "{0-15}"
#else
#define QRANGE "{0-31}"
#endif

void cmmQmSetPrintHelp()
{
	char buf[128];

	print_all_gemac_ports(buf, 128);

	cmm_print(DEBUG_STDOUT, 
		  "Usage: set qm interface {%s}\n"
		  "                                  reset\n"
                  "\n"
#ifdef COMCERTO_2000
		  "                                  qos {on | off}\n"
#else
		  "                                  qos\n"
                  "                                       [on | off]\n"
                  "                                       [max_txdepth {bytes}]\n"
                  "                                       [scheduler {pq|cbwfq|dwrr}] **\n"
                  "                                       [nhigh_queue {number of queues}] **\n"
                  "                                       [qweight {queue number} {weight}] **\n"
                  "                                       [qdepth {queue number} {depth}] **\n"
#endif
                  "\n"
#ifdef COMCERTO_2000
                  "                                  shaper {0-7 | port}\n"
#else
                  "                                  shaper {0-7}\n"
#endif
                  "                                       [on | off]\n"
                  "                                       [rate {Kbps}]\n"
                  "                                       [ifg {bytes}]\n"
                  "                                       [bucket_size {bits}]\n"
                  "                                       [queue " QRANGE "] [queue " QRANGE "] ...\n"                  
                  "\n"
                  "                                  scheduler {0-7}\n"
                  "                                       [algorithm {pq | cbwfq | dwrr | rr}]\n"
                  "                                       [queue " QRANGE "] [queue " QRANGE "] ...\n"                  
                  "\n"
                  "                                  queue " QRANGE "\n"                  
                  "                                       [qos {on | off}] \n"
                  "                                       [shaper {0-7}]\n"
                  "                                       [scheduler {0-7}]\n"
                  "                                       [qweight {weight}]\n"
                  "                                       [qdepth {depth}]\n"
                  "\n"
#ifndef COMCERTO_2000
                  "                                  rate_limiting {on|off} **\n"
                  "                                       [rate {Kbps}]\n"
                  "                                       [bucket_size {bits}]\n"
                  "                                       [queue " QRANGE "] [queue " QRANGE "] ...\n"                  
                  "\n"
		  "                                  ** Deprecated\n"
#endif

                  "\n"
#ifdef COMCERTO_2000
		    "       set qm expt_rate {eth|wifi|arp_ndp|pcap} {1000-5000000 or 0}\n"
#else
		    "       set qm expt_rate {1000-5000000 or 0}\n"
#endif
                  "\n"
		    "       set qm dscp_queue\n"
		    "						[queue {0-31}] \n"
                  "						[dscp {0-63}-{0-63}]  \n",

	          buf);
}

/************************************************************
 *
 *
 *
 ************************************************************/
int cmmQmSetProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle)
{
	int cpt = tabStart;
	unsigned int tmp, tmp1;
	unsigned int cmdToSend = 0; /* bits field*/
	char * endptr;
	unsigned char first_dscp = 0, last_dscp = 0, dscp_range = 0;
	int num_dscp = 0;
	int i;
	unsigned char dscp_value[FPP_NUM_DSCP] = {0};


	
	fpp_qm_qos_enable_cmd_t enableCmd;
	fpp_qm_qos_alg_cmd_t algCmd;
	fpp_qm_nhigh_cmd_t nHighCmd;
	fpp_qm_max_qdepth_cmd_t maxQdepthCmd;
	fpp_qm_max_txdepth_cmd_t maxTxDepthCmd;
	fpp_qm_max_weight_cmd_t maxWeightCmd;
	fpp_qm_rate_limit_cmd_t rateLimitCmd;
	fpp_qm_expt_rate_cmd_t exptRateCmd;
	fpp_qm_scheduler_cfg_t schedulerCmd;
	fpp_qm_shaper_cfg_t shaperCmd;
	fpp_qm_reset_cmd_t resetCmd;
	fpp_qm_dscp_queue_mod_t dscpCmd;
	fpp_qm_queue_qos_enable_cmd_t queueenableCmd;
    
	union u_rxbuf rxbuf;

	memset(&enableCmd, 0, sizeof(enableCmd));
	memset(&algCmd, 0, sizeof(algCmd));
	memset(&nHighCmd, 0, sizeof(nHighCmd));
	memset(&maxQdepthCmd, 0, sizeof(maxQdepthCmd));
	memset(&maxTxDepthCmd, 0, sizeof(maxTxDepthCmd));
	memset(&maxWeightCmd, 0, sizeof(maxWeightCmd));
	memset(&rateLimitCmd, 0, sizeof(rateLimitCmd));
	memset(&exptRateCmd, 0, sizeof(exptRateCmd));
	memset(&schedulerCmd, 0, sizeof(schedulerCmd));
	memset(&shaperCmd, 0, sizeof(shaperCmd));
	memset(&resetCmd, 0, sizeof(resetCmd));
	memset(&dscpCmd, 0, sizeof(dscpCmd));
	memset(&queueenableCmd, 0, sizeof(queueenableCmd));


	if(!keywords[cpt])
		goto help;

	if(strcasecmp(keywords[cpt], "interface") == 0)
	{
		int port_id;

		if(!keywords[++cpt])
			goto help;

		if ((port_id = get_port_id(keywords[cpt])) >= 0)
		{
#ifndef LS1043
			enableCmd.interface = port_id;
			algCmd.interface = port_id;
			nHighCmd.interface = port_id;
			maxQdepthCmd.interface = port_id;
			maxTxDepthCmd.interface = port_id;
			maxWeightCmd.interface = port_id;
			rateLimitCmd.interface = port_id;
			shaperCmd.interface = port_id;
			schedulerCmd.interface = port_id;
			resetCmd.interface = port_id;
			queueenableCmd.interface = port_id;
#else
			STR_TRUNC_COPY(enableCmd.interface, keywords[cpt], sizeof(enableCmd.interface));
			STR_TRUNC_COPY(algCmd.interface, keywords[cpt], sizeof(algCmd.interface));
			STR_TRUNC_COPY(nHighCmd.interface, keywords[cpt], sizeof(nHighCmd.interface));
			STR_TRUNC_COPY(maxQdepthCmd.interface, keywords[cpt], sizeof(maxQdepthCmd.interface));
			STR_TRUNC_COPY(maxTxDepthCmd.interface, keywords[cpt], sizeof(maxTxDepthCmd.interface));
			STR_TRUNC_COPY(maxWeightCmd.interface, keywords[cpt], sizeof(maxWeightCmd.interface));
			STR_TRUNC_COPY(rateLimitCmd.interface, keywords[cpt], sizeof(rateLimitCmd.interface));
			STR_TRUNC_COPY(shaperCmd.interface, keywords[cpt], sizeof(shaperCmd.interface));
			STR_TRUNC_COPY(schedulerCmd.interface, keywords[cpt], sizeof(schedulerCmd.interface));
			STR_TRUNC_COPY(resetCmd.interface, keywords[cpt], sizeof(resetCmd.interface));
			STR_TRUNC_COPY(queueenableCmd.interface, keywords[cpt], sizeof(queueenableCmd.interface));
#endif
		}
		else
			goto keyword_error;
	}
	else if(strcasecmp(keywords[cpt], "expt_rate") == 0)
	{
		if(!keywords[++cpt])
			goto help;
		memset(&exptRateCmd, 0, sizeof(exptRateCmd));

#ifdef COMCERTO_2000
		if(strcasecmp(keywords[cpt], "eth") == 0 )
			exptRateCmd.if_type = FPP_EXPT_TYPE_ETH;
		else if (strcasecmp(keywords[cpt], "wifi") == 0 )
			exptRateCmd.if_type = FPP_EXPT_TYPE_WIFI;
		else if (strcasecmp(keywords[cpt], "arp_ndp") == 0 )
			exptRateCmd.if_type = FPP_EXPT_TYPE_ARP;
		else if (strcasecmp(keywords[cpt], "pcap") == 0 )
			exptRateCmd.if_type = FPP_EXPT_TYPE_PCAP;
		else
			goto help;

		if(!keywords[++cpt])
			goto help;
#endif

		/*Get an integer from the string*/
		endptr = NULL;
		tmp = strtoul(keywords[cpt], &endptr, 0);
		if ((keywords[cpt] == endptr) || (tmp != 0 && (tmp < 1000 || tmp > 5000000)))
		{
			cmm_print(DEBUG_CRIT, "CMD_QM_EXPT_RATE ERROR: rate must be zero (to disable) or a number between 1000 and 5000000\n");
			goto help;
		}
		if(keywords[++cpt])
			goto help;
		exptRateCmd.pkts_per_msec = tmp / 1000;
		// Send CMD_QM_EXPT_RATE command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_EXPT_RATE, &exptRateCmd, sizeof(exptRateCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_EXPT_RATE", ERRMSG_SOURCE_FPP,rxbuf.rcvBuffer);
		}
		return 0;
	}
	else if(strcasecmp(keywords[cpt], "dscp_queue") == 0)
	{
		if(!keywords[++cpt])
			goto help;

		if(strcasecmp(keywords[cpt], "queue") == 0)
		{
			if(!keywords[++cpt])
				goto help;

			 /*Get an integer from the string*/
			endptr = NULL;
			tmp = strtoul(keywords[cpt], &endptr, 0);
			if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_QUEUES))
			{
				cmm_print(DEBUG_STDERR, "dscp_queue ERROR: selected queue must be a number between 0 and %d\n", (FPP_NUM_QUEUES-1));
				goto help;
			}
			dscpCmd.queue = tmp;
			cmm_print(DEBUG_INFO, "dscp_queue - queue %d selected\n", dscpCmd.queue);

			if(!keywords[++cpt])
				goto help;
		}
		else
		   goto keyword_error;

		if(strcasecmp(keywords[cpt], "dscp") == 0)
		{
			/* get list of dscp values assigned to the selected queue */
			if(!keywords[++cpt])
				goto help;
			num_dscp = 0;
			first_dscp = 0;
			cmm_print(DEBUG_INFO, "dscp_queue - parsing dscp list for queue %d\n", dscpCmd.queue);
			while(keywords[cpt] && (num_dscp < FPP_NUM_DSCP))
			{
				cmm_print(DEBUG_INFO, "dscp_queue - processing arg '%s' \n", keywords[cpt]);
				if(strcasecmp(keywords[cpt], "-") == 0)
				{
					dscp_range = 1;
					cmm_print(DEBUG_INFO, "dscp_queue - dscp range detected\n");
				}
				else
				{
					endptr = NULL;
					tmp = strtoul(keywords[cpt], &endptr, 0);
					if ((keywords[cpt] == endptr) || (tmp > FPP_MAX_DSCP))
					{
						cmm_print(DEBUG_STDERR, "dscp_queue ERROR: DSCP value out of range\n");
						goto help;
					}
					else
					{
						cmm_print(DEBUG_INFO, "dscp_queue - one more dscp added\n");
						/* save low-end dscp value i.e. the first value specified*/
						if(num_dscp == 0)
							first_dscp = tmp;
						last_dscp = tmp; /* save high end dscp i.e. the last one specified*/
						dscp_value[num_dscp++] = tmp;
					}
				}
				cpt++;
			}

			/* no dscp specified means all dscp */
			if(num_dscp == 0) 
			{
				for(i = 0; i < FPP_NUM_DSCP; i++)
					dscpCmd.dscp[i] = i;
				dscpCmd.num_dscp = FPP_NUM_DSCP;
				cmm_print(DEBUG_INFO, "dscp_queue - all dscp assigned\n");
			}
			else if (dscp_range)
			{
				if(last_dscp <= first_dscp)
				{
					cmm_print(DEBUG_STDERR, "dscp_queue: wrong DSCP range\n");
					goto help;
				}
				for(i = first_dscp; i <= last_dscp; i++)
					dscpCmd.dscp[i - first_dscp] = i;
				dscpCmd.num_dscp = (last_dscp - first_dscp) + 1; 
				cmm_print(DEBUG_INFO, "dscp_queue - dscp range %d to %d\n", first_dscp, last_dscp);
			}
			else
			{
				cmm_print(DEBUG_INFO, "dscp_queue - dscp non-ordered list\n");
				dscpCmd.num_dscp = num_dscp;
				for(i = 0; i < dscpCmd.num_dscp; i++)
					dscpCmd.dscp[i] = dscp_value[i];
			}
			cmm_print(DEBUG_INFO, "dscp_queue - %d dscp assigned ->\n", dscpCmd.num_dscp);
			for(i = 0; i < dscpCmd.num_dscp; i++)
				cmm_print(DEBUG_INFO, "%d ", dscpCmd.dscp[i]);
			cmm_print(DEBUG_INFO, "\n");

			if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_DSCP_MAP, &dscpCmd, sizeof(fpp_qm_dscp_queue_mod_t), rxbuf.rcvBuffer) == 2)
			{
				if (rxbuf.result != 0)
					showErrorMsg("CMD_QM_DSCP_MAP", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
				return (rxbuf.result);
			}
		}
		else {
			cmm_print(DEBUG_STDERR, "ERROR: Unknown keyword %s\n", keywords[cpt]);
			goto help;
		}

		return 0;
	}
	else
		goto keyword_error;

	if(!keywords[++cpt])
		goto help;
	
	if(strcasecmp(keywords[cpt], "qos") == 0)
	{		
		if(!keywords[++cpt])
			goto help;
		
		while (keywords[cpt] != NULL)
		{
			if(strcasecmp(keywords[cpt], "on") == 0)
			{
				cmdToSend |= CMD_BIT(FPP_CMD_QM_QOSENABLE);
				enableCmd.enable = 1;
			}
			else if(strcasecmp(keywords[cpt], "off") == 0)
			{
				cmdToSend |= CMD_BIT(FPP_CMD_QM_QOSENABLE);
				enableCmd.enable = 0;
			}
			else if(strcasecmp(keywords[cpt], "scheduler") == 0)
			{
				if(!keywords[++cpt])
					goto help;


				cmdToSend |= CMD_BIT(FPP_CMD_QM_QOSALG);

				if(strcasecmp(keywords[cpt], "pq") == 0)
				{
					algCmd.scheduler = 0;
				}
				else if (strcasecmp(keywords[cpt], "cbwfq") == 0)
				{
					algCmd.scheduler = 1;
				}
				else if (strcasecmp(keywords[cpt], "dwrr") == 0)
				{
					algCmd.scheduler = 2;
				}
				else
					goto keyword_error;
			}
			else if(strcasecmp(keywords[cpt], "nhigh_queue") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_QUEUES))
				{
					cmm_print(DEBUG_CRIT, "qos ERROR: nhigh_queue must be a number between 0 and %d \n", (FPP_NUM_QUEUES -1));
					goto help;
				}

				nHighCmd.number_high_queues = tmp;
				
				cmdToSend |= CMD_BIT(FPP_CMD_QM_NHIGH);
			}
			else if(strcasecmp(keywords[cpt], "max_txdepth") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || tmp < 1 || (tmp > USHRT_MAX))
				{
					cmm_print(DEBUG_CRIT, "qos ERROR: max_txdepth must be a number between 1 and %d\n", USHRT_MAX);
					goto help;
				}
		
				maxTxDepthCmd.max_bytes = tmp;

				cmdToSend |= CMD_BIT(FPP_CMD_QM_MAX_TXDEPTH);
			}
			else if(strcasecmp(keywords[cpt], "qweight") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_QUEUES))
				{
					cmm_print(DEBUG_STDERR, "qos ERROR: queue must be a number between 0 and %d \n", (FPP_NUM_QUEUES -1) );
					goto help;
				}
				
				if(!keywords[++cpt])
					goto help;
				
				/*Get an integer from the string*/
				endptr = NULL;
				tmp1 = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || tmp1 < 1 || (tmp1 > USHRT_MAX))
				{
					cmm_print(DEBUG_STDERR, "qos ERROR: weight must be a number between 1 and %d\n", USHRT_MAX);
					goto help;
				}
				
				maxWeightCmd.qxweight[tmp] = tmp1;
				cmdToSend |= CMD_BIT(FPP_CMD_QM_MAX_WEIGHT);
			}

			else if(strcasecmp(keywords[cpt], "qdepth") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_QUEUES))
				{
					cmm_print(DEBUG_STDERR, "qos ERROR: queue must be a number between 0 and %d \n", (FPP_NUM_QUEUES -1));
					goto help;
				}
				
				if(!keywords[++cpt])
					goto help;
				
				/*Get an integer from the string*/
				endptr = NULL;
				tmp1 = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || tmp1 < 1 || (tmp1 > USHRT_MAX))
				{
					cmm_print(DEBUG_STDERR, "qos ERROR: depth must be a number between 1 and %d\n", USHRT_MAX);
					goto help;
				}
				
				maxQdepthCmd.qtxdepth[tmp] = tmp1;
				cmdToSend |= CMD_BIT(FPP_CMD_QM_MAX_QDEPTH);
			}
			else
				goto keyword_error;

			cpt++;
		}
	}
	else if(strcasecmp(keywords[cpt], "rate_limiting") == 0)
	{
		if(!keywords[++cpt])
			goto help;
		
		if(strcasecmp(keywords[cpt], "on") == 0)
		{
			cmdToSend |= CMD_BIT(FPP_CMD_QM_RATE_LIMIT);
			rateLimitCmd.enable = 1;
	
			cpt++;
			while (keywords[cpt] != NULL)
			{
				if(strcasecmp(keywords[cpt], "queue") == 0)
				{
					if(!keywords[++cpt])
						goto help;

					/*Get an integer from the string*/
					endptr = NULL;
					tmp = strtoul(keywords[cpt], &endptr, 0);
					if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_QUEUES))
					{
						cmm_print(DEBUG_CRIT, "rate_limiting ERROR: queue must be a number between 0 and %d \n", (FPP_NUM_QUEUES -1));
						goto help;
					}

					rateLimitCmd.queues |= (1 << tmp);
				}
				else if(strcasecmp(keywords[cpt], "rate") == 0)
				{
					if(!keywords[++cpt])
						goto help;

					/*Get an integer from the string*/
					endptr = NULL;
					tmp = strtoul(keywords[cpt], &endptr, 0);
					if ((keywords[cpt] == endptr) || (tmp < 8) || (tmp > ULONG_MAX))
					{
						cmm_print(DEBUG_CRIT, "rate_limiting ERROR: rate must be a number between 8 and %d (Kbps)\n", (unsigned int)ULONG_MAX);
						goto help;
					}

					rateLimitCmd.rate = tmp;
				}
				else if(strcasecmp(keywords[cpt], "bucket_size") == 0)
				{
					if(!keywords[++cpt])
						goto help;

					/*Get an integer from the string*/
					endptr = NULL;
					tmp = strtoul(keywords[cpt], &endptr, 0);
					if ((keywords[cpt] == endptr) || (tmp < 8) || (tmp > ULONG_MAX))
					{
						cmm_print(DEBUG_CRIT, "rate_limiting ERROR: bucket_size must be a number between 8 and %d\n", (unsigned int)ULONG_MAX);
						goto help;
					}

					rateLimitCmd.bucket_size = tmp;
				}
				else
					goto keyword_error;
			
				cpt++;
			}

			/*Dependencies check*/
			if (rateLimitCmd.queues == 0)
			{
				cmm_print(DEBUG_CRIT, "Rate Limiting ERROR: At least one queue must be specified\n");
				goto help;
			}
			
			if(rateLimitCmd.rate == 0)
			{
				cmm_print(DEBUG_CRIT, "Rate Limiting ERROR: The bandwidth have to be specified\n");
				goto help;
			}
		}
		else if(strcasecmp(keywords[cpt], "off") == 0)
		{
			cmdToSend |= CMD_BIT(FPP_CMD_QM_RATE_LIMIT);
			rateLimitCmd.enable = 0;
		}
		else
			goto keyword_error;
		
	}
	else if(strcasecmp(keywords[cpt], "shaper") == 0)
	{
		if(!keywords[++cpt])
			goto help;

		/*Get an integer from the string*/
#if defined(COMCERTO_2000) || defined(LS1043)
		if (strcasecmp(keywords[cpt], "port") == 0)
		{
			tmp = FPP_PORT_SHAPER_NUM;
		}
		else
#endif
		{
			endptr = NULL;
			tmp = strtoul(keywords[cpt], &endptr, 0);
			if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_SHAPERS))
			{
				cmm_print(DEBUG_CRIT, "shaper ERROR: shaper number must be between 0 and %d\n", FPP_NUM_SHAPERS);
				goto help;
			}
		}

		shaperCmd.shaper = tmp;
		
		if(!keywords[++cpt])
			goto help;

		cmdToSend |= CMD_BIT(FPP_CMD_QM_SHAPER_CFG);

		while (keywords[cpt] != NULL)
		{
			if(strcasecmp(keywords[cpt], "on") == 0)
			{
				shaperCmd.enable = 1;
			}
			else if(strcasecmp(keywords[cpt], "off") == 0)
			{
				shaperCmd.enable = 2;
			}
			else if(strcasecmp(keywords[cpt], "queue") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_QUEUES))
				{
					cmm_print(DEBUG_CRIT, "shaper ERROR: queue must be a number between 0 and %d \n", (FPP_NUM_QUEUES -1));
					goto help;
				}

				shaperCmd.queues |= (1 << tmp);
			}
			else if(strcasecmp(keywords[cpt], "ifg") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp > 255))
				{
					cmm_print(DEBUG_CRIT, "shaper ERROR: ifg must be a number between 0 and 255\n");
					goto help;
				}

				shaperCmd.ifg = tmp;
				shaperCmd.ifg_change_flag = 1;
			}
			else if(strcasecmp(keywords[cpt], "rate") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				/* Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
                                if ((keywords[cpt] == endptr) || (tmp < 8) || (tmp > ULONG_MAX))
                                {
                                        cmm_print(DEBUG_CRIT, "shaper ERROR: rate must be a number between 8 and %d (Kbps)\n", (unsigned int)ULONG_MAX);
                                        goto help;
                                }


				shaperCmd.rate = tmp;
			}
			else if(strcasecmp(keywords[cpt], "bucket_size") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp < 8) || (tmp > ULONG_MAX))
				{
					cmm_print(DEBUG_CRIT, "shaper ERROR: bucket_size must be a number between 8 and %d\n", (unsigned int)ULONG_MAX);
					goto help;
				}

				shaperCmd.bucket_size = tmp;
			}
			else
				goto keyword_error;
		
			cpt++;
		}
	}
	else if(strcasecmp(keywords[cpt], "scheduler") == 0)
	{
		if(!keywords[++cpt])
			goto help;

		/*Get an integer from the string*/
		endptr = NULL;
		tmp = strtoul(keywords[cpt], &endptr, 0);
		if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_SCHEDULERS))
		{
			cmm_print(DEBUG_CRIT, "scheduler ERROR: scheduler number must be between 0 and 3\n");
			goto help;
		}

		schedulerCmd.scheduler = tmp;
		
		if(!keywords[++cpt])
			goto help;

		cmdToSend |= CMD_BIT(FPP_CMD_QM_SCHED_CFG);
	
		while (keywords[cpt] != NULL)
		{
			if(strcasecmp(keywords[cpt], "queue") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_QUEUES))
				{
					cmm_print(DEBUG_CRIT, "scheduler ERROR: queue must be a number between 0 and %d \n", (FPP_NUM_QUEUES -1));
					goto help;
				}

				schedulerCmd.queues |= (1 << tmp);
			}
			else if(strcasecmp(keywords[cpt], "algorithm") == 0)
			{
				if(!keywords[++cpt])
					goto help;

				if(strcasecmp(keywords[cpt], "pq") == 0)
				{
					schedulerCmd.algo = 0;
					schedulerCmd.algo_change_flag = 1;
				}
				else if (strcasecmp(keywords[cpt], "cbwfq") == 0)
				{
					schedulerCmd.algo = 1;
					schedulerCmd.algo_change_flag = 1;
				}
				else if (strcasecmp(keywords[cpt], "dwrr") == 0)
				{
					schedulerCmd.algo = 2;
					schedulerCmd.algo_change_flag = 1;
				}
				else if (strcasecmp(keywords[cpt], "rr") == 0)
				{
					schedulerCmd.algo = 3;
					schedulerCmd.algo_change_flag = 1;
				}
				else
					goto keyword_error;
			}			
			else
				goto keyword_error;
		
			cpt++;
		}

	}

	else if(strcasecmp(keywords[cpt], "queue") == 0)
	{
		unsigned int qmask=0; /* Bit mask of single or set of queues that are programmed */

		if(!keywords[++cpt])
			goto help;

		/*Get an integer from the string*/
		endptr = NULL;
		tmp = strtoul(keywords[cpt], &endptr, 0);
		if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_QUEUES))
		{
			cmm_print(DEBUG_CRIT, "queue ERROR: queue must be a number between 0 and %d\n", (FPP_NUM_QUEUES-1));
			goto help;
		}
		qmask |= (1<<tmp);

		if(!keywords[++cpt])
			goto help;

		while (keywords[cpt] != NULL)
		{
			if(strcasecmp(keywords[cpt], "queue") == 0)
			{
			       if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_QUEUES))
				{
					cmm_print(DEBUG_CRIT, "queue ERROR: queue must be a number between 0 and %d \n", (FPP_NUM_QUEUES -1));
					goto help;
				}

				qmask |= (1<<tmp);
			}
			else if(strcasecmp(keywords[cpt], "qos") == 0)
			{
				if (qmask ==0)
				{
					cmm_print(DEBUG_CRIT, "queue ERROR: One or more queues need to be specified \n");
					goto help;
				}
				
				if(!keywords[++cpt])
					goto help;
		
				
				if(strcasecmp(keywords[cpt], "on") == 0)
					queueenableCmd.enable_flag = 1;
				else if(strcasecmp(keywords[cpt], "off") == 0)
					queueenableCmd.enable_flag = 0;
				
				queueenableCmd.queue_qosenable_mask = qmask;
				cmdToSend |= CMD_BIT(FPP_CMD_QM_QUEUE_QOSENABLE);
				
			}
			else if(strcasecmp(keywords[cpt], "shaper") == 0)
			{
				if (qmask ==0)
				{
					cmm_print(DEBUG_CRIT, "queue ERROR: One or more queues need to be specified \n");
					goto help;
				}
				
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_SHAPERS))
				{
					cmm_print(DEBUG_CRIT, "queue ERROR: shaper number must be between 0 and 4\n");
					goto help;
				}

				shaperCmd.shaper = tmp;
				shaperCmd.queues = qmask;
				cmdToSend |= CMD_BIT(FPP_CMD_QM_SHAPER_CFG);
			}
			else if(strcasecmp(keywords[cpt], "scheduler") == 0)
			{
				if (qmask ==0)
				{
					cmm_print(DEBUG_CRIT, "queue ERROR: One or more queues need to be specified \n");
					goto help;
				}
				
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || (tmp >= FPP_NUM_SCHEDULERS))
				{
					cmm_print(DEBUG_CRIT, "queue ERROR: scheduler number must be between 0 and 3\n");
					goto help;
				}

				schedulerCmd.scheduler = tmp;
				schedulerCmd.queues = qmask;
				cmdToSend |= CMD_BIT(FPP_CMD_QM_SCHED_CFG);
			}
			else if(strcasecmp(keywords[cpt], "qweight") == 0)
			{
				if (qmask ==0)
				{
					cmm_print(DEBUG_CRIT, "queue ERROR: One or more queues need to be specified \n");
					goto help;
				}
				
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp1 = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || tmp1 < 1 || (tmp1 > USHRT_MAX))
				{
					cmm_print(DEBUG_STDERR, "queue ERROR: weight must be a number between 1 and %d\n", USHRT_MAX);
					goto help;
				}

				for(i=0; i < FPP_NUM_QUEUES; i++) {
					if(qmask & (1 << i))
						maxWeightCmd.qxweight[i] = tmp1;
				}
				cmdToSend |= CMD_BIT(FPP_CMD_QM_MAX_WEIGHT);
			}

			else if(strcasecmp(keywords[cpt], "qdepth") == 0)
			{
				if (qmask ==0)
				{
					cmm_print(DEBUG_CRIT, "queue ERROR: One or more queues need to be specified \n");
					goto help;
				}
				
				if(!keywords[++cpt])
					goto help;

				/*Get an integer from the string*/
				endptr = NULL;
				tmp1 = strtoul(keywords[cpt], &endptr, 0);
				if ((keywords[cpt] == endptr) || tmp1 < 1 || (tmp1 > USHRT_MAX))
				{
					cmm_print(DEBUG_STDERR, "queue ERROR: depth must be a number between 1 and %d\n", USHRT_MAX);
					goto help;
				}

				for(i=0; i < FPP_NUM_QUEUES; i++) {
					if(qmask & (1 << i))
						maxQdepthCmd.qtxdepth[i] = tmp1;
				}
				cmdToSend |= CMD_BIT(FPP_CMD_QM_MAX_QDEPTH);
			}
			else
				goto keyword_error;
		
			cpt++;
		}

	}

	else if(strcasecmp(keywords[cpt], "reset") == 0)
	{
		if(keywords[++cpt])
			goto help;

		cmdToSend |= CMD_BIT(FPP_CMD_QM_RESET);	
	}
	else
		goto keyword_error;

	/*
	 * Parsing have been performed
	 * Now send the right commands
	 */

	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_RESET))
	{
		// Send CMD_QM_RATE_LIMIT command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_RESET, &resetCmd, sizeof(resetCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_RESET", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}
	
	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_QOSENABLE))
	{
		// Send CMD_QM_QOSENABLE command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_QOSENABLE, & enableCmd, sizeof(enableCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_QOSENABLE", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}

	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_QUEUE_QOSENABLE))
	{
		// Send FPP_CMD_QM_QUEUE_QOSENABLE command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_QUEUE_QOSENABLE, &queueenableCmd, sizeof(queueenableCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_QUEUE_QOSENABLE", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}
	
	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_QOSALG))
	{
		// Send CMD_QM_QOSALG command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_QOSALG, & algCmd, sizeof(algCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_QOSALG", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}

	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_NHIGH))
	{
		// Send CMD_QM_NHIGH command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_NHIGH, & nHighCmd, sizeof(nHighCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_NHIGH", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}

	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_MAX_TXDEPTH))
	{
		// Send CMD_QM_MAX_TXDEPTH command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_MAX_TXDEPTH, &maxTxDepthCmd, sizeof(maxTxDepthCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_MAX_TXDEPTH", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}

	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_MAX_QDEPTH))
	{
		// Send CMD_QM_MAX_QDEPTH command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_MAX_QDEPTH, & maxQdepthCmd , sizeof(maxQdepthCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_MAX_QDEPTH", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}

	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_MAX_WEIGHT))
	{
		// Send CMD_QM_MAX_WEIGHT command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_MAX_WEIGHT, &maxWeightCmd , sizeof(maxWeightCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_MAX_WEIGHT", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}

	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_RATE_LIMIT))
	{
		// Send CMD_QM_RATE_LIMIT command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_RATE_LIMIT, &rateLimitCmd, sizeof(rateLimitCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_RATE_LIMIT", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}

	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_SHAPER_CFG))
	{
		// Send CMD_QM_RATE_LIMIT command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_SHAPER_CFG, &shaperCmd, sizeof(shaperCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_SHAPER_CFG", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}

	if(TEST_CMD_BIT(cmdToSend, FPP_CMD_QM_SCHED_CFG))
	{
		// Send CMD_QM_RATE_LIMIT command
		if(cmmSendToDaemon(daemon_handle, FPP_CMD_QM_SCHED_CFG, &schedulerCmd, sizeof(schedulerCmd), &rxbuf.rcvBuffer) == 2)
		{
			if (rxbuf.result != 0)
				showErrorMsg("CMD_QM_SCHED_CFG", ERRMSG_SOURCE_FPP, rxbuf.rcvBuffer);
		}
	}

	return 0;

keyword_error:
	cmm_print(DEBUG_CRIT, "ERROR: Unknown keyword %s\n", keywords[cpt]);

help:
	cmmQmSetPrintHelp();
	return -1;
}


void cmmQmResetQ2Prio(fpp_qm_reset_cmd_t *cmdp, int cmdlen)
{
	u_int16_t interface;
	char fname[128], ifname[IFNAMSIZ];
	FILE *fp;

	if (cmdlen != sizeof(fpp_qm_reset_cmd_t))
	{
		cmm_print(DEBUG_ERROR, "%s: Wrong length for cmd, expected %d, got %d\n", __func__,
						sizeof(fpp_qm_scheduler_cfg_t), cmdlen);
		return;
	}

	interface = cmdp->interface;

	snprintf(fname, 128, "/sys/class/net/%s/q2prio", get_port_name(interface, ifname, IFNAMSIZ));
	fp = fopen(fname, "w");
	if (!fp)
	{
		cmm_print(DEBUG_WARNING, "%s: Cannot open %s\n", __func__, fname);
		return;
	}
	fprintf(fp, "reset\n");
	fclose(fp);
}


void cmmQmUpdateQ2Prio(fpp_qm_scheduler_cfg_t *cmdp, int cmdlen)
{
	u_int16_t interface;
        u_int16_t scheduler;
        u_int32_t queues;
	char fname[128], ifname[IFNAMSIZ];
	FILE *fp;

	if (cmdlen != sizeof(fpp_qm_scheduler_cfg_t))
	{
		cmm_print(DEBUG_ERROR, "%s: Wrong length for cmd, expected %d, got %d\n", __func__,
						sizeof(fpp_qm_scheduler_cfg_t), cmdlen);
		return;
	}

	interface = cmdp->interface;
	scheduler = cmdp->scheduler;
	queues = cmdp->queues;

	snprintf(fname, 128, "/sys/class/net/%s/q2prio", get_port_name(interface, ifname, IFNAMSIZ));
	fp = fopen(fname, "w");
	if (!fp)
	{
		cmm_print(DEBUG_WARNING, "%s: Cannot open %s\n", __func__, fname);
		return;
	}
	fprintf(fp, "%d 0x%x\n", scheduler, queues);
	fclose(fp);
}
