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

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "libcmm.h"
#include "cmmd.h"
#include "fpp.h"

int main()
{
	cmm_command_t		cmd;
	cmm_response_t		res;
	fpp_rtcp_query_cmd_t 	*rtcp_cmd;
	fpp_rtcp_query_res_t    *rtcp_res;
	cmm_handle_t  		*handle;
	int rc = 0;

	memset(&cmd, 0 , sizeof(cmd));
	memset(&res, 0 , sizeof(res));

	handle = cmm_open();
	if (!handle) {
		printf("Error opening CMM\n");
		return -1;
	}

	cmd.func = FPP_CMD_RTCP_QUERY;
	cmd.length = sizeof(fpp_rtcp_query_cmd_t);
	rtcp_cmd = (fpp_rtcp_query_cmd_t*)&cmd.buf;
	rtcp_cmd->socket_id = 1;

	if (cmm_send(handle, &cmd, 0) != 0) {
		printf("Error sending message to CMM, error = `%s'\n", strerror(errno));
		rc = -1;
		goto close;
	}

	if (cmm_recv(handle, &res, 0) < 0) {
		printf("Error receiving message from CMM, error = `%s'\n", strerror(errno));
		rc = -1;
		goto close;
	}

	if (res.rc != FPP_ERR_OK) {
		printf("Error from CMM, error = `%d'\n", res.rc);
		rc = -1;
		goto close;
	}

	// message handling goes here
	rtcp_res = (fpp_rtcp_query_res_t*)&res.buf;
	printf("RTCP Statistics\n\n"
               "prev_reception_period	: %uld\n"
               "last_reception_period	: %uld\n"
               "num_tx_pkts		: %uld\n"
               "num_rx_pkts 		: %uld\n"
               "last_rx_seq		: %uld\n"
               "last_rx_ts		: %uld\n"
               "num_dup_rx		: %uld\n"
               "num_rx_since_rtcp	: %uld\n"
               "num_tx_bytes		: %uld\n",
               rtcp_res->prev_reception_period,
               rtcp_res->last_reception_period,
               rtcp_res->num_tx_pkts,
               rtcp_res->num_rx_pkts,
               rtcp_res->last_rx_seq,
               rtcp_res->last_rx_timestamp,
               rtcp_res->num_rx_dup,
               rtcp_res->num_rx_since_rtcp,
               rtcp_res->num_tx_bytes);
        
close:
	cmm_close(handle);
	return rc;
}

