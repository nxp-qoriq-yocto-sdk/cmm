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


#ifndef __MODULE_ROUTE_H__
#define __MODULE_ROUTE_H__

	void cmmRouteShowPrintHelp();
	int cmmRouteShowProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
	void cmmRouteSetPrintHelp();
	int cmmRouteSetProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
	int cmmRouteProcessClientCmd(FCI_CLIENT* fciMsgHandler, int function_code, u_int8_t *cmd_buf, u_int16_t *res_buf, u_int16_t *res_len);
	struct RtEntry *cmmPolicyRouting(unsigned int srcip, unsigned int dstip, unsigned short proto, unsigned short sport, unsigned short dport);

#endif

