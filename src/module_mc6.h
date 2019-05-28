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


#ifndef __MODULE_MC6_H__
#define __MODULE_MC6_H__

	void cmmMc6ShowPrintHelp();
	int cmmMc6ShowProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
	int cmmMc6QueryProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
	void cmmMc6SetPrintHelp();
	int cmmMc6SetProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
	int cmmMc6ProcessClientCmd(FCI_CLIENT* fciMsgHandler, int function_code, u_int8_t *cmd_buf, u_int16_t cmd_len, u_int16_t *res_buf, u_int16_t *res_len);
	int cmmMc6Show(struct cli_def * cli, char *command, char *argv[], int argc);

	extern  int parse_macaddr(char *pstring, unsigned char *pmacaddr);


#endif
