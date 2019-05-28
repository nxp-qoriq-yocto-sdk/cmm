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


#ifndef __MODULE_VLAN_H__
#define __MODULE_VLAN_H__

	#include "itf.h"

	void __cmmGetVlan(int fd, struct interface *itf);
	int cmmFeVLANUpdate(FCI_CLIENT *fci_handle, int request, struct interface *itf);
	void cmmVlanReset(FCI_CLIENT *fci_handle);
	int cmmVlanLocalShow(struct cli_def *cli, char *command, char *argv[], int argc);
	int cmmVlanCheckPolicy(struct interface *itf);

/* remote command processing */
	int vlanAddProcess(daemon_handle_t daemon_handle, int argc, char *argv[]);
	int vlanDeleteProcess(daemon_handle_t daemon_handle, int argc, char *argv[]);
	int cmmVlanClient(int argc, char **argv, int firstarg, daemon_handle_t daemon_handle);
	int cmmVlanProcessClientCmd(FCI_CLIENT *fci_handle, int function_code, u_int8_t *cmd_buf, u_int16_t cmd_len, u_int16_t *res_buf, u_int16_t *res_len);
	int cmmVlanQuery(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
#endif

