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


#ifndef __MODULE_PKTCAP_H__
#define __MODULE_PKTCAP_H__
#include "fpp.h"

#define CMD_PKTCAP_IFSTATUS	FPP_CMD_PKTCAP_IFSTATUS	
#define CMD_PKTCAP_SLICE	FPP_CMD_PKTCAP_SLICE	
#define CMD_PKTCAP_FLF          FPP_CMD_PKTCAP_FLF

#define PKTCAP_IFSTATUS_ENABLE  0x1
#define PKTCAP_IFSTATUS_DISABLE 0x0



int PktCapSliceProcess(daemon_handle_t daemon_handle, int argc, char *argv[]);

int PktCapStatProcess(daemon_handle_t daemon_handle, int argc, char *argv[]);

int PktCapFilterProcess(daemon_handle_t daemon_handle, int argc, char *argv[]);

int PktCapQueryProcess(struct cli_def *cli, daemon_handle_t daemon_handle);

int Check_BPFfilter(struct bpf_insn *filter, int flen);

#endif
