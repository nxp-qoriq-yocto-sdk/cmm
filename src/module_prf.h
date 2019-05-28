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


#ifndef __MODULE_PRF_H__
#define __MODULE_PRF_H__

/*Function codes*/
#define FPP_CMD_TRC_MASK                            0xff00
#define FPP_CMD_TRC_VAL                             0x0f00

int cmmPrfMem(int argc,char **argv,int firstarg ,daemon_handle_t daemon_handle);
int cmmPrfNM(int argc,char **argv,int firstarg ,daemon_handle_t daemon_handle);
int prfMspMS(daemon_handle_t daemon_handle, int argc, char **argv);
int prfMspMSW(daemon_handle_t daemon_handle, int argc, char **argv);
int prfMspCT(daemon_handle_t daemon_handle, int argc, char **argv);
int prfStatus(daemon_handle_t daemon_handle, int argc, char **argv);
int prfPTBusyCPU(daemon_handle_t daemon_handle, int argc, char **argv);
int prfPTsetmask(daemon_handle_t daemon_handle, int argc, char **argv);
int prfPTstart(daemon_handle_t daemon_handle, int argc, char **argv);
int prfPTswitch(daemon_handle_t daemon_handle, int argc, char **argv);
int prfPTshow(daemon_handle_t daemon_handle, int argc, char **argv);

#endif

