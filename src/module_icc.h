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


#ifndef __MODULE_ICC_H__
#define __MODULE_ICC_H__
#include "fpp.h"

#define ICC_NUM_INTERFACES	3

#define ICC_ACTION_ADD		0
#define ICC_ACTION_DELETE	1

#define ICC_ACTION_QUERY	0
#define ICC_ACTION_QUERY_CONT	1

#define	ICC_TABLETYPE_ETHERTYPE	0
#define	ICC_TABLETYPE_PROTOCOL	1
#define	ICC_TABLETYPE_DSCP	2
#define	ICC_TABLETYPE_SADDR	3
#define	ICC_TABLETYPE_DADDR	4
#define	ICC_TABLETYPE_SADDR6	5
#define	ICC_TABLETYPE_DADDR6	6
#define	ICC_TABLETYPE_PORT	7
#define	ICC_TABLETYPE_VLAN	8

int IccReset(daemon_handle_t daemon_handle, int argc, char *argv[]);
int IccThreshold(daemon_handle_t daemon_handle, int argc, char *argv[]);
int IccAdd(daemon_handle_t daemon_handle, int argc, char *argv[]);
int IccDelete(daemon_handle_t daemon_handle, int argc, char *argv[]);
int IccQuery(daemon_handle_t daemon_handle, int argc, char *argv[]);

#endif
