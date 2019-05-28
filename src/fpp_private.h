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

#ifndef __FPP_PRIVATE__
#define __FPP_PRIVATE__

/*----------------------------------------- IPV4 -----------------------------*/
#define FPP_CMD_IPV4_CONNTRACK_CHANGE		0x0315
#define FPP_CMD_IPV4_SOCK_OPEN			0x0330
#define FPP_CMD_IPV4_SOCK_CLOSE			0x0331
#define FPP_CMD_IPV4_SOCK_UPDATE		0x0332

/*----------------------------------------- IPV6 -----------------------------*/
#define FPP_CMD_IPV6_CONNTRACK_CHANGE		0x0415
#define FPP_CMD_IPV6_SOCK_OPEN			0x0430
#define FPP_CMD_IPV6_SOCK_CLOSE			0x0431
#define FPP_CMD_IPV6_SOCK_UPDATE		0x0432

/*------------- CtEntry/RtEntry Flags ----------------------------------------------*/
#define FPP_PROGRAMMED		(1 << 0)
#define FPP_NEEDS_UPDATE	(1 << 1)

#define INVALID			(1 << 3)
#define RT_POLICY		(1 << 4)
#define USER_ADDED		(1 << 5)
#define CHECK_BRIDGE_PORT	(1 << 6)
#define NEEDS_SOLICIT		(1 << 7)

#define LOCAL_CONN_ORIG		(1 << 8)
#define LOCAL_CONN_REPL		(1 << 9)
#define LOCAL_CONN		(LOCAL_CONN_ORIG | LOCAL_CONN_REPL)

#define	IS_LOCAL		(1 << 10)

#define ADD             (1 << 0)
#define UPDATE          (1 << 1)
#define REMOVE          (1 << 2)
#define ENABLE          (1 << 3)
#define DISABLE         (1 << 4)

#define IPADDRLEN(family) ((family) == AF_INET ? 4 : 16)

/* CMM tunnel entry states */
#define TNL_IPSEC      		(1 << 0)
#define TNL_6RD			(1 << 1)
#define TNL_4RD                 (1 << 2)

#ifndef IPPROTO_ETHERIP
#define IPPROTO_ETHERIP		97
#endif

#define TNL_ETHIPOIP6  		0
#define TNL_6O4			1
#define TNL_4O6			2
#define TNL_ETHIPOIP4  		3
#define TNL_GRE_IPV6		4

#endif

