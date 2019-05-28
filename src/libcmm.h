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

#ifndef __CMMLIB__
#define __CMMLIB__

#include <sys/types.h>

#define CMM_BUF_SIZE 512 

typedef struct cmm_handle cmm_handle_t;

typedef struct cmm_command
{
	long int	msg_type;		/* internal, user shouldn't use this*/
	u_int16_t	func;			/* function code, filled by user */ 
	u_int16_t	length;			/* buf length, filled by user */
	u_int8_t	buf[CMM_BUF_SIZE];	/* command payload, filled by user */
} __attribute__((__packed__)) cmm_command_t;	/* to be consistent with cmm_response_t, actually 
						 * no demand for "packed" here
						 */

typedef struct cmm_response
{
	long int 	msg_type;		/* internal, user shouldn't use this */
	int 		daemon_errno;		/* internal, user shouldn't use this */
	u_int16_t	func;			/* function code, set by remote side */
	u_int16_t	length;			/* length of a buf, set by remote side */
	union {
		u_int16_t	rc;			/* return code, set by remote side */
		u_int8_t	buf[CMM_BUF_SIZE];	/* response payload, set by remote side */
	};
} __attribute__((__packed__)) cmm_response_t;	/* "packed" is due to operations
						 * on the structure using memcpy() internally in CMM daemon
						 */

cmm_handle_t 	*cmm_open(void);
void		cmm_close(cmm_handle_t*);
int		cmm_send(cmm_handle_t*, cmm_command_t*, int nonblocking);
int		cmm_recv(cmm_handle_t*, cmm_response_t*, int nonblocking);

#endif

