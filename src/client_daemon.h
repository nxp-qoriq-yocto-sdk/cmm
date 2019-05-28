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

#ifndef __CLIENT_DAEMON_H__
#define __CLIENT_DAEMON_H__

	static __inline unsigned short cmmDaemonCmdRC(void *rspbuf)
	{
	  return *( (unsigned short *) rspbuf);
	}

static inline void setbit_in_array(u_int8_t *pbits, u_int32_t bitindex, u_int32_t bitval)
{
	if (bitval)
		pbits[bitindex >> 3] |= 1 << (bitindex & 0x07);
	else
		pbits[bitindex >> 3] &= ~(1 << (bitindex & 0x07));
}

static inline u_int32_t testbit_in_array(u_int8_t *pbits, u_int32_t bitindex)
{
	u_int8_t x;
	u_int32_t bitmask;
	x = pbits[bitindex >> 3];
	bitmask = 1 << (bitindex & 0x07);
	return (x & bitmask);
}

#define ERRMSG_SOURCE_FPP		(0)
#define ERRMSG_SOURCE_CMMD		(1)

	int cmmClient(char * command, int argc, char **argv);
	int cmmSendToDaemon(daemon_handle_t daemon_handle, unsigned short commandCode, void * dataToSend, int dataSize, void* dataToRcv);

	struct cmm_daemon;

	int cmmCommandCheck(struct cmm_daemon *ctx, int function_code, char * buffer, int buffer_size_in, int max_buffer_size);
	char * getErrorString(unsigned short error);
	void showErrorMsg(char *commandCodeString, unsigned int source, char *rxBuffer);
	
	int cmmDaemonInit(struct cmm_daemon *ctx);
	void cmmDaemonExit(struct cmm_daemon *ctx);

	int parse_value(char *p, u_int32_t *value, u_int32_t maxval);
	int parse_range(char *p, u_int32_t *from, u_int32_t *to, u_int32_t maxval);

#endif

