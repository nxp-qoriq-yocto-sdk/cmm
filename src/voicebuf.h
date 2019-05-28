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

#ifndef __VOICEBUF_H__
#define __VOICEBUF_H__

#include <sys/ioctl.h>

#define MEMBUF_CHAR_DEVNAME "/dev/membuf"

#define VOICE_FILE_MAX		8

/* These must match the kernel definitions */
#define MEMBUF_GET_SCATTER _IOR('m', 1, struct usr_scatter_list)

#define MAX_BUFFERS	48

struct usr_scatter_list
{
	u_int8_t entries;
	u_int8_t pg_order[MAX_BUFFERS];
	u_int32_t addr[MAX_BUFFERS];
};

int voice_file_load(FCI_CLIENT *fci_handle, cmmd_voice_file_load_cmd_t *cmd, u_int16_t *res_buf, u_int16_t *res_len);
int voice_file_unload(FCI_CLIENT *fci_handle, cmmd_voice_file_unload_cmd_t *cmd, u_int16_t *res_buf, u_int16_t *res_len);
int voice_buffer_reset(FCI_CLIENT *fci_handle);
int cmmVoiceBufSetProcess(int argc, char *argv[], daemon_handle_t daemon_handle);

#endif
