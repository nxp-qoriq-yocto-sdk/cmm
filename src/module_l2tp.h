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


#ifndef __MODULE_L2TP_H__
#define __MODULE_L2TP_H__


int l2tp_itf_add(FCI_CLIENT *fci_handle, int request, struct interface *itf);
int __l2tp_itf_del(FCI_CLIENT *fci_handle, struct interface *itf);
int l2tp_itf_del(FCI_CLIENT *fci_handle, struct interface *itf);
int l2tp_daemon(FCI_CLIENT *fci_handle,int command, cmmd_l2tp_session_t *cmd,  u_int16_t cmd_len, u_int16_t *res_buf, u_int16_t *res_len);

#endif
