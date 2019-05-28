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


#ifndef __MODULE_LRO_H__
#define __MODULE_LRO_H__

int lro_interface_add(char *ifname);
void lro_interface_update(struct interface *itf);
void lro_socket_open(FCI_CLIENT *fci_handle, struct ctTable *ctEntry);
void lro_socket_close(FCI_CLIENT *fci_handle, FCI_CLIENT *fci_key_handle, struct ctTable *ctEntry);

#endif /* __MODULE_LRO_H__ */
