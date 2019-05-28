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


/* Function prototypes */ 
int timeoutSet(daemon_handle_t daemon_handle, char *argv[], int argc);
int cmmtimeoutSet(daemon_handle_t daemon_handle, char *argv[], int argc, int tab);
int cmmFeGetTimeout(FCI_CLIENT *fci_handle, struct ctTable *ctEntry, unsigned int *timeout);
int cmmFragTimeoutSet(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
unsigned long long cmm_convert_to_numeric(char *str );

#define MAX_TIMEOUT_STR_LEN 10
