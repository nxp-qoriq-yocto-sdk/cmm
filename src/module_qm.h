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


#ifndef __MODULE_QM_H__
#define __MODULE_QM_H__

int cmmQmShowProcess(char ** keywords, int tabSize, daemon_handle_t daemon_handle);
int cmmQmQueryProcess(char ** keywords, int tabSize, daemon_handle_t daemon_handle);
int cmmQmExptRateQueryProcess(char ** keywords, int tabSize, daemon_handle_t daemon_handle);
int cmmQmSetProcess(char ** keywords, int tabSize, daemon_handle_t daemon_handle);
void cmmQmResetQ2Prio(fpp_qm_reset_cmd_t *cmdp, int cmdlen);
void cmmQmUpdateQ2Prio(fpp_qm_scheduler_cfg_t *cmdp, int cmdlen);

#endif


