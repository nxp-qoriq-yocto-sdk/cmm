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

#ifndef __FORWARD_ENGINE__
#define __FORWARD_ENGINE__

#include "keytrack.h"
#include "conntrack.h"
#include "jhash.h"
#include "neighbor_resolution.h"
#include "route_cache.h"
#include "fpp.h"
#include "fpp_private.h"
#include "module_rx.h"

	void cmmFeReset(FCI_CLIENT* fci_handle);

	/* IPv4 */
	int cmmFeCtUpdate4(FCI_CLIENT *fci_handle, int action, struct ctTable *ctEntry);

	int __cmmFeRouteUpdate(FCI_CLIENT* fci_handle, int action, struct fpp_rt *route);

	/* IPv6 */
	int cmmFeCtUpdate6(FCI_CLIENT *fci_handle, int action, struct ctTable *ctEntry);

        int cmmCt6QueryProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
	int cmmSAQueryProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
	int cmmCtQueryProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
	int cmmL2FlowQueryProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);

	int cmmFeCatch(unsigned short fcode, unsigned short len, unsigned short *payload);

	/* command processors */
	int cmmCtChangeProcess4(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
	int cmmCtChangeProcess6(char ** keywords, int tabStart, daemon_handle_t daemon_handle);

	int cmmRtQueryProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);

	int cmmFeFFControl(FCI_CLIENT* fci_handle, u_int8_t *cmd_buf, u_int16_t cmd_len, u_int16_t *res_buf, u_int16_t *res_len);
	int cmmFeL2FlowUpdate(FCI_CLIENT* fci_handler, int request, struct l2flowTable *l2flow);

static inline int cmmFeRouteUpdate(FCI_CLIENT* fci_handle, int request, struct fpp_rt *fpp_route)
{
	int action;

	switch (request)
	{
	default:
	case (ADD | UPDATE):
		if ((fpp_route->flags & (FPP_PROGRAMMED | FPP_NEEDS_UPDATE)) == FPP_PROGRAMMED)
			goto out;

		if ((fpp_route->flags & (FPP_PROGRAMMED | FPP_NEEDS_UPDATE)) == (FPP_PROGRAMMED | FPP_NEEDS_UPDATE))
		{
			action = FPP_ACTION_UPDATE;
		}
		else
		{
			action = FPP_ACTION_REGISTER;
		}

		break;

	case UPDATE:
		if (!((fpp_route->flags & FPP_PROGRAMMED) && (fpp_route->flags & FPP_NEEDS_UPDATE)))
			goto out;

		action = FPP_ACTION_UPDATE;

		break;

	case REMOVE:
		if (!(fpp_route->flags & FPP_PROGRAMMED))
			goto out;

		action = FPP_ACTION_DEREGISTER;

		break;
	}

	return __cmmFeRouteUpdate(fci_handle, action, fpp_route);

out:
	return 0;
}


static inline int cmmFeCtUpdate(FCI_CLIENT *fci_handle, int request, struct ctTable *ctEntry)
{
	int action;

	switch (request) {
	default:
	case (ADD | UPDATE):
		if (!(ctEntry->flags & FPP_PROGRAMMED))
			action = FPP_ACTION_REGISTER;
		else if (ctEntry->flags & FPP_NEEDS_UPDATE)
			action = FPP_ACTION_UPDATE;
		else if (ctEntry->fEntryOrigOut && (!(ctEntry->fEntryOrigOut->flags & FPP_PROGRAMMED) || (ctEntry->fEntryOrigOut->flags & FPP_NEEDS_UPDATE)))
			action = FPP_ACTION_UPDATE;
		else if (ctEntry->fEntryOrigFwd && (!(ctEntry->fEntryOrigFwd->flags & FPP_PROGRAMMED) || (ctEntry->fEntryOrigFwd->flags & FPP_NEEDS_UPDATE)))
			action = FPP_ACTION_UPDATE;
		else if (ctEntry->fEntryRepOut && (!(ctEntry->fEntryRepOut->flags & FPP_PROGRAMMED) || (ctEntry->fEntryRepOut->flags & FPP_NEEDS_UPDATE)))
			action = FPP_ACTION_UPDATE;
		else if (ctEntry->fEntryRepFwd && (!(ctEntry->fEntryRepFwd->flags & FPP_PROGRAMMED) || (ctEntry->fEntryRepFwd->flags & FPP_NEEDS_UPDATE)))
			action = FPP_ACTION_UPDATE;
		else
			goto out;

		break;

	case UPDATE:
		if (!((ctEntry->flags & FPP_PROGRAMMED) && (ctEntry->flags & FPP_NEEDS_UPDATE)))
			goto out;

		action = FPP_ACTION_UPDATE;
		break;

	case REMOVE:
		if (!(ctEntry->flags & FPP_PROGRAMMED))
			goto out;

		action = FPP_ACTION_DEREGISTER;
		break;
	}

	if (ctEntry->family == AF_INET)
		return cmmFeCtUpdate4(fci_handle, action, ctEntry);
	else
		return cmmFeCtUpdate6(fci_handle, action, ctEntry);

out:
	return 0;
}

#endif
