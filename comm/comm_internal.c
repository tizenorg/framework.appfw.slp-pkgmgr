/*
 * slp-pkgmgr
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "comm_config.h"
#include <stdio.h>
#include <vasum.h>

#define ZONE_HOST "host"

int get_zone_name(int pid, char *zone_name, int len)
{
	vsm_zone_h zone;
	vsm_context_h ctx = vsm_create_context();
	const char *zone_name_tmp = NULL;
	int ret = 0;
	if (ctx == NULL) {
			ERR("vsm_create_context failed");
			return -1;
	}
	zone = vsm_lookup_zone_by_pid(ctx, pid);

	if (zone != NULL && !vsm_is_host_zone(zone)) {
		zone_name_tmp = vsm_get_zone_name(zone);
		if (zone_name_tmp == NULL) {
			ERR("failed to get zone");
			ret = -1;
			goto err;
		}
	} else if (vsm_is_host_zone(zone)) {
		zone_name_tmp = ZONE_HOST;
	} else {
		ERR("could not get zone name");
		ret = -1;
		goto err;
	}

	snprintf(zone_name, len, "%s", zone_name_tmp);
err:
	if (vsm_cleanup_context(ctx) != 0)
		ERR("vsm cleanup failed");
	return ret;

}
