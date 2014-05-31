/*
 *  slp-pkgmgr
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
#include <tet_api.h>
#include <package-manager.h>

static void startup(void);
static void cleanup(void);

void (*tet_startup) (void) = startup;
void (*tet_cleanup) (void) = cleanup;

static void utc_ApplicationFW_pkgmgr_client_uninstall_func_01(void);
static void utc_ApplicationFW_pkgmgr_client_uninstall_func_02(void);
static void utc_ApplicationFW_pkgmgr_client_uninstall_func_03(void);
static int event_cb(int req_id, const char *pkg_type, const char *pkg_name,
		    const char *key, const char *val, const void *pmsg,
		    void *data);

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

struct tet_testlist tet_testlist[] = {
	{utc_ApplicationFW_pkgmgr_client_uninstall_func_01, POSITIVE_TC_IDX},
	{utc_ApplicationFW_pkgmgr_client_uninstall_func_02, NEGATIVE_TC_IDX},
	{utc_ApplicationFW_pkgmgr_client_uninstall_func_03, NEGATIVE_TC_IDX},
	{NULL, 0},
};

static void startup(void)
{
}

static void cleanup(void)
{
}

static int event_cb(int req_id, const char *pkg_type, const char *pkg_name,
		    const char *key, const char *val, const void *pmsg,
		    void *data)
{
	return 0;
}

/**
 * @brief Positive test case of pkgmgr_client_uninstall()
 */
static void utc_ApplicationFW_pkgmgr_client_uninstall_func_01(void)
{
	int r = PKGMGR_R_ERROR;
	pkgmgr_client *pc = NULL;
	pc = pkgmgr_client_new(PC_REQUEST);
	if (!pc) {
		tet_result(TET_UNINITIATED);
		return;
	}
	r = pkgmgr_client_uninstall(pc, "rpm", "com.samsung.hello",
				    PM_QUIET, event_cb, NULL);
	if (r < 0) {
		tet_infoline
		    ("pkgmgr_client_uninstall() failed in positive test case");
		tet_result(TET_FAIL);
		return;
	}
	if (pc) {
		pkgmgr_client_free(pc);
		pc = NULL;
	}
	tet_result(TET_PASS);
}

/**
 * @brief Negative test case 01 of pkgmgr_client_uninstall()
 */
static void utc_ApplicationFW_pkgmgr_client_uninstall_func_02(void)
{
	int r = PKGMGR_R_ERROR;
	pkgmgr_client *pc = NULL;
	pc = pkgmgr_client_new(PC_REQUEST);
	if (!pc) {
		tet_result(TET_UNINITIATED);
		return;
	}
	r = pkgmgr_client_uninstall(pc, "rpm", NULL, PM_QUIET, event_cb, NULL);
	if (r != PKGMGR_R_EINVAL) {
		tet_infoline
		    ("pkgmgr_client_uninstall() failed in negative test case");
		tet_result(TET_FAIL);
		return;
	}
	if (pc) {
		pkgmgr_client_free(pc);
		pc = NULL;
	}
	tet_result(TET_PASS);
}


/**
 * @brief Negative test case 02 of pkgmgr_client_uninstall()
 */
static void utc_ApplicationFW_pkgmgr_client_uninstall_func_03(void)
{
	int r = PKGMGR_R_ERROR;
	r = pkgmgr_client_uninstall(NULL, "rpm", "com.samsung.hello", PM_QUIET,
				    event_cb, NULL);
	if (r != PKGMGR_R_EINVAL) {
		tet_infoline
		    ("pkgmgr_client_uninstall() failed in negative test case");
		tet_result(TET_FAIL);
		return;
	}
	tet_result(TET_PASS);
}
