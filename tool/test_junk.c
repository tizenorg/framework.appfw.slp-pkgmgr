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

#define _GNU_SOURCE

#include <stdio.h>
#include <dlog.h>
#include <string.h>
#include <glib.h>
#include <stdlib.h>
#include <glib-object.h>

#include "junk-manager.h"

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "JUNK_TEST"
#endif

void junk_result_test(junkmgr_result_h handle)
{
    int cnt = 0;
    while (junkmgr_result_cursor_step_next(handle) == JUNKMGR_E_SUCCESS)
    {
        printf(">>>>> loop count: %d\n", cnt);

        char *junk_name = NULL;
        junkmgr_result_cursor_get_junk_name(handle, &junk_name);
        printf("junk name: %s\n", junk_name);
        free(junk_name);

        junkmgr_category_e category;
        junkmgr_result_cursor_get_category(handle, &category);
        printf("category: %d\n", category);

        junkmgr_file_type_e file_type = -1;
        junkmgr_result_cursor_get_file_type(handle, &file_type);
        printf("file type: %d\n", file_type);

        junkmgr_storage_type_e storage_type = -1;
        junkmgr_result_cursor_get_storage_type(handle, &storage_type);
        printf("storage type: %d\n", storage_type);

        long long junk_size = -1;
        junkmgr_result_cursor_get_junk_size(handle, &junk_size);
        printf("junk size: %lld\n", junk_size);

        char *junk_path = NULL;
        junkmgr_result_cursor_get_junk_path(handle, &junk_path);
        printf("junk path: %s\n", junk_path);
        free(junk_path);

        cnt++;
        printf("<<<<< end\n");
    }

    return;
}

void __junk_cb(int reqid, junkmgr_result_h handle, void *user_data)
{
	LOGD("reqid: %d, junkmgr_result_h: 0x%x, user_data: 0x%x", reqid, handle, user_data);

    junk_result_test(handle);

    g_main_loop_quit((GMainLoop *)user_data);
}

int main(int argc, char *argv[])
{
	LOGD("Test start!");

	g_type_init();
	GMainLoop *main_loop = g_main_loop_new(NULL, FALSE);


	junkmgr_h junkmgr = junkmgr_create_handle();
	if (junkmgr == NULL) {
		LOGE("Failed to get pkgmgr_client instance!");
		return 1;
	}

    int ret = 0;
    int reqid = 0;
#if 1
	ret = junkmgr_get_junk_root_dirs(junkmgr, __junk_cb, main_loop, &reqid);
	LOGD("result(req_id): %d", ret);
#else
	ret = junkmgr_get_junk_files(junkmgr, "/opt/storage/sdcard/Others/__@@bada_applications@@__", __junk_cb, main_loop, &reqid);
	LOGD("result(req_id): %d", ret);
#endif
	g_main_loop_run(main_loop);

    junkmgr_destroy_handle(junkmgr);

	return 0;
}
