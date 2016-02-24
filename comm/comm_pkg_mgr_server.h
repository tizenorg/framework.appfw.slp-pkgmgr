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





#ifndef __COMM_PKG_MGR_SERVER_H__
#define __COMM_PKG_MGR_SERVER_H__

#include "comm_config.h"

typedef struct pkg_mgr_server_gdbus_s *pkgmgr_server_gdbus_h;

typedef void (*request_callback) (void *cb_data, const char *req_id,
				  const int req_type, const char *pkg_type,
				  const char *pkgid, const char *args,
				  const char *cookie, const char *zone, int *ret);

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
typedef void (*request_tep_callback) (void *cb_data, const char *req_id,
				  const int req_type, const char *pkg_type,
				  const char *pkgid, const char *tep_path,
				  const char *args, const char *cookie, const char *zone, int *ret);
#endif

typedef int (*create_directory_cb) (const char *zone);

typedef int (*drm_generate_license_request_cb) (const char *resp_data,
		char **req_data, char **license_url, int *ret);
typedef int (*drm_register_license_cb) (const char *resp_data, int *ret);
typedef int (*drm_decrypt_package_cb) (const char *drm_file_path,
		const char *decrypted_file_path, int *ret);

API int pkg_mgr_server_gdbus_init(pkgmgr_server_gdbus_h *pkgmgr_server_h);
API void pkg_mgr_server_gdbus_fini(pkgmgr_server_gdbus_h pkgmgr_server);

API void pkg_mgr_set_request_callback(pkgmgr_server_gdbus_h pkgmgr_server,
		request_callback req_cb, void *cb_data);

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
API void pkg_mgr_set_request_tep_callback(pkgmgr_server_gdbus_h pkgmgr_server,
		request_tep_callback req_cb, void *cb_data);
#endif

API void pkg_mgr_set_callback_to_create_directory(pkgmgr_server_gdbus_h pkgmgr_server,
		create_directory_cb callback);

API void pkg_mgr_set_drm_generate_license_request_callback(pkgmgr_server_gdbus_h pkgmgr_server,
		drm_generate_license_request_cb gen_license_req_cb);

API void pkg_mgr_set_drm_register_license_callback(pkgmgr_server_gdbus_h pkgmgr_server,
		drm_register_license_cb reg_license_cb);

API void pkg_mgr_set_drm_decrypt_package_callback(pkgmgr_server_gdbus_h pkgmgr_server,
		drm_decrypt_package_cb decrypt_pkg_cb);

#endif				/* __COMM_PKG_MGR_SERVER_H__ */
