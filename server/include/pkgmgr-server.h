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





#ifndef _PKGMGR_SERVER_H_
#define _PKGMGR_SERVER_H_

#define CONF_FILE	"/usr/etc/package-manager/server/.config"
#define DESKTOP_FILE_DIRS	"/usr/share/install-info/desktop.conf"

#define PKG_BACKEND	"backend:"
#define PKG_CONF_PATH	"/usr/etc/package-manager/pkg_path.conf"

#define MAX_REQ_ID_LEN		256
#define MAX_PKG_TYPE_LEN	128
#define MAX_PKG_NAME_LEN	256
#define MAX_PKG_ARGS_LEN	4096
#define MAX_COOKIE_LEN		32
#define DESKTOP_FILE_DIRS_NUM		1024

typedef struct {
	char req_id[MAX_REQ_ID_LEN];
	int req_type;
	char pkg_type[MAX_PKG_TYPE_LEN];
	char pkg_name[MAX_PKG_NAME_LEN];
	char args[MAX_PKG_ARGS_LEN];
	char cookie[MAX_COOKIE_LEN];
} pm_dbus_msg;

typedef struct backend_info_t {
	int pid;
	char pkgtype[MAX_PKG_TYPE_LEN];
	char pkgname[MAX_PKG_NAME_LEN];
	char args[MAX_PKG_ARGS_LEN];
}backend_info;

struct pm_inotify_paths_t {
	int wd;
	char *path;
};
typedef struct pm_inotify_paths_t pm_inotify_paths;

char *_get_backend_cmd(char *type);
void _pm_desktop_file_monitor_init();
void _pm_desktop_file_monitor_fini();
int _pm_desktop_file_dir_search(pm_inotify_paths *paths, int number);

#endif				/*  _PKGMGR_SERVER_H_ */
