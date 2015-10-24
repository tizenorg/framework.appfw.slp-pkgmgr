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





#ifndef __PACKAGE_INSTALLER_CONFIG_H__
#define __PACKAGE_INSTALLER_CONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Supported options */
#ifdef _APPFW_FEATURE_MOUNT_INSTALL
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
const char *short_opts = "k:l:i:d:c:m:t:o:r:p:s:e:M:C:wG";
#else
const char *short_opts = "k:l:i:d:c:m:t:o:r:p:s:C:wG";
#endif
#else
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
const char *short_opts = "k:l:i:d:c:m:t:o:r:p:s:e:M:C:G";
#else
const char *short_opts = "k:l:i:d:c:m:t:o:r:p:s:C:G";
#endif
#endif

const struct option long_opts[] = {
	{ "session-id", 1, NULL, 'k' },
	{ "license-path", 1, NULL, 'l' },
	{ "install", 1, NULL, 'i' },
#ifdef _APPFW_FEATURE_MOUNT_INSTALL
	{ "mount-install", 0, NULL, 'w' },
#endif
	{ "uninstall", 1, NULL, 'd' },
	{ "clear", 1, NULL, 'c' },
	{ "move", 1, NULL, 'm' },
	{ "move-type", 1, NULL, 't' },
	{ "optional-data", 0, NULL, 'o' },
	{ "reinstall", 0, NULL, 'r' },
	{ "caller-pkgid", 1, NULL, 'p' },
	{ "smack", 1, NULL, 's' },
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	{ "extension", 1, NULL, 'e' },
	{ "tep_move", 1, NULL, 'M'},
#endif
	{ "debug-mode", 0, NULL, 'G'},
	{ "chksum", 1, NULL, 'C'},
	{ 0, 0, 0, 0 }	/* sentinel */
};

#ifdef __cplusplus
}
#endif

#endif				/* __PACKAGE_INSTALLER_CONFIG_H__ */
