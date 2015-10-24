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





#include "pkgmgr_installer.h"
#include "pkgmgr_installer_config.h"

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#include "package-manager-debug.h"
#endif

#include "comm_config.h"
#include "comm_status_broadcast_server.h"
#include "error_report.h"

#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <db-util.h>
#include <pkgmgr-info.h>


#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR_INSTALLER"
#endif				/* LOG_TAG */

#define MAX_STRLEN 1024
#define MAX_QUERY_LEN	4096

#define CHK_PI_RET(r) \
	do { if (NULL == pi) return (r); } while (0)

/* ADT */
struct pkgmgr_installer {
	int request_type;
	int move_type;
	char *pkgmgr_info;
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
		char *tep_path;
		int tep_move;
#endif
	char *session_id;
	char *license_path;
	char *quiet_socket_path;
	char *optional_data;
	char *caller_pkgid;
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
		int is_tep_included;
#endif
	bool debug_mode;
	char *pkg_chksum;

	DBusConnection *conn;
};

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#define TEP_MOVE "tep_move"
#define TEP_COPY "tep_copy"
#endif

/* API */

static int __send_signal_for_event(int comm_status_type, pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *key, const char *val)
{
	if (!pi)
		return -1;

	if (!pi->conn)
		pi->conn = comm_status_broadcast_server_connect(comm_status_type);

	char *sid = pi->session_id;
	if (!sid)
		sid = "";
	comm_status_broadcast_server_send_signal(comm_status_type, pi->conn, sid, pkg_type, pkgid, key, val);

	return 0;
}

API int __send_event(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *key, const char *val)
{
	int r = -1;

	_LOGD("option is pkgid[%s] key[%s] value[%s]", pkgid, key, val );

	if (strcmp(key,PKGMGR_INSTALLER_START_KEY_STR) == 0) {
		if(strcmp(val,PKGMGR_INSTALLER_UPGRADE_EVENT_STR) == 0) {
			pi->request_type = PKGMGR_REQ_UPGRADE;
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_UPGRADE, pi, pkg_type, pkgid, key, val);
		}
		if(pi->request_type == PKGMGR_REQ_INSTALL) {
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_INSTALL, pi, pkg_type, pkgid, key, val);
		} else if (pi->request_type == PKGMGR_REQ_UNINSTALL){
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_UNINSTALL, pi, pkg_type, pkgid, key, val);
#ifdef _APPFW_FEATURE_MOUNT_INSTALL
		} else if (pi->request_type == PKGMGR_REQ_MOUNT_INSTALL){
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_INSTALL, pi, pkg_type, pkgid, key, val);
#endif
		} else if (pi->request_type == PKGMGR_REQ_MOVE){
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_MOVE, pi, pkg_type, pkgid, key, val);
		}
	} else if (strcmp(key,PKGMGR_INSTALLER_END_KEY_STR) == 0) {
		if(pi->request_type == PKGMGR_REQ_INSTALL) {
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_INSTALL, pi, pkg_type, pkgid, key, val);
		} else if (pi->request_type == PKGMGR_REQ_UNINSTALL){
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_UNINSTALL, pi, pkg_type, pkgid, key, val);
		} else if (pi->request_type == PKGMGR_REQ_MOVE){
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_MOVE, pi, pkg_type, pkgid, key, val);
		} else if (pi->request_type == PKGMGR_REQ_UPGRADE){
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_UPGRADE, pi, pkg_type, pkgid, key, val);
#ifdef _APPFW_FEATURE_MOUNT_INSTALL
		} else if (pi->request_type == PKGMGR_REQ_MOUNT_INSTALL){
			r = __send_signal_for_event(COMM_STATUS_BROADCAST_INSTALL, pi, pkg_type, pkgid, key, val);
#endif
		}
	} else if (strcmp(key,PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR) == 0) {
		r = __send_signal_for_event(COMM_STATUS_BROADCAST_INSTALL_PROGRESS, pi, pkg_type, pkgid, key, val);
	}

	return r;
}

API pkgmgr_installer *pkgmgr_installer_new(void)
{
	pkgmgr_installer *pi = NULL;
	pi = calloc(1, sizeof(struct pkgmgr_installer));
	if (NULL == pi)
		return ERR_PTR(-ENOMEM);

	pi->request_type = PKGMGR_REQ_INVALID;
	pi->pkg_chksum = NULL;

	return pi;
}

API int pkgmgr_installer_free(pkgmgr_installer *pi)
{
	CHK_PI_RET(-EINVAL);

	/* free members */
	if (pi->pkgmgr_info)
		free(pi->pkgmgr_info);
	if (pi->session_id)
		free(pi->session_id);
	if (pi->optional_data)
		free(pi->optional_data);
	if (pi->caller_pkgid)
		free(pi->caller_pkgid);
	if(pi->license_path)
		free(pi->license_path);
	if(pi->quiet_socket_path)
		free(pi->quiet_socket_path);
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	if(pi->tep_path)
		free(pi->tep_path);
#endif

	if (pi->conn)
		comm_status_broadcast_server_disconnect(pi->conn);

	free(pi);

	return 0;
}

API int
pkgmgr_installer_receive_request(pkgmgr_installer *pi,
				 const int argc, char **argv)
{
	CHK_PI_RET(-EINVAL);

	int r = 0;

	/* Parse argv */
	optind = 1;		/* Initialize optind to clear prev. index */
	int opt_idx = 0;
	int c;
	int mode = 0;
	while (1) {
		c = getopt_long(argc, argv, short_opts, long_opts, &opt_idx);
		/* printf("c=%d %c\n", c, c); //debug */
		if (-1 == c)
			break;	/* Parse is end */
		switch (c) {
		case 'k':	/* session id */
			if (pi->session_id)
				free(pi->session_id);
			pi->session_id = strndup(optarg, MAX_STRLEN);
			break;

		case 'l':	/* license path */
			if (pi->license_path)
				free(pi->license_path);
			pi->license_path = strndup(optarg, MAX_STRLEN);
			break;

		case 'i':	/* install */
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
			_LOGE("option is [i]" );
#endif
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'i';
			pi->request_type = PKGMGR_REQ_INSTALL;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
			_LOGD("option is [i] pkgid[%s]", pi->pkgmgr_info );
			if (pi->pkgmgr_info && strlen(pi->pkgmgr_info)==0){
				free(pi->pkgmgr_info);
			}else{
				mode = 'i';
			}
			break;

		case 'e':	/* install */
			_LOGD("option is [e]" );
			if (!mode)
				pi->request_type = PKGMGR_REQ_INSTALL_TEP;
			if (pi->tep_path)
				free(pi->tep_path);
			pi->tep_path = strndup(optarg, MAX_STRLEN);
			pi->is_tep_included = 1;
			_LOGD("option is [e] tep_path[%s]", pi->tep_path);
			break;

		case 'M':	/* install */
			_LOGD("option is [M]" );
			if (strncmp(optarg, TEP_MOVE, strlen(TEP_MOVE)) == 0)
				pi->tep_move = 1;
			else
				pi->tep_move = 0;
			_LOGD("option is [e] tep_move[%d]", pi->tep_move);
#endif
			break;

#ifdef _APPFW_FEATURE_MOUNT_INSTALL
		case 'w':	/* mount based install */
			_LOGD("option is [w]" );
			pi->request_type = PKGMGR_REQ_MOUNT_INSTALL;
			break;
#endif
		case 'd':	/* uninstall */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'd';
			pi->request_type = PKGMGR_REQ_UNINSTALL;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;


		case 'c':	/* clear */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'c';
			pi->request_type = PKGMGR_REQ_CLEAR;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;

		case 'm':	/* move */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'm';
			pi->request_type = PKGMGR_REQ_MOVE;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;

		case 'r':	/* reinstall */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'r';
			pi->request_type = PKGMGR_REQ_REINSTALL;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;

		case 't': /* move type*/
			pi->move_type = atoi(optarg);
			break;
		case 'p': /* caller pkgid*/
			if (pi->caller_pkgid)
				free(pi->caller_pkgid);
			pi->caller_pkgid = strndup(optarg, MAX_STRLEN);

			break;

		case 's':	/* smack */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 's';
			pi->request_type = PKGMGR_REQ_SMACK;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;

		case 'G':  /* debug mode for sdk */
			pi->debug_mode = true;
			break;
		case 'o': /* optional data*/
			if (pi->optional_data)
				free(pi->optional_data);
			pi->optional_data = strndup(optarg, MAX_STRLEN);
			break;
		case 'C': /* pkgfile checksum for installer app */
			if (pi->pkg_chksum)
				free(pi->pkg_chksum);
			pi->pkg_chksum = strndup(optarg, MAX_STRLEN);
			break;

			/* Otherwise */
		case '?':	/* Not an option */
			break;

		case ':':	/* */
			break;

		}
	}

	/* quiet mode : get options from socket (to be impelemented) */

	/* normal mode : get options from argv */

 RET:
	return r;
}

API int pkgmgr_installer_get_request_type(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->request_type;
}

API const char *pkgmgr_installer_get_request_info(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->pkgmgr_info;
}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
API const char *pkgmgr_installer_get_tep_path(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->tep_path;
}

API int pkgmgr_installer_get_tep_move_type(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->tep_move;
}
#endif

API const char *pkgmgr_installer_get_session_id(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->session_id;
}

API const char *pkgmgr_installer_get_license_path(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->license_path;
}

API const char *pkgmgr_installer_get_optional_data(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->optional_data;
}

API int pkgmgr_installer_is_quiet(pkgmgr_installer *pi)
{
/*TODO: need to discuss with HQ to delete this API*/
#if 0
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->quiet;
#endif
return 1;
}

API const char *pkgmgr_installer_get_pkg_chksum(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->pkg_chksum;
}

API int pkgmgr_installer_get_move_type(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->move_type;
}

API const char *pkgmgr_installer_get_caller_pkgid(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->caller_pkgid;
}
API int pkgmgr_installer_is_debug_mode(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->debug_mode;
}

API int pkgmgr_installer_send_app_uninstall_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *val)
{
	int ret = -1;

	ret = __send_signal_for_event(COMM_STATUS_BROADCAST_UNINSTALL, pi, pkg_type, pkgid, "appid", val);
	return ret;
}

API int
pkgmgr_installer_send_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *key, const char *val)
{
	int r = 0;

	if (strcmp(pkg_type,PKGMGR_INSTALLER_GET_SIZE_KEY_STR) == 0) {
		r = __send_signal_for_event(COMM_STATUS_BROADCAST_GET_SIZE, pi, pkg_type, pkgid, key, val);
		return r;
	}

	if (!pi->conn)
		pi->conn = comm_status_broadcast_server_connect(COMM_STATUS_BROADCAST_ALL);

	char *sid = pi->session_id;
	if (!sid)
		sid = "";
	comm_status_broadcast_server_send_signal(COMM_STATUS_BROADCAST_ALL, pi->conn, sid, pkg_type,
						 pkgid, key, val);

	__send_event(pi, pkg_type, pkgid, key, val);

	return r;
}

API int pkgmgr_installer_create_certinfo_set_handle(pkgmgr_instcertinfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_create_certinfo_set_handle(handle);
	return ret;
}

API int pkgmgr_installer_set_cert_value(pkgmgr_instcertinfo_h handle, pkgmgr_instcert_type cert_type, char *cert_value)
{
	int ret = 0;
	ret = pkgmgrinfo_set_cert_value(handle, cert_type, cert_value);
	return ret;
}

API int pkgmgr_installer_save_certinfo(const char *pkgid, pkgmgr_instcertinfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_save_certinfo(pkgid, handle);
	return ret;
}

API int pkgmgr_installer_destroy_certinfo_set_handle(pkgmgr_instcertinfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_destroy_certinfo_set_handle(handle);
	return ret;
}

API int pkgmgr_installer_delete_certinfo(const char *pkgid)
{
	int ret = 0;
	ret = pkgmgrinfo_delete_certinfo(pkgid);
	return ret;
}
