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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <vconf.h>
#include <db-util.h>
#include <pkgmgr-info.h>
#include <iniparser.h>
#include <security-server.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "package-manager.h"
#include "package-manager-debug.h"
#include "package-manager-internal.h"
#include "comm_client.h"
#include "comm_status_broadcast_server.h"
#include "pkgmgr_parser.h"

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR"
#endif				/* LOG_TAG */

#define BINSH_NAME	"/bin/sh"
#define BINSH_SIZE	7

#define PKG_INFO_DB_LABEL "pkgmgr::db"
#define PKG_PARSER_DB_FILE "/opt/dbspace/.pkgmgr_parser.db"
#define PKG_PARSER_DB_FILE_JOURNAL "/opt/dbspace/.pkgmgr_parser.db-journal"

#define FACTORY_RESET_BACKUP_FILE		"/usr/system/RestoreDir/opt.zip"
#define OPT_USR_APPS					"/opt/usr/apps"
#define SOFT_RESET_PATH					"/usr/etc/package-manager/soft-reset"
#define PKGMGR_FOTA_PATH			"/opt/usr/data/pkgmgr/fota/"
#define PKG_DISABLED_LIST_FILE 		PKGMGR_FOTA_PATH"pkg_disabled_list.txt"

#define TOKEN_PATH_STR						"path="
#define TOKEN_OP_STR						"op="
#define SEPERATOR_END						':'

#define OPT_USR_MEDIA			"/opt/usr/media"
#define SOFT_RESET_TEST_FLAG	OPT_USR_MEDIA"/.soft_reset_test"
FILE *logfile = NULL;

#define _LOGF(fmt, arg...) do { \
	_LOGE(fmt, ##arg);\
	if (logfile != NULL) {\
		fprintf(logfile, ""fmt"", ##arg); \
		fflush(logfile);\
	}\
} while (0)

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#define TEP_MOVE "tep_move"
#define TEP_COPY "tep_copy"
#endif

static int _get_request_id()
{
	int pid = 0;
	static int internal_req_id = 1;

	internal_req_id++;
	pid = getpid();

	pid = pid * 10000 + internal_req_id;

	return pid;
}

typedef struct _req_cb_info {
	int request_id;
	char *req_key;
	pkgmgr_handler event_cb;
	void *data;
	struct _req_cb_info *next;
} req_cb_info;

typedef struct _listen_cb_info {
	int request_id;
	pkgmgr_handler event_cb;
	int with_zone;
	pkgmgr_handler_with_zone event_cb_with_zone;
	void *data;
	struct _listen_cb_info *next;
} listen_cb_info;

typedef struct _pkgmgr_client_t {
	client_type ctype;
	int status_type;
	union {
		struct _request {
			comm_client *cc;
			req_cb_info *rhead;
		} request;
		struct _listening {
			comm_client *cc;
			listen_cb_info *lhead;
		} listening;
		struct _broadcast {
			DBusConnection *bc;
		} broadcast;
	} info;
	void* new_event_cb;
    void* extension;
	bool debug_mode;
	char *pkg_chksum;
} pkgmgr_client_t;

typedef struct _iter_data {
	pkgmgr_iter_fn iter_fn;
	void *data;
} iter_data;

static char *__get_cookie_from_security_server(void)
{
	int ret = 0;
	size_t cookie_size = 0;
	char *e_cookie = NULL;

	//calculage cookie size
	cookie_size = security_server_get_cookie_size();
	retvm_if(cookie_size <= 0, NULL, "security_server_get_cookie_size : cookie_size is %d", cookie_size);

	//get cookie from security server
	char cookie[cookie_size];
	cookie[0] = '\0';
	ret = security_server_request_cookie(cookie, cookie_size);
	retvm_if(ret < 0, NULL, "security_server_request_cookie fail (%d)", ret);

	//encode cookie
	e_cookie = g_base64_encode((const guchar *)cookie, cookie_size);
	retvm_if(e_cookie == NULL, NULL, "g_base64_encode e_cookie is NULL");

	return e_cookie;
}

static int __xsystem(const char *argv[])
{
	int status = 0;
	pid_t pid;
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child */
		execvp(argv[0], (char *const *)argv);
		_exit(-1);
	default:
		/* parent */
		break;
	}
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid failed");
		return -1;
	}
	if (WIFSIGNALED(status)) {
		perror("signal");
		return -1;
	}
	if (!WIFEXITED(status)) {
		/* shouldn't happen */
		perror("should not happen");
		return -1;
	}
	return WEXITSTATUS(status);
}

static void __error_to_string(int errnumber, char **errstr)
{
	if (errstr == NULL)
		return;
	switch (errnumber) {
	case PKGCMD_ERR_PACKAGE_NOT_FOUND:
		*errstr = PKGCMD_ERR_PACKAGE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_PACKAGE_INVALID:
		*errstr = PKGCMD_ERR_PACKAGE_INVALID_STR;
		break;
	case PKGCMD_ERR_PACKAGE_LOWER_VERSION:
		*errstr = PKGCMD_ERR_PACKAGE_LOWER_VERSION_STR;
		break;
	case PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND:
		*errstr = PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_MANIFEST_INVALID:
		*errstr = PKGCMD_ERR_MANIFEST_INVALID_STR;
		break;
	case PKGCMD_ERR_CONFIG_NOT_FOUND:
		*errstr = PKGCMD_ERR_CONFIG_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_CONFIG_INVALID:
		*errstr = PKGCMD_ERR_CONFIG_INVALID_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_NOT_FOUND:
		*errstr = PKGCMD_ERR_SIGNATURE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_INVALID:
		*errstr = PKGCMD_ERR_SIGNATURE_INVALID_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED:
		*errstr = PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED_STR;
		break;
	case PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND:
		*errstr = PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_INVALID:
		*errstr = PKGCMD_ERR_CERTIFICATE_INVALID_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED:
		*errstr = PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_EXPIRED:
		*errstr = PKGCMD_ERR_CERTIFICATE_EXPIRED_STR;
		break;
	case PKGCMD_ERR_INVALID_PRIVILEGE:
		*errstr = PKGCMD_ERR_INVALID_PRIVILEGE_STR;
		break;
	case PKGCMD_ERR_MENU_ICON_NOT_FOUND:
		*errstr = PKGCMD_ERR_MENU_ICON_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_FATAL_ERROR:
		*errstr = PKGCMD_ERR_FATAL_ERROR_STR;
		break;
	case PKGCMD_ERR_OUT_OF_STORAGE:
		*errstr = PKGCMD_ERR_OUT_OF_STORAGE_STR;
		break;
	case PKGCMD_ERR_OUT_OF_MEMORY:
		*errstr = PKGCMD_ERR_OUT_OF_MEMORY_STR;
		break;
	case PKGCMD_ERR_ARGUMENT_INVALID:
		*errstr = PKGCMD_ERR_ARGUMENT_INVALID_STR;
		break;
	default:
		*errstr = PKGCMD_ERR_UNKNOWN_STR;
		break;
	}
}

static void __add_op_cbinfo(pkgmgr_client_t *pc, int request_id,
		const char *req_key, pkgmgr_handler event_cb, void* new_event_cb,
		void *data)
{
	req_cb_info *cb_info;
	req_cb_info *current;
	req_cb_info *prev;

	cb_info = (req_cb_info *) calloc(1, sizeof(req_cb_info));
	if (cb_info == NULL) {
		_LOGD("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->req_key = strdup(req_key);
	cb_info->event_cb = event_cb;
	cb_info->data = data;
	cb_info->next = NULL;
	pc->new_event_cb = new_event_cb;

	if (pc->info.request.rhead == NULL)
		pc->info.request.rhead = cb_info;
	else {
		current = prev = pc->info.request.rhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static req_cb_info *__find_op_cbinfo(pkgmgr_client_t *pc, const char *req_key)
{
	req_cb_info *tmp;

	tmp = pc->info.request.rhead;

	if (tmp == NULL) {
		_LOGE("tmp is NULL");
		return NULL;
	}

	while (tmp) {
		if (strncmp(tmp->req_key, req_key, strlen(tmp->req_key)) == 0)
			return tmp;
		tmp = tmp->next;
	}
	return NULL;
}

static void __add_stat_cbinfo(pkgmgr_client_t *pc, int request_id,
			      pkgmgr_handler event_cb, void *data)
{
	listen_cb_info *cb_info;
	listen_cb_info *current;
	listen_cb_info *prev;

	cb_info = (listen_cb_info *) calloc(1, sizeof(listen_cb_info));
	if (cb_info == NULL) {
		_LOGD("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->event_cb = event_cb;
	cb_info->data = data;
	cb_info->next = NULL;

	/* TODO - check the order of callback - FIFO or LIFO => Should be changed to LIFO */
	if (pc->info.listening.lhead == NULL)
		pc->info.listening.lhead = cb_info;
	else {
		current = prev = pc->info.listening.lhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static void __add_stat_cbinfo_with_zone(pkgmgr_client_t *pc, int request_id,
		pkgmgr_handler_with_zone event_cb, void *data)
{
	listen_cb_info *cb_info;
	listen_cb_info *current;
	listen_cb_info *prev;

	cb_info = (listen_cb_info *) calloc(1, sizeof(listen_cb_info));
	if (cb_info == NULL) {
		_LOGD("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->event_cb_with_zone = event_cb;
	cb_info->with_zone = 1;
	cb_info->data = data;
	cb_info->next = NULL;

	/* TODO - check the order of callback - FIFO or LIFO => Should be changed to LIFO */
	if (pc->info.listening.lhead == NULL)
		pc->info.listening.lhead = cb_info;
	else {
		current = prev = pc->info.listening.lhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static void __operation_callback(void *cb_data, const char *req_id,
				 const char *pkg_type, const char *pkgid,
				 const char *key, const char *val, const char *zone)
{
	pkgmgr_client_t *pc;
	req_cb_info *cb_info;

	pc = (pkgmgr_client_t *) cb_data;

	/* find callback info */
	cb_info = __find_op_cbinfo(pc, req_id);
	if (cb_info == NULL)
		return;

	/* call callback */
	if (cb_info->event_cb) {
		if (pc->new_event_cb)
		{
			cb_info->event_cb(cb_info->request_id, pkg_type, pkgid, key,
					val, pc, cb_info->data);
		}
		else
		{
			cb_info->event_cb(cb_info->request_id, pkg_type, pkgid, key,
					val, NULL, cb_info->data);
		}
	}

	/*remove callback for last call
	   if (strcmp(key, "end") == 0) {
	   __remove_op_cbinfo(pc, cb_info);
	   _LOGD("__remove_op_cbinfo");
	   }
	 */

	return;
}

static void __status_callback(void *cb_data, const char *req_id,
			      const char *pkg_type, const char *pkgid,
			      const char *key, const char *val, const char *zone)
{
	pkgmgr_client_t *pc;
	listen_cb_info *tmp;
	int with_zone = 0;
	int ret = 0;

	pc = (pkgmgr_client_t *) cb_data;

	tmp = pc->info.listening.lhead;
	while (tmp) {
		with_zone = tmp->with_zone;
		if (with_zone && tmp->event_cb_with_zone) {
			_LOGD("call event_cb_with_zone");
			ret = tmp->event_cb_with_zone(tmp->request_id, pkg_type, pkgid, key, val, NULL, tmp->data, zone);
		} else {
			ret = tmp->event_cb(tmp->request_id, pkg_type, pkgid, key, val, NULL, tmp->data);
		}

		if (ret != 0)
			break;
		tmp = tmp->next;
	}

	return;
}

static char *__get_str(const char* str, const char* pKey)
{
	const char* p = NULL;
	const char* pStart = NULL;
	const char* pEnd = NULL;

	if (str == NULL)
		return NULL;

	char *pBuf = strdup(str);
	if(!pBuf){
		_LOGE("Malloc failed!");
		return NULL;
	}

	p = strstr(pBuf, pKey);
	if (p == NULL){
		if(pBuf){
			free(pBuf);
			pBuf = NULL;
		}
		return NULL;
	}

	pStart = p + strlen(pKey);
	pEnd = strchr(pStart, SEPERATOR_END);
	if (pEnd == NULL){
		if(pBuf){
			free(pBuf);
			pBuf = NULL;
		}
		return NULL;
	}
	size_t len = pEnd - pStart;
	if (len <= 0){
		if(pBuf){
			free(pBuf);
			pBuf = NULL;
		}
		return NULL;
	}
	char *pRes = (char*)malloc(len + 1);
	if(!pRes){
		if(pBuf){
			free(pBuf);
			pBuf = NULL;
		}
		_LOGE("Malloc failed!");
		return NULL;
	}
	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	if(pBuf){
		free(pBuf);
		pBuf = NULL;
	}

	return pRes;
}

static char *__get_req_key(const char *pkg_path)
{
	struct timeval tv;
	long curtime;
	char timestr[PKG_STRING_LEN_MAX];
	char *str_req_key;
	int size;

	gettimeofday(&tv, NULL);
	curtime = tv.tv_sec * 1000000 + tv.tv_usec;
	snprintf(timestr, sizeof(timestr), "%ld", curtime);

	size = strlen(pkg_path) + strlen(timestr) + 2;
	str_req_key = (char *)calloc(size, sizeof(char));
	if (str_req_key == NULL) {
		_LOGD("calloc failed");
		return NULL;
	}
	snprintf(str_req_key, size, "%s_%s", pkg_path, timestr);

	return str_req_key;
}

static int __get_pkgid_by_appid(const char *appid, char **pkgid)
{
	pkgmgrinfo_appinfo_h appinfo_h = NULL;
	int ret = -1;
	char *pkg_id = NULL;
	char *pkg_id_dup = NULL;

	if (pkgmgrinfo_appinfo_get_appinfo(appid, &appinfo_h) != PMINFO_R_OK)
		return -1;

	if (pkgmgrinfo_appinfo_get_pkgid(appinfo_h, &pkg_id) != PMINFO_R_OK)
		goto err;

	pkg_id_dup = strdup(pkg_id);
	if (pkg_id_dup == NULL)
		goto err;

	*pkgid = pkg_id_dup;
	ret = PMINFO_R_OK;

err:
	pkgmgrinfo_appinfo_destroy_appinfo(appinfo_h);

	return ret;
}

int __appinfo_cb(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = 0;
	char *appid = NULL;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	retvm_if(ret != PMINFO_R_OK, PKGMGR_R_ERROR, "pkgmgrinfo_appinfo_get_appid fail");

	(* (char **) user_data) = strdup(appid);

	return PMINFO_R_OK;
}

static char *__get_app_info_from_db_by_apppath(const char *apppath)
{
	int ret = 0;
	char *caller_appid = NULL;
	pkgmgrinfo_appinfo_filter_h appinfo_filter_h= NULL;

	ret = pkgmgrinfo_appinfo_filter_create(&appinfo_filter_h);
	retvm_if(ret != PMINFO_R_OK, NULL, "pkgmgrinfo_appinfo_filter_create fail");

	ret = pkgmgrinfo_appinfo_filter_add_string(appinfo_filter_h, PMINFO_APPINFO_PROP_APP_EXEC, apppath);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "PMINFO_APPINFO_PROP_APP_EXEC failed, ret=%d", ret);

	ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(appinfo_filter_h, __appinfo_cb, &caller_appid);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "foreach_appinfo failed, ret=%d", ret);

catch:

	pkgmgrinfo_appinfo_filter_destroy(appinfo_filter_h);
	return caller_appid;
}

static inline int __read_proc(const char *path, char *buf, int size)
{
	int fd = 0;
	int ret = 0;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

char *__proc_get_cmdline_bypid(int pid)
{
	char buf[PKG_STRING_LEN_MAX] = {'\0', };
	int ret = 0;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	/* support app launched by shell script*/
	if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0)
		return strdup(&buf[BINSH_SIZE + 1]);
	else
		return strdup(buf);
}

static int __is_core_type_csc(char *pkgid)
{
	int ret = -1;

	char tizen_manifest[PKG_STRING_LEN_MAX] = {'\0', };
	snprintf(tizen_manifest, PKG_STRING_LEN_MAX, "/opt/usr/apps/%s/tizen-manifest.xml", pkgid);

	if (access(tizen_manifest, F_OK)==0) {
		ret = 1;
	} else {
		snprintf(tizen_manifest, PKG_STRING_LEN_MAX, "/usr/apps/%s/tizen-manifest.xml", pkgid);
		if (access(tizen_manifest, F_OK)==0) {
			ret = 1;
		}
	}

	return ret;
}

static int __is_core_tpk_csc(char *description)
{
	int ret = 0;
	char *path_str = NULL;
	char *op_str = NULL;
	char *pkg_type = NULL;
	char csc_str[PKG_STRING_LEN_MAX] = {'\0'};
	snprintf(csc_str, PKG_STRING_LEN_MAX - 1, "%s:", description);

	_LOGD("csc_str [%s]\n", csc_str);

	path_str = __get_str(csc_str, TOKEN_PATH_STR);
	tryvm_if(path_str == NULL, ret = PKGMGR_R_ERROR, "path_str is NULL");

	op_str = __get_str(csc_str, TOKEN_OP_STR);
	tryvm_if(op_str == NULL, ret = PKGMGR_R_ERROR, "op_str is NULL");

	_LOGD("path_str [%s], op_str [%s]\n", path_str, op_str);

	if (strcmp(op_str, "uninstall") == 0) {
		ret = __is_core_type_csc(path_str);
	} else {
		pkg_type = _get_backend_from_zip(path_str);
		if (pkg_type) {
			if (strstr(pkg_type, "coretpk"))
				ret = 1;
			else
				ret  =-1;
			free(pkg_type);
		}
	}

catch:

	if(path_str)
		free(path_str);
	if(op_str)
		free(op_str);

	return ret;
}

static int __get_appid_bypid(int pid, char *pkgname, int len)
{
	char *cmdline = NULL;
	char *caller_appid = NULL;

	cmdline = __proc_get_cmdline_bypid(pid);
	if (cmdline == NULL)
		return -1;

	caller_appid = __get_app_info_from_db_by_apppath(cmdline);
	snprintf(pkgname, len, "%s", caller_appid);

	free(cmdline);
	free(caller_appid);

	return 0;
}

static char *__get_caller_pkgid()
{
	char caller_appid[PKG_STRING_LEN_MAX] = {0, };
	char *caller_pkgid = NULL;

	if (__get_appid_bypid(getpid(), caller_appid, sizeof(caller_appid)) < 0) {
		return NULL;
	}
	if (__get_pkgid_by_appid((const char*)caller_appid, &caller_pkgid) < 0){
		return NULL;
	}

	return caller_pkgid;
}

static inline int __pkgmgr_read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

static inline int __pkgmgr_find_pid_by_cmdline(const char *dname,
				      const char *cmdline, const char *apppath)
{
	int pid = 0;

	if (strncmp(cmdline, apppath, PKG_STRING_LEN_MAX-1) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid))
			pid = 0;
	}

	return pid;
}

void __make_sizeinfo_file(char *description)
{
	FILE* file = NULL;
	int fd = 0;

	if(description == NULL)
		return;

	file = fopen(PKG_SIZE_INFO_FILE, "w");
	if (file == NULL) {
		_LOGE("Couldn't open the file %s \n", PKG_SIZE_INFO_FILE);
		return;
	}

	fwrite(description, 1, strlen(description), file);
	fflush(file);
	fd = fileno(file);
	fsync(fd);
	fclose(file);
}

static int __check_sync_condition(char *req_key)
{
	int ret = 0;
	ssize_t r;
	char *buf;
	size_t len;

	char info_file[PKG_STRING_LEN_MAX] = {'\0', };

	snprintf(info_file, PKG_STRING_LEN_MAX, "%s/%s", PKG_SIZE_INFO_PATH, req_key);
	if (access(info_file, F_OK)==0) {
		_LOGE("sync check file[%s] exist !!! it is need to delete\n",info_file);

		r = lgetxattr (info_file, "security.SMACK64", NULL, 0);
		if (r == -1) {
			_LOGE("get smack attr len error(%d)\n", errno);
			return -1;
		}

		len = r;
		buf = malloc(len);
		if (buf == NULL) {
			_LOGE("malloc fail");
			return -1;
		}

		r = lgetxattr (info_file, "security.SMACK64", buf, len);
		if (r == -1) {
			_LOGE("get smack attr error(%d)\n", errno);
			free(buf);
			return -1;
		}

		if (len != (size_t) r) {
			_LOGE("unexpected size(%zu/%zd)\n", len, r);
			free(buf);
			return -1;
		}

		_LOGE("file[%s] has smack[%s]\n", info_file, buf);

		free(buf);

		ret = remove(info_file);
		if (ret < 0)
			_LOGD("file is can not remove[%s, %d]\n", info_file, ret);
	}
	return ret;
}

static int __check_sync_process(char *req_key)
{
	int ret = 0;
	char info_file[PKG_STRING_LEN_MAX] = {'\0', };
	int result = -1;
	int check_cnt = 0;
	FILE *fp;
	char buf[PKG_STRING_LEN_MAX] = {0};

	snprintf(info_file, PKG_STRING_LEN_MAX, "%s/%s", PKG_SIZE_INFO_PATH, req_key);
	while(1)
	{
		check_cnt ++;

		if (access(info_file, F_OK)==0) {
			fp = fopen(info_file, "r");
			if (fp == NULL){
				_LOGD("file is not generated yet.... wait\n");
				usleep(100 * 1000);	/* 100ms sleep*/
				continue;
			}

			fgets(buf, PKG_STRING_LEN_MAX, fp);
			fclose(fp);

			_LOGD("info_file file is generated, result = %s. \n", buf);
			result = atoi(buf);
			break;
		}

		_LOGD("file is not generated yet.... wait\n");
		usleep(100 * 1000);	/* 100ms sleep*/

		if (check_cnt > 6000) {	/* 60s * 10 time over*/
			_LOGE("wait time over!!\n");
			break;
		}
	}

	ret = remove(info_file);
	if (ret < 0)
		_LOGE("file is can not remove[%s, %d]\n", info_file, ret);

	return result;
}

static int __enable_pkg()
{
	int ret = 0;
	FILE *fp = NULL;
	char *file_path = PKG_DISABLED_LIST_FILE;
	char pkgid[PKG_STRING_LEN_MAX] = {'\0',};

	fp = fopen(file_path, "r");
	retvm_if(fp == NULL, -1, "fopen is failed.");

	while (fgets(pkgid, PKG_STRING_LEN_MAX - 1, fp) != NULL) {
		ret = pkgmgr_parser_enable_pkg(pkgid, NULL);
		if (ret < 0) {
			_LOGE("pkgmgr_parser_enable_pkg is failed. pkgid is [%s].\n", pkgid);
			continue;
		}
		_LOGD("pkgid [%s] is enabled.\n", pkgid);
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
}

static int __disable_pkg()
{
	int ret = 0;
	FILE *fp = NULL;
	char *file_path = PKG_DISABLED_LIST_FILE;
	char pkgid[PKG_STRING_LEN_MAX] = {'\0',};

	fp = fopen(file_path, "r");
	retvm_if(fp == NULL, -1, "fopen is failed.");

	while (fgets(pkgid, PKG_STRING_LEN_MAX - 1, fp) != NULL) {
		ret = pkgmgr_parser_disable_pkg(pkgid, NULL);
		if (ret < 0) {
			_LOGE("pkgmgr_parser_disable_pkg is failed. pkgid is [%s].\n", pkgid);
			continue;
		}
		_LOGD("pkgid [%s] is disabled.\n", pkgid);
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
}

static int __csc_process(const char *csc_path, char *result_path)
{
	int ret = 0;
	int cnt = 0;
	int count = 0;
	int csc_fail = 0;
	int fd = 0;
	char *pkgtype = NULL;
	char *des = NULL;
	char buf[PKG_STRING_LEN_MAX] = {0,};
	char type_buf[1024] = { 0 };
	char des_buf[1024] = { 0 };
	dictionary *csc = NULL;
	FILE* file = NULL;

	if (__enable_pkg() < 0) {
		_LOGE("__enable_pkg fail");
	}

	csc = iniparser_load(csc_path);
	retvm_if(csc == NULL, PKGMGR_R_EINVAL, "cannot open parse file [%s]", csc_path);

	file = fopen(result_path, "w");
	tryvm_if(file == NULL, ret = PKGMGR_R_EINVAL, "cannot open result file [%s]", result_path);

	count = iniparser_getint(csc, "csc packages:count", -1);
	tryvm_if(count == 0, ret = PKGMGR_R_ERROR, "csc [%s] dont have packages", csc_path);

	snprintf(buf, PKG_STRING_LEN_MAX, "[result]\n");
	fwrite(buf, 1, strlen(buf), file);
	snprintf(buf, PKG_STRING_LEN_MAX, "count = %d\n", count);
	fwrite(buf, 1, strlen(buf), file);

	for(cnt = 1 ; cnt <= count ; cnt++)
	{
		snprintf(type_buf, PKG_STRING_LEN_MAX - 1, "csc packages:type_%03d", cnt);
		snprintf(des_buf, PKG_STRING_LEN_MAX - 1, "csc packages:description_%03d", cnt);

		pkgtype = iniparser_getstr(csc, type_buf);
		des = iniparser_getstr(csc, des_buf);
		ret = 0;

		if (pkgtype == NULL) {
			csc_fail++;
			snprintf(buf, PKG_STRING_LEN_MAX, "%s = Fail to get pkgtype\n", type_buf);
			fwrite(buf, 1, strlen(buf), file);
			continue;
		} else if (des == NULL) {
			csc_fail++;
			snprintf(buf, PKG_STRING_LEN_MAX, "%s = Fail to get description\n", des_buf);
			fwrite(buf, 1, strlen(buf), file);
			continue;
		}

		snprintf(buf, PKG_STRING_LEN_MAX, "type_%03d = %s\n", cnt, pkgtype);
		fwrite(buf, 1, strlen(buf), file);
		snprintf(buf, PKG_STRING_LEN_MAX, "description_%03d = %s\n", cnt, des);
		fwrite(buf, 1, strlen(buf), file);

		if (strcmp(pkgtype, "tpk") == 0) {
			if (__is_core_tpk_csc(des) == 1) {
				const char *coreinstaller_argv[] = { "/usr/bin/rpm-backend", "-c", des, NULL };
				ret = __xsystem(coreinstaller_argv);
			} else {
				const char *ospinstaller_argv[] = { "/usr/bin/osp-installer", "-c", des, NULL };
				ret = __xsystem(ospinstaller_argv);
			}
		} else if (strcmp(pkgtype, "wgt")== 0) {
			const char *wrtinstaller_argv[] = { "/usr/bin/wrt-installer", "-c", des, NULL };
			ret = __xsystem(wrtinstaller_argv);
		} else if (strcmp(pkgtype, "xml")== 0) {
			const char *rpminstaller_argv[] = { "/usr/bin/rpm-backend", "-k", "csc-xml", "-s", des, NULL };
			ret = __xsystem(rpminstaller_argv);
		} else {
			csc_fail++;
			ret = -1;
		}

		if (ret != 0) {
			char *errstr = NULL;
			__error_to_string(ret, &errstr);
			snprintf(buf, PKG_STRING_LEN_MAX, "result_%03d = fail[%s]\n", cnt, errstr);
		}
		else
			snprintf(buf, PKG_STRING_LEN_MAX, "result_%03d = success\n", cnt);

		fwrite(buf, 1, strlen(buf), file);
	}

catch:
	iniparser_freedict(csc);
	if (file != NULL) {
		fflush(file);
		fd = fileno(file);
		fsync(fd);
		fclose(file);
	}

	if (__disable_pkg() < 0) {
		_LOGE("__disable_pkg fail");
	}

	if (pkgmgr_parser_update_app_aliasid() < 0) {
		_LOGE("pkgmgr_parser_update_app_aliasid fail");
	}

	const char *argv_parser[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_PARSER_DB_FILE, NULL };
	__xsystem(argv_parser);
	const char *argv_parserjn[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_PARSER_DB_FILE_JOURNAL, NULL };
	__xsystem(argv_parserjn);

	return ret;
}

static int __get_size_process(pkgmgr_client * pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data)
{
	char *req_key = NULL;
	int ret =0;
	char *pkgtype = "getsize";
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int i = 0;
	char buf[128] = {'\0'};
	char *cookie = NULL;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	req_key = __get_req_key(pkgid);
	if (!req_key) {
		ret = PKGMGR_R_ENOMEM;
		goto catch;
	}

	snprintf(buf, 128, "%d", get_type);
	argv[argcnt++] = strdup(pkgid);
	argv[argcnt++] = strdup(buf);
	argv[argcnt++] = strdup(req_key);

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "args alloc fail");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* request */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_GET_SIZE, pkgtype, pkgid, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "COMM_REQ_GET_SIZE failed, ret=%d\n", ret);

	ret = __check_sync_process(req_key);
	if (ret < 0)
		_LOGE("get size failed, ret=%d\n", ret);

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);
	if (req_key)
		free(req_key);

	return ret;
}

static int __move_pkg_process(pkgmgr_client * pc, const char *pkgid, pkgmgr_move_type move_type, pkgmgr_handler event_cb, void *data)
{
	_LOGE("move pkg[%s] start.", pkgid);

	char *req_key = NULL;
	int ret =0;
	pkgmgrinfo_pkginfo_h handle;
	char *pkgtype = NULL;
	char *installer_path = NULL;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int i = 0;
	char buf[128] = {'\0'};
	char *cookie = NULL;
	pkgmgrinfo_install_location location = 0;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_pkginfo failed");

	pkgmgrinfo_pkginfo_get_install_location(handle, &location);
	tryvm_if(location == PMINFO_INSTALL_LOCATION_INTERNAL_ONLY, ret = PKGMGR_R_ERROR, "package[%s] is internal-only, can not be moved", pkgid);

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_type failed");

	installer_path = _get_backend_path(pkgid);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_ERROR, "installer_path fail");

	req_key = __get_req_key(pkgid);
	tryvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

//	req_id = _get_request_id();

	/* generate argv */
	snprintf(buf, 128, "%d", move_type);
	/* argv[0] installer path */
	argv[argcnt++] = strdup(installer_path);
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-m");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	/* argv[5] */
	argv[argcnt++] = strdup("-t");
	/* argv[6] */
	argv[argcnt++] = strdup(buf);
	/* argv[7] */
	argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "args alloc fail");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	ret = __check_sync_condition((char*)pkgid);

	/* 6. request */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_MOVER, pkgtype, pkgid, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "COMM_REQ_TO_MOVER failed, ret=%d\n", ret);

	ret = __check_sync_process((char*)pkgid);
	if (ret != 0)
		_LOGE("move pkg failed, ret=%d\n", ret);

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);
	if (installer_path)
		free(installer_path);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	_LOGE("move pkg[%s] finish, ret=[%d]", pkgid, ret);
	return ret;
}

static int __check_app_process(pkgmgr_request_service_type service_type, pkgmgr_client * pc, const char *pkgid, void *data)
{
	char *pkgtype = NULL;
	char *req_key = NULL;
	int ret = 0;
	pkgmgrinfo_pkginfo_h handle = NULL;
	int pid = -1;

	/* Check for NULL value of pc */
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_pkginfo failed");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_type failed");

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);
	tryvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	/* 3. request activate */
	if (service_type == PM_REQUEST_KILL_APP)
		ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_KILL_APP, pkgtype, pkgid, NULL, NULL, 1);
	else if (service_type == PM_REQUEST_CHECK_APP)
		ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_CHECK_APP, pkgtype, pkgid, NULL, NULL, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "comm_client_request[type %d] failed, ret=%d\n", service_type, ret);

	pid  = __check_sync_process((char*)pkgid);
	* (int *) data = pid;

catch:
	if (req_key)
		free(req_key);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;

}

static int __request_size_info(pkgmgr_client *pc)
{
	char *req_key = NULL;
	int ret =0;
	char *pkgtype = "getsize";
	char *pkgid = "size_info";
	pkgmgr_getsize_type get_type = PM_GET_SIZE_INFO;

	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int i = 0;
	char buf[128] = {'\0'};
	char *cookie = NULL;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	req_key = __get_req_key(pkgid);
	retvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	snprintf(buf, 128, "%d", get_type);
	argv[argcnt++] = strdup(pkgid);
	argv[argcnt++] = strdup(buf);
	argv[argcnt++] = strdup(req_key);

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "args alloc fail");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("args=[%s], len=[%d]", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* request */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_GET_SIZE, pkgtype, pkgid, args, cookie, 1);
	if (ret < 0) {
		_LOGE("COMM_REQ_GET_SIZE failed, ret=%d\n", ret);
	}

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);
	if (req_key)
		free(req_key);

	return ret;
}

static int __change_op_cb_for_getsize(pkgmgr_client *pc)
{
	int ret = -1;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/*  free listening head */
	req_cb_info *tmp = NULL;
	req_cb_info *prev = NULL;
	for (tmp = mpc->info.request.rhead; tmp;) {
		prev = tmp;
		tmp = tmp->next;
		free(prev);
	}

	/* free dbus connection */
	ret = comm_client_free(mpc->info.request.cc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "comm_client_free() failed - %d", ret);

	/* Manage pc for seperated event */
	mpc->ctype = PC_REQUEST;
	mpc->status_type = PKGMGR_CLIENT_STATUS_GET_SIZE;


	mpc->info.request.cc = comm_client_new();
	retvm_if(mpc->info.request.cc == NULL, PKGMGR_R_ERROR, "client creation failed");

	ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_GET_SIZE, mpc->info.request.cc, __operation_callback, pc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "set_status_callback() failed - %d", ret);

	return PKGMGR_R_OK;
}

static int __get_pkg_size_info_cb(int req_id, const char *req_type,
		const char *pkgid, const char *key,
		const char *value, const void *pc, void *user_data)
{
	int ret = 0;
	_LOGS("reqid: %d, req type: %s, pkgid: %s, unused key: %s, size info: %s",
			req_id, req_type, pkgid, key, value);

	pkg_size_info_t *size_info = (pkg_size_info_t *)calloc(1, sizeof(pkg_size_info_t));
	retvm_if(size_info == NULL, -1, "The memory is insufficient.");

	char *save_ptr = NULL;
	char *token = strtok_r((char*)value, ":", &save_ptr);
	tryvm_if(token == NULL, -1, "token is null.");

	size_info->data_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	if (token)
		size_info->cache_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	if (token)
		size_info->app_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	if (token)
		size_info->ext_data_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	if (token)
		size_info->ext_cache_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	if (token)
		size_info->ext_app_size = atoll(token);

	_LOGS("data: %lld, cache: %lld, app: %lld, ext_data: %lld, ext_cache: %lld, ext_app: %lld",
			size_info->data_size, size_info->cache_size, size_info->app_size,
			size_info->ext_data_size, size_info->ext_cache_size, size_info->ext_app_size);

	pkgmgr_client_t *pmc = (pkgmgr_client_t *)pc;
	tryvm_if(pmc == NULL, ret = -1, "pkgmgr_client instance is null.");

	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0)
	{	// total package size info
		pkgmgr_total_pkg_size_info_receive_cb callback = (pkgmgr_total_pkg_size_info_receive_cb)(pmc->new_event_cb);
		callback((pkgmgr_client *)pc, size_info, user_data);
	}
	else
	{
		pkgmgr_pkg_size_info_receive_cb callback = (pkgmgr_pkg_size_info_receive_cb)(pmc->new_event_cb);
		callback((pkgmgr_client *)pc, pkgid, size_info, user_data);
	}

catch:

	if(size_info){
		free(size_info);
		size_info = NULL;
	}
	return ret;
}

static int __get_package_size_info(pkgmgr_client_t *mpc, char *req_key, const char *pkgid, pkgmgr_getsize_type get_type)
{
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	char *pkgtype = "getsize"; //unused
	char buf[128] = { 0, };
	int len = 0;
	char *cookie = NULL;
	char *temp = NULL;
	int i = 0;
	int ret = 0;

	snprintf(buf, 128, "%d", get_type);
	argv[argcnt++] = strdup(pkgid);
	argv[argcnt++] = strdup(buf);
	argv[argcnt++] = strdup("-k");
	argv[argcnt++] = req_key;

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "args alloc fail");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* request */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_GET_SIZE, pkgtype, pkgid, args, cookie, 1);
	if (ret < 0)
		_LOGE("COMM_REQ_GET_SIZE failed, ret=%d\n", ret);

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);

	return ret;
}

API pkgmgr_client *pkgmgr_client_new(client_type ctype)
{
	pkgmgr_client_t *pc = NULL;
	int ret = -1;

	retvm_if(ctype != PC_REQUEST && ctype != PC_REQUEST_PRIVATE && ctype != PC_LISTENING && ctype != PC_BROADCAST, NULL, "ctype is not client_type");

	/* Allocate memory for ADT:pkgmgr_client */
	pc = calloc(1, sizeof(pkgmgr_client_t));
	retvm_if(pc == NULL, NULL, "No memory");

	/* Manage pc */
	pc->ctype = ctype;
	pc->status_type = PKGMGR_CLIENT_STATUS_ALL;
	pc->pkg_chksum = NULL;

	if (pc->ctype == PC_REQUEST) {
		pc->info.request.cc = comm_client_new();
		trym_if(pc->info.request.cc == NULL, "client creation failed");

		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ALL, pc->info.request.cc, __operation_callback, pc);
		trym_if(ret < 0L, "comm_client_set_status_callback() failed - %d", ret);
	} else if (pc->ctype == PC_LISTENING) {
		pc->info.listening.cc = comm_client_new();
		trym_if(pc->info.listening.cc == NULL, "client creation failed");

		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ALL, pc->info.listening.cc, __status_callback, pc);
		trym_if(ret < 0L, "comm_client_set_status_callback() failed - %d", ret);
	} else if (pc->ctype == PC_BROADCAST) {
		pc->info.broadcast.bc = comm_status_broadcast_server_connect(COMM_STATUS_BROADCAST_ALL);
		trym_if(pc->info.broadcast.bc == NULL, "client creation failed");
	} else if (pc->ctype == PC_REQUEST_PRIVATE) {
		/* set private connection */
		pc->info.request.cc = comm_client_new_private();
		/* reset ctype */
		pc->ctype = PC_REQUEST;
		trym_if(pc->info.request.cc == NULL, "client creation failed (private request)");

		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ALL, pc->info.request.cc, __operation_callback, pc);
		trym_if(ret < 0L, "comm_client_set_status_callback() failed - %d", ret);
	}

	return (pkgmgr_client *) pc;

catch:
	if (pc)
		free(pc);
	return NULL;
}

API int pkgmgr_client_free(pkgmgr_client *pc)
{
	int ret = -1;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc == NULL, PKGMGR_R_EINVAL, "Invalid argument");

	if (mpc->ctype == PC_REQUEST) {
		req_cb_info *tmp;
		req_cb_info *prev;
		for (tmp = mpc->info.request.rhead; tmp;) {
			prev = tmp;
			if(prev->req_key)
				free(prev->req_key);
			tmp = tmp->next;
			free(prev);
		}

		ret = comm_client_free(mpc->info.request.cc);
		tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "comm_client_free() failed");
	} else if (mpc->ctype == PC_LISTENING) {
			listen_cb_info *tmp;
			listen_cb_info *prev;
			for (tmp = mpc->info.listening.lhead; tmp;) {
				prev = tmp;
				tmp = tmp->next;
				free(prev);
			}

			ret = comm_client_free(mpc->info.listening.cc);
			tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "comm_client_free() failed");
	} else if (mpc->ctype == PC_BROADCAST) {
		comm_status_broadcast_server_disconnect(mpc->info.broadcast.bc);
		ret = 0;
	} else {
		_LOGE("Invalid client type\n");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->pkg_chksum) {
		free(mpc->pkg_chksum);
		mpc->pkg_chksum = NULL;
	}

	free(mpc);
	mpc = NULL;
	return PKGMGR_R_OK;

 catch:
	if (mpc) {
		free(mpc);
		mpc = NULL;
	}
	return PKGMGR_R_ERROR;
}

API int pkgmgr_client_install(pkgmgr_client * pc, const char *pkg_type,
			      const char *descriptor_path, const char *pkg_path,
			      const char *optional_file, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data)
{
	_LOGE("install pkg start.");

	char *req_key = NULL;
	int req_id = 0;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = 0;
	char *cookie = NULL;
	char *caller_pkgid = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL");

	/* 0. check the pc type */
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	if (descriptor_path) {
		retvm_if(strlen(descriptor_path) >= PATH_MAX, PKGMGR_R_EINVAL, "descriptor_path over PATH_MAX");
		retvm_if(access(descriptor_path, F_OK) != 0, PKGMGR_R_EINVAL, "descriptor_path access fail");
	}

	retvm_if(pkg_path == NULL, PKGMGR_R_EINVAL, "pkg_path is NULL");
	retvm_if(strlen(pkg_path) >= PATH_MAX, PKGMGR_R_EINVAL, "pkg_path over PATH_MAX");
	retvm_if(access(pkg_path, F_OK) != 0, PKGMGR_R_EINVAL, "pkg_path access fail");

	if (optional_file)
		retvm_if(strlen(optional_file) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "optional_file over PKG_STRING_LEN_MAX");

	/* 3. generate req_key */
	req_key = __get_req_key(pkg_path);
	retvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	caller_pkgid = __get_caller_pkgid();
	if (caller_pkgid != NULL)
		_LOGE("caller pkgid = %s\n", caller_pkgid);

	/* 5. generate argv */

	/*  argv[0] installer path */
	argv[argcnt++] = strdup("arg-start");
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-i");
	/* argv[(4)] if exists */
	if (descriptor_path)
		argv[argcnt++] = strdup(descriptor_path);
	/* argv[4] */
	argv[argcnt++] = strdup(pkg_path);
	/* argv[(5)] if exists */
	if (optional_file){
		argv[argcnt++] = strdup("-o");
		argv[argcnt++] = strdup(optional_file);
	}
	if (caller_pkgid) {
		argv[argcnt++] = strdup("-p");
		argv[argcnt++] = strdup(caller_pkgid);
	}
	if (mpc->debug_mode) {
		argv[argcnt++] = strdup("-G");
	}
	if (mpc->pkg_chksum) {
		argv[argcnt++] = strdup("-C");
		argv[argcnt++] = strdup(mpc->pkg_chksum);
	}


	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALL, pkg_type, pkg_path, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_INSTALL failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);
	if (caller_pkgid)
		free(caller_pkgid);

	_LOGE("install pkg finish, ret=[%d]", ret);

	return ret;
}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
API int pkgmgr_client_install_with_tep(pkgmgr_client * pc, const char *pkg_type,
		const char *descriptor_path, const char *pkg_path,
		const char *tep_path, bool tep_move, const char *optional_file,
		pkgmgr_mode mode, pkgmgr_handler event_cb, void *data)
{
	_LOGE("started tep pkg installation.");

	char *req_key = NULL;
	int req_id = 0;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = 0;
	char *cookie = NULL;
	char *caller_pkgid = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL");

	/* 0. check the pc type */
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	if (descriptor_path && strlen(descriptor_path) == 0)
		descriptor_path = NULL;
	if (pkg_path && strlen(pkg_path) == 0)
		pkg_path = NULL;
	if (tep_path && strlen(tep_path) == 0)
		tep_path = NULL;
	if (optional_file && strlen(optional_file) == 0)
		optional_file = NULL;

  /* 1. check argument */
	if (descriptor_path) {
		retvm_if(strlen(descriptor_path) >= PATH_MAX, PKGMGR_R_EINVAL, "descriptor_path over PATH_MAX");
		retvm_if(access(descriptor_path, F_OK) != 0, PKGMGR_R_EINVAL, "descriptor_path access fail");
	}

	if (tep_path) {
		// if tep alone is getting installed, pkg path can be NULL
		if (pkg_path) {
			retvm_if(strlen(pkg_path) >= PATH_MAX, PKGMGR_R_EINVAL, "pkg_path over PATH_MAX");
			retvm_if(access(pkg_path, F_OK) != 0, PKGMGR_R_EINVAL, "pkg_path access fail");
		}
		retvm_if(strlen(tep_path) >= PATH_MAX, PKGMGR_R_EINVAL, "tep_path over PATH_MAX");
		retvm_if(access(tep_path, F_OK) != 0, PKGMGR_R_EINVAL, "tep_path access fail");
	} else {
		retvm_if(pkg_path == NULL, PKGMGR_R_EINVAL, "pkg_path is NULL");
		retvm_if(strlen(pkg_path) >= PATH_MAX, PKGMGR_R_EINVAL, "pkg_path over PATH_MAX");
		retvm_if(access(pkg_path, F_OK) != 0, PKGMGR_R_EINVAL, "pkg_path access fail");
	}

	if (optional_file)
		retvm_if(strlen(optional_file) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "optional_file over PKG_STRING_LEN_MAX");

	/* 3. generate req_key */
	if (pkg_path)
		req_key = __get_req_key(pkg_path);
	else if (tep_path)
		req_key = __get_req_key(tep_path);
	retvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	caller_pkgid = __get_caller_pkgid();
	if (caller_pkgid != NULL)
		_LOGE("caller pkgid = %s\n", caller_pkgid);

	/* 5. generate argv */

	/*  argv[0] installer path */
	argv[argcnt++] = strdup("arg-start");
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	if (pkg_path)
		argv[argcnt++] = strdup("-i");
	/* argv[(4)] if exists */
	if (descriptor_path)
		argv[argcnt++] = strdup(descriptor_path);
	/* argv[4] */
	if (pkg_path)
		argv[argcnt++] = strdup(pkg_path);

	/* argv[(5)] if exists */
	if(tep_path) {
		argv[argcnt++] = strdup("-e");
		argv[argcnt++] = strdup(tep_path);
	}

	if (tep_move == true){
		argv[argcnt++] = strdup("-M");
		argv[argcnt++] = strdup(TEP_MOVE);
	}else{
		argv[argcnt++] = strdup("-M");
		argv[argcnt++] = strdup(TEP_COPY);
	}

	/* argv[(6)] if exists */
	if (optional_file){
		argv[argcnt++] = strdup("-o");
		argv[argcnt++] = strdup(optional_file);
	}
	if (caller_pkgid) {
		argv[argcnt++] = strdup("-p");
		argv[argcnt++] = strdup(caller_pkgid);
	}

	/*** add quote in all string for special character like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request_with_tep(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALL, pkg_type, pkg_path, tep_path, args, cookie, 1);
	trym_if(ret < 0, "COMM_REQ_TO_INSTALL failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);
	if (caller_pkgid)
		free(caller_pkgid);

	_LOGE("finished tep pkg installation, ret=[%d]", ret);

	return ret;
}
#endif

#ifdef _APPFW_FEATURE_MOUNT_INSTALL
API int pkgmgr_client_mount_install(pkgmgr_client * pc, const char *pkg_type,
			const char *pkg_path, const char *optional_file,
			pkgmgr_handler event_cb, void *data)
{
	_LOGE("install pkg start.");

	char *req_key = NULL;
	int req_id = 0;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = 0;
	char *cookie = NULL;
	char *caller_pkgid = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL");

	/* 0. check the pc type */
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	retvm_if(pkg_path == NULL, PKGMGR_R_EINVAL, "pkg_path is NULL");
	retvm_if(strlen(pkg_path) >= PATH_MAX, PKGMGR_R_EINVAL, "pkg_path over PATH_MAX");
	retvm_if(access(pkg_path, F_OK) != 0, PKGMGR_R_EINVAL, "pkg_path access fail");

	if (optional_file)
		retvm_if(strlen(optional_file) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "optional_file over PKG_STRING_LEN_MAX");

	/* 3. generate req_key */
	req_key = __get_req_key(pkg_path);
	retvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	caller_pkgid = __get_caller_pkgid();
	if (caller_pkgid != NULL)
		_LOGE("caller pkgid = %s\n", caller_pkgid);

	/* 5. generate argv */

	/*  argv[0] installer path */
	argv[argcnt++] = strdup("arg-start");
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-i");

	/* argv[4] */
	argv[argcnt++] = strdup(pkg_path);

	argv[argcnt++] = strdup("-w");

	/* argv[(6)] if exists */
	if (optional_file){
		argv[argcnt++] = strdup("-o");
		argv[argcnt++] = strdup(optional_file);
	}
	if (caller_pkgid) {
		argv[argcnt++] = strdup("-p");
		argv[argcnt++] = strdup(caller_pkgid);
	}


	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALL, pkg_type, pkg_path, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_INSTALL failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);
	if (caller_pkgid)
		free(caller_pkgid);

	_LOGE("install pkg finish, ret=[%d]", ret);

	return ret;
}
#endif

API int pkgmgr_client_reinstall(pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
				  const char *optional_file, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data)
{
	_LOGE("reinstall pkg start.");

	char *pkgtype = NULL;
	char *installer_path = NULL;
	char *req_key = NULL;
	int req_id = 0;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = 0;
	char *cookie = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retv_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL);


	/* 1. check argument */
	retv_if(pkgid == NULL, PKGMGR_R_EINVAL);
	retv_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL);
	if (optional_file) {
		if (strlen(optional_file) >= PKG_STRING_LEN_MAX)
			return PKGMGR_R_EINVAL;
	}

	/* 2. get installer path using pkg_path */
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgrinfo_pkginfo_get_pkginfo fail");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgrinfo_pkginfo_get_type fail");

	installer_path = _get_backend_path(pkgid);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);
	tryvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	/* 5. generate argv */

	/*  argv[0] installer path */
	argv[argcnt++] = strdup(installer_path);
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-r");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	/* argv[(5)] if exists */
	if (optional_file){
		argv[argcnt++] = strdup("-o");
		argv[argcnt++] = strdup(optional_file);
	}

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALL, pkgtype, pkgid, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_INSTALL failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);
	if (installer_path)
		free(installer_path);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	_LOGE("reinstall pkg finish, ret=[%d]", ret);

	return ret;
}

API int pkgmgr_client_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data)
{
	_LOGE("uninstall pkg start.");

	char *pkgtype = NULL;
	char *installer_path = NULL;
	char *req_key = NULL;
	int req_id = 0;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = -1;
	char *cookie = NULL;
	bool removable = false;
	char *caller_pkgid = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retv_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL);

	/* 1. check argument */
	retv_if(pkgid == NULL, PKGMGR_R_EINVAL);

	pkgmgrinfo_pkginfo_h handle = NULL;
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret < 0) {
		ret = pkgmgrinfo_pkginfo_get_unmounted_pkginfo(pkgid, &handle);
	}

	/*check package id	*/
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgrinfo_pkginfo_get_pkginfo fail");
	tryvm_if(handle == NULL, ret = PKGMGR_R_EINVAL, "Pkgid(%s) can not find in installed pkg DB! \n", pkgid);

	/*check type	*/
	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgrinfo_pkginfo_get_type fail");
	tryvm_if(pkgtype == NULL, ret = PKGMGR_R_ERROR, "pkgtype is NULL");

	/*check removable*/
	pkgmgrinfo_pkginfo_is_removable(handle, &removable);
	tryvm_if(removable == false, ret = PKGMGR_R_ERROR, "Pkgid(%s) can not be removed, This is non-removalbe package...\n", pkgid);

	/*check pkgid length	*/
	tryvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "pkgid is too long");

	/* 2. get installer path using pkgtype */
	installer_path = _get_backend_path(pkgid);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);
	tryvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	caller_pkgid = __get_caller_pkgid();
	if (caller_pkgid != NULL)
		_LOGE("caller pkgid = %s\n", caller_pkgid);

	/* 5. generate argv */

	/* argv[0] installer path */
	argv[argcnt++] = strdup(installer_path);
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-d");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	if (caller_pkgid) {
		argv[argcnt++] = strdup("-p");
		argv[argcnt++] = caller_pkgid;
	}


	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request uninstall */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_UNINSTALL, pkgtype, pkgid, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_UNINSTALL failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);
	if (installer_path)
		free(installer_path);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	_LOGE("uninstall pkg finish, ret=[%d]", ret);

	return ret;
}

API int pkgmgr_client_move(pkgmgr_client *pc, const char *pkgid, pkgmgr_move_type move_type, pkgmgr_handler event_cb, void *data)
{
	_LOGE("move pkg[%s] start.", pkgid);

	char *pkgtype = NULL;
	char *installer_path= NULL;
	char *req_key = NULL;
	int req_id = 0;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = -1;
	char *cookie = NULL;
	char buf[128] = {'\0'};
	pkgmgrinfo_install_location location = 0;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retv_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL);

	/* 1. check argument */
	retv_if(pkgid == NULL, PKGMGR_R_EINVAL);

	pkgmgrinfo_pkginfo_h handle;
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);

	/*check package id	*/
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgrinfo_pkginfo_get_pkginfo fail");
	tryvm_if(handle == NULL, ret = PKGMGR_R_EINVAL, "Pkgid(%s) can not find in installed pkg DB! \n", pkgid);

	pkgmgrinfo_pkginfo_get_install_location(handle, &location);
	tryvm_if(location == PMINFO_INSTALL_LOCATION_INTERNAL_ONLY, ret = PKGMGR_R_ERROR, "package[%s] is internal-only, can not be moved", pkgid);

	/*check type	*/
	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgrinfo_pkginfo_get_type fail");
	tryvm_if(pkgtype == NULL, ret = PKGMGR_R_ERROR, "pkgtype is NULL");

	/*check pkgid length	*/
	tryvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "pkgid is too long");

	/*check move_type	*/
	tryvm_if((move_type < PM_MOVE_TO_INTERNAL) || (move_type > PM_MOVE_TO_SDCARD), ret = PKGMGR_R_EINVAL, "move_type is not supported");

	/* 2. get installer path using pkgtype */
	installer_path = _get_backend_path(pkgid);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);
	tryvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	/* 5. generate argv */
	snprintf(buf, 128, "%d", move_type);
	/* argv[0] installer path */
	argv[argcnt++] = strdup(installer_path);
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-m");
	/* argv[4] */
	argv[argcnt++] = strdup(pkgid);
	/* argv[5] */
	argv[argcnt++] = strdup("-t");
	/* argv[6] */
	argv[argcnt++] = strdup(buf);
	/* argv[5] -q option should be located at the end of command !! */
	argv[argcnt++] = strdup("-q");

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_MOVER, pkgtype, pkgid, args, cookie, 1);
	trym_if(ret < 0, "COMM_REQ_TO_MOVER failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		g_free(cookie);
	if (installer_path)
		free(installer_path);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	_LOGE("move pkg[%s] finish, ret=[%d]", pkgid, ret);

	return ret;
}

API int pkgmgr_client_activate(pkgmgr_client * pc, const char *pkg_type, const char *pkgid)
{
	_LOGE("activate pkg[%s] start", pkgid);

	char *req_key = NULL;
	int ret = 0;
	pkgmgrinfo_pkginfo_h handle = NULL;
	char *cookie = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if ((ret == 0) && (handle != NULL)) {
		SECURE_LOGD("pkg[%s] is already installed.", pkgid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		// This package is already installed. skip the activation event.
		return PKGMGR_R_OK;
	}

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);
	retvm_if(req_key == NULL, PKGMGR_R_ENOMEM, "req_key is NULL");

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_ACTIVATE_PKG, "pkg", pkgid, NULL, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_ACTIVATE_PKG failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	if (req_key)
		free(req_key);
	if (cookie)
		g_free(cookie);
	_LOGE("activate pkg finish[%d]", ret);

	return ret;
}

API int pkgmgr_client_deactivate(pkgmgr_client *pc, const char *pkg_type, const char *pkgid)
{
	_LOGE("deactivate pkg[%s] start", pkgid);

	char *req_key = NULL;
	int ret = 0;
	pkgmgrinfo_pkginfo_h handle = NULL;
	char *cookie = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	// This package is not installed. skip the deactivation event.
	if ((ret < 0) || (handle == NULL)) {
		SECURE_LOGD("pkg[%s] is not installed.", pkgid);
		return PKGMGR_R_OK;
	}

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);
	tryvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_DEACTIVATE_PKG, "pkg", pkgid, NULL, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_DEACTIVATE_PKG failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	if (req_key)
		free(req_key);
	if (cookie)
		g_free(cookie);
	if (handle)
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	_LOGE("deactivate pkg finish, ret=[%d]", ret);

	return ret;
}

API int pkgmgr_client_activate_app(pkgmgr_client * pc, const char *appid)
{
	_LOGE("activate app[%s] start", appid);

	char *req_key = NULL;
	int ret = 0;
	int fd = 0;
	FILE *fp = NULL;
	char activation_info_file[PKG_STRING_LEN_MAX] = { 0, };
	char *cookie = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(appid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(appid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	/* 2. generate req_key */
	req_key = __get_req_key(appid);
	retvm_if(req_key == NULL, PKGMGR_R_ENOMEM, "req_key is NULL");

	snprintf(activation_info_file, PKG_STRING_LEN_MAX, "%s/%s", PKG_DATA_PATH, appid);
	fp = fopen(activation_info_file, "w");
	tryvm_if(fp == NULL, ret = PMINFO_R_ERROR, "rev_file[%s] is null\n", activation_info_file);

	fflush(fp);
	fd = fileno(fp);
	fsync(fd);
	fclose(fp);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_ACTIVATE_APP, "pkg", appid, NULL, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_ACTIVATE_APP failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	if (req_key)
		free(req_key);
	if (cookie)
		g_free(cookie);
	_LOGE("activate app finish, ret=[%d]", ret);

	return ret;
}

API int pkgmgr_client_activate_appv(pkgmgr_client * pc, const char *appid, char *const argv[])
{
	_LOGE("activate app[%s] with label start.", appid);

	char *req_key = NULL;
	int ret = 0;
	int fd = 0;
	FILE *fp = NULL;
	char activation_info_file[PKG_STRING_LEN_MAX] = { 0, };
	char *cookie = NULL;

	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");
	retvm_if(argv == NULL, PKGMGR_R_EINVAL, "argv is NULL\n");
	retvm_if(argv[0] == NULL, PKGMGR_R_EINVAL, "argv[0] is NULL\n");

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(appid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(appid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	/* 2. generate req_key */
	req_key = __get_req_key(appid);
	retvm_if(req_key == NULL, PKGMGR_R_ENOMEM, "req_key is NULL");

	snprintf(activation_info_file, PKG_STRING_LEN_MAX, "%s/%s", PKG_DATA_PATH, appid);
	fp = fopen(activation_info_file, "w");
	tryvm_if(fp == NULL, ret = PKGMGR_R_ERROR, "fopen failed");

	_LOGE("activate_appv label[%s]", argv[1]);
	fwrite(argv[1], sizeof(char), strlen(argv[1]), fp);

	fflush(fp);
	fd = fileno(fp);
	fsync(fd);
	fclose(fp);

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_ACTIVATE_APP_WITH_LABEL, "pkg", appid, argv[1], cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_ACTIVATE_APP_WITH_LABEL failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:

	if (req_key)
		free(req_key);
	if (cookie)
		g_free(cookie);
	_LOGE("activate app with label finish, ret=[%d]", ret);

	return ret;
}

API int pkgmgr_client_deactivate_app(pkgmgr_client *pc, const char *appid)
{
	_LOGE("deactivate app[%s] start.", appid);

	char *req_key = NULL;
	int ret = 0;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");
	char *cookie = NULL;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(appid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");
	retvm_if(strlen(appid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkgid length over PKG_STRING_LEN_MAX ");

	/* 2. generate req_key */
	req_key = __get_req_key(appid);
	retvm_if(req_key == NULL, PKGMGR_R_ENOMEM, "req_key is NULL");

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_DEACTIVATE_APP, "pkg", appid, NULL, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_DEACTIVATOR failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	if (req_key)
		free(req_key);
	if (cookie)
		g_free(cookie);
	_LOGE("deactivate app finish, ret=[%d]", ret);

	return ret;
}

API int pkgmgr_client_enable_app_bg_operation(pkgmgr_client *pc, const char *appid)
{
	_LOGE("enabe app bg operation[%s] start.", appid);

	char *req_key = NULL;
	int ret = 0;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");
	char *cookie = NULL;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(appid == NULL, PKGMGR_R_EINVAL, "appid is NULL");
	retvm_if(strlen(appid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "appid length over PKG_STRING_LEN_MAX ");

	/* 2. generate req_key */
	req_key = __get_req_key(appid);
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_ENABLE_BG_OPERATION, "pkg", appid, NULL, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_ENABLE_BG_OPERATION failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	if(req_key)
		free(req_key);
	if (cookie)
		g_free(cookie);
	_LOGE("enabling app bg operation finish, ret=[%d]", ret);
	return ret;
}

API int pkgmgr_client_disable_app_bg_operation(pkgmgr_client *pc, const char *appid)
{
	_LOGE("disable app bg operation[%s] start.", appid);

	char *req_key = NULL;
	int ret = 0;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client handle is NULL\n");
	char *cookie = NULL;

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	/* 1. check argument */
	retvm_if(appid == NULL, PKGMGR_R_EINVAL, "appid is NULL");
	retvm_if(strlen(appid) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "appid length over PKG_STRING_LEN_MAX ");

	/* 2. generate req_key */
	req_key = __get_req_key(appid);
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ERROR, "__get_cookie_from_security_server is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_DISABLE_BG_OPERATION, "pkg", appid, NULL, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_DISABLE_BG_OPERATION failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	if(req_key)
		free(req_key);
	if (cookie)
		g_free(cookie);
	_LOGE("disabling app bg operation finish, ret=[%d]", ret);
	return ret;
}

API int pkgmgr_client_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				      const char *appid, pkgmgr_mode mode)
{
	_LOGE("clear user data[%s] start.", appid);

	const char *pkgtype = NULL;
	char *pkgid = NULL;
	char *installer_path = NULL;
	char *req_key = NULL;
	int i = 0;
	char *argv[PKG_ARGC_MAX] = { NULL, };
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int ret = 0;
	char *cookie = NULL;

	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_REQUEST)
		return PKGMGR_R_EINVAL;

	/* 1. check argument */
	if (appid == NULL)
		return PKGMGR_R_EINVAL;


	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(appid);
		if (pkgtype == NULL)
			return PKGMGR_R_EINVAL;
	} else
		pkgtype = pkg_type;

	if (strlen(appid) >= PKG_STRING_LEN_MAX)
		return PKGMGR_R_EINVAL;

	/* 2. get installer path using pkg_id */
	if(__get_pkgid_by_appid(appid, &pkgid)){
		return PKGMGR_R_ERROR;
	}

	installer_path = _get_backend_path(pkgid);
	if (installer_path == NULL)
		return PKGMGR_R_EINVAL;

	/* 3. generate req_key */
	req_key = __get_req_key(appid);
	tryvm_if(req_key == NULL, ret = PKGMGR_R_ENOMEM, "req_key is NULL");

	/* 4. generate argv */

	/* argv[0] installer path */
	argv[argcnt++] = strdup(installer_path);
	/* argv[1] */
	argv[argcnt++] = strdup("-k");
	/* argv[2] */
	argv[argcnt++] = req_key;
	/* argv[3] */
	argv[argcnt++] = strdup("-c");
	/* argv[4] */
	argv[argcnt++] = strdup(appid);

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);
	/******************* end of quote ************************/

	/* 6. request clear */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_CLEARER, pkgtype, appid, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_CLEARER failed[%d]", ret);

	ret = PKGMGR_R_OK;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (installer_path)
		free(installer_path);
	if(pkgid)
		free(pkgid);

	_LOGE("clear user data finish, ret=[%d]", ret);

	return ret;
}

API int pkgmgr_client_set_status_type(pkgmgr_client *pc, int status_type)
{
	int ret = -1;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	retvm_if(status_type == PKGMGR_CLIENT_STATUS_ALL, PKGMGR_R_OK, "status_type is PKGMGR_CLIENT_STATUS_ALL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/*  free listening head */
	listen_cb_info *tmp = NULL;
	listen_cb_info *prev = NULL;
	for (tmp = mpc->info.listening.lhead; tmp;) {
		prev = tmp;
		tmp = tmp->next;
		free(prev);
	}

	/* free dbus connection */
	ret = comm_client_free(mpc->info.listening.cc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "comm_client_free() failed - %d", ret);

	/* Manage pc for seperated event */
	mpc->ctype = PC_LISTENING;
	mpc->status_type = status_type;

	mpc->info.listening.cc = comm_client_new();
	retvm_if(mpc->info.listening.cc == NULL, PKGMGR_R_EINVAL, "client creation failed");

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_INSTALL) == PKGMGR_CLIENT_STATUS_INSTALL) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_INSTALL, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "PKGMGR_CLIENT_STATUS_INSTALL failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_UNINSTALL) == PKGMGR_CLIENT_STATUS_UNINSTALL) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_UNINSTALL, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_UNINSTALL failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_MOVE) == PKGMGR_CLIENT_STATUS_MOVE) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_MOVE, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_MOVE failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS) == PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_INSTALL_PROGRESS, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_INSTALL_PROGRESS failed - %d", ret);
	}

   if ((mpc->status_type & PKGMGR_CLIENT_STATUS_UPGRADE) == PKGMGR_CLIENT_STATUS_UPGRADE) {
	   ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_UPGRADE, mpc->info.listening.cc, __status_callback, pc);
	   retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_UPGRADE failed - %d", ret);
   }

   if ((mpc->status_type & PKGMGR_CLIENT_STATUS_GET_SIZE) == PKGMGR_CLIENT_STATUS_GET_SIZE) {
	   ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_GET_SIZE, mpc->info.listening.cc, __status_callback, pc);
	   retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_GET_SIZE failed - %d", ret);
   }

   return PKGMGR_R_OK;
}

API int pkgmgr_client_set_pkg_chksum(pkgmgr_client *pc, char *pkg_chksum)
{
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	retvm_if(pkg_chksum == NULL, PKGMGR_R_EINVAL, "cert value is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	mpc->pkg_chksum = strdup(pkg_chksum);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_set_debug_mode(pkgmgr_client *pc, bool debug_mode)
{
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	mpc->debug_mode = debug_mode;

	return PKGMGR_R_OK;
}


API int pkgmgr_client_listen_status(pkgmgr_client *pc, pkgmgr_handler event_cb,
				    void *data)
{
	int req_id;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check input */
	retvm_if(mpc->ctype != PC_LISTENING, PKGMGR_R_EINVAL, "ctype is not PC_LISTENING");
	retvm_if(event_cb == NULL, PKGMGR_R_EINVAL, "event_cb is NULL");

	/* 1. get id */
	req_id = _get_request_id();

	/* 2. add callback info to pkgmgr_client */
	__add_stat_cbinfo(mpc, req_id, event_cb, data);
	return req_id;
}

API int pkgmgr_client_listen_status_with_zone(pkgmgr_client *pc,
		pkgmgr_handler_with_zone event_cb, void *data)
{
	int req_id;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check input */
	retvm_if(mpc->ctype != PC_LISTENING, PKGMGR_R_EINVAL, "ctype is not PC_LISTENING");
	retvm_if(event_cb == NULL, PKGMGR_R_EINVAL, "event_cb is NULL");

	/* 1. get id */
	req_id = _get_request_id();

	/* 2. add callback info to pkgmgr_client */
	__add_stat_cbinfo_with_zone(mpc, req_id, event_cb, data);

	return req_id;
}

API int pkgmgr_client_broadcast_status(pkgmgr_client *pc, const char *pkg_type,
				       const char *pkgid, const char *key,
				       const char *val)
{
	/* Check for NULL value of pc */
	if (pc == NULL) {
		_LOGD("package manager client handle is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	/* Check for valid arguments. NULL parameter causes DBUS to abort */
	if (pkgid == NULL || pkg_type == NULL || key == NULL || val == NULL) {
		_LOGD("Argument supplied is NULL\n");
		return PKGMGR_R_EINVAL;
	}
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	if (mpc->ctype != PC_BROADCAST)
		return PKGMGR_R_EINVAL;

	comm_status_broadcast_server_send_signal(COMM_STATUS_BROADCAST_ALL, mpc->info.broadcast.bc,
						 PKG_STATUS, pkg_type,
						 pkgid, key, val);

	return PKGMGR_R_OK;
}

API pkgmgr_info *pkgmgr_client_check_pkginfo_from_file(const char *pkg_path)
{
	int ret = PKGMGR_R_OK;
	char *pkg_backend = NULL;
	pkg_plugin_set *plugin_set = NULL;
	package_manager_pkg_detail_info_t *pkg_detail_info = NULL;

	retvm_if(pkg_path == NULL, NULL, "pkg_path is NULL");

	pkg_detail_info = calloc(1, sizeof(package_manager_pkg_detail_info_t));
	retvm_if(pkg_detail_info == NULL, NULL, "pkg_detail_info calloc failed for path[%s]", pkg_path);

	pkg_backend = _get_backend_from_zip(pkg_path);
	tryvm_if(pkg_backend == NULL, ret = PKGMGR_R_ERROR, "type is NULL for path[%s]", pkg_path);

	plugin_set = _package_manager_load_library(pkg_backend);
	tryvm_if(plugin_set == NULL, ret = PKGMGR_R_ERROR, "load_library failed for path[%s]", pkg_path);

	ret = plugin_set->get_pkg_detail_info_from_package(pkg_path, pkg_detail_info);
	tryvm_if(ret != 0, ret = PKGMGR_R_ERROR, "get_pkg_detail_info_from_package failed for path[%s]", pkg_path);

	ret = PKGMGR_R_OK;

catch:
	if (pkg_backend)
		free(pkg_backend);

	if (ret < 0) {
		free(pkg_detail_info);
		return NULL;
	} else {
		return (pkgmgr_info *) pkg_detail_info;
	}
}

API int pkgmgr_client_free_pkginfo(pkgmgr_info * pkg_info)
{
	if (pkg_info == NULL)
		return PKGMGR_R_EINVAL;

	package_manager_pkg_detail_info_t *info = (package_manager_pkg_detail_info_t *)pkg_info;

	if (info->icon_buf)
		free(info->icon_buf);

	if(info->pkg_optional_info)
		free(info->pkg_optional_info);

	free(info);
	info = NULL;

	return PKGMGR_R_OK;
}

API int pkgmgr_client_request_service(pkgmgr_request_service_type service_type, int service_mode,
				  pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
			      const char *custom_info, pkgmgr_handler event_cb, void *data)
{
	int ret =0;

	/* Check for NULL value of service type */
	retvm_if(service_type > PM_REQUEST_MAX, PKGMGR_R_EINVAL, "service type is not defined\n");
	retvm_if(service_type < 0, PKGMGR_R_EINVAL, "service type is error\n");

	switch (service_type) {
	case PM_REQUEST_CSC:
		tryvm_if(custom_info == NULL, ret = PKGMGR_R_EINVAL, "custom_info is NULL\n");
		tryvm_if(strlen(custom_info) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "optional_file over PKG_STRING_LEN_MAX");
		tryvm_if(data == NULL, ret = PKGMGR_R_EINVAL, "data is NULL\n");

		ret = __csc_process(custom_info, (char *)data);
		if (ret < 0)
			_LOGE("__csc_process fail \n");
		else
			ret = PKGMGR_R_OK;

		break;

	case PM_REQUEST_MOVE:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");
		tryvm_if((service_mode < PM_MOVE_TO_INTERNAL) || (service_mode > PM_MOVE_TO_SDCARD), ret = PKGMGR_R_EINVAL, "service_mode[%d] is wrong\n", service_mode);

		ret = __move_pkg_process(pc, pkgid, (pkgmgr_move_type)service_mode, event_cb, data);
		break;

	case PM_REQUEST_GET_SIZE:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");
		tryvm_if((service_mode < PM_GET_TOTAL_SIZE) || (service_mode >= PM_GET_MAX), ret = PKGMGR_R_EINVAL, "service_mode[%d] is wrong\n", service_mode);

		ret = __get_size_process(pc, pkgid, (pkgmgr_getsize_type)service_mode, event_cb, data);
		break;

	case PM_REQUEST_KILL_APP:
	case PM_REQUEST_CHECK_APP:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");

		ret = __check_app_process(service_type, pc, pkgid, data);
		if (ret < 0)
			_LOGE("__check_app_process fail \n");
		else
			ret = PKGMGR_R_OK;

		break;

	default:
		_LOGE("Wrong Request\n");
		ret = -1;
		break;
	}

catch:

	return ret;
}

API int pkgmgr_client_request_size_info(void) // get all package size (data, total)
{
	int ret = 0;
	pkgmgr_client *pc = NULL;

	pc = pkgmgr_client_new(PC_REQUEST);
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "request pc is null\n");

	_LOGD("called");
	ret = __request_size_info(pc);
	if (ret < 0) {
		_LOGE("__request_size_info fail \n");
	}

	pkgmgr_client_free(pc);
	return ret;
}

API int pkgmgr_client_clear_cache_dir(const char *pkgid)
{
	_LOGD("clear cache dir[%s] start", pkgid);

	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "package id is null\n");

	int ret = 0;
	pkgmgr_client_t *pc = NULL;
	char *pkg_type = NULL;
	char *cookie = NULL;
	int is_type_malloced = 0;

	pkgmgrinfo_pkginfo_h handle = NULL;

	pc = pkgmgr_client_new(PC_REQUEST);
	retvm_if(pc == NULL, PKGMGR_R_ESYSTEM, "request pc is null\n");

	if (strcmp(pkgid, PKG_CLEAR_ALL_CACHE) != 0)
	{
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
		tryvm_if(ret < 0, ret = PKGMGR_R_ENOPKG, "pkgmgr_pkginfo_get_pkginfo failed");

		ret = pkgmgrinfo_pkginfo_get_type(handle, &pkg_type);
		tryvm_if(ret < 0, ret = PKGMGR_R_ESYSTEM, "pkgmgr_pkginfo_get_type failed");
	}
	else
	{
		int len = strlen("rpm") + 1;
		pkg_type = (char *)calloc(len, sizeof(char));
		tryvm_if(pkg_type == NULL, ret = PKGMGR_R_ESYSTEM, "memory alloc failed");
		strncpy(pkg_type, "rpm", len);
		is_type_malloced = 1;
	}

	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ESYSTEM, "__get_cookie_from_security_server is NULL");

	ret = comm_client_request(pc->info.request.cc, NULL, COMM_REQ_CLEAR_CACHE_DIR, pkg_type, pkgid, NULL, cookie, 0);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "COMM_REQ_CLEAR_CACHE_DIR failed, ret=%d\n", ret);

	ret = PKGMGR_R_OK;
catch:
	if (cookie)
		g_free(cookie);

	if (pc)
		pkgmgr_client_free(pc);

	if(is_type_malloced)
		free(pkg_type);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	_LOGE("clear cache dir finish, ret=[%d]", ret);

	return ret;
}

API int pkgmgr_client_clear_all_cache_dir(void)
{
	int ret = 0;
	ret = pkgmgr_client_clear_cache_dir(PKG_CLEAR_ALL_CACHE);
	return ret;
}

char* __get_getsize_type_string(pkgmgr_getsize_type get_type)
{
	char *str = "NULL";

	if (get_type == PM_GET_TOTAL_SIZE) {
		str = "PM_GET_TOTAL_SIZE";
	} else if (get_type == PM_GET_DATA_SIZE) {
		str = "PM_GET_DATA_SIZE";
	} else if (get_type == PM_GET_ALL_PKGS) {
		str = "PM_GET_ALL_PKGS";
	} else if (get_type == PM_GET_SIZE_INFO) {
		str = "PM_GET_SIZE_INFO";
	} else if (get_type == PM_GET_TOTAL_AND_DATA) {
		str = "PM_GET_TOTAL_AND_DATA";
	} else if (get_type == PM_GET_SIZE_FILE) {
		str = "PM_GET_SIZE_FILE";
	} else if (get_type == PM_GET_PKG_SIZE_INFO) {
		str = "PM_GET_PKG_SIZE_INFO";
	} else if (get_type == PM_GET_TOTAL_PKG_SIZE_INFO) {
		str = "PM_GET_TOTAL_PKG_SIZE_INFO";
	} else if (get_type == PM_GET_MAX) {
		str = "PM_GET_MAX";
	}

	return str;
}

API int pkgmgr_client_get_size(pkgmgr_client *pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data)
{
	char *req_key = NULL;
	int req_id = 0;
	int ret = 0;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "The specified pc is NULL.");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");
	retvm_if(event_cb == NULL, PKGMGR_R_EINVAL, "event_cb is NULL\n");
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL\n");

	ret = __change_op_cb_for_getsize(mpc);
	retvm_if(ret < 0 , PKGMGR_R_EINVAL, "__change_op_cb_for_getsize is fail");

	req_key = __get_req_key(pkgid);
	retvm_if(req_key == NULL, PKGMGR_R_ENOMEM, "req_key is NULL");

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	_LOGD("package=[%s], get_type=[%s][%d]", pkgid, __get_getsize_type_string(get_type), (int)get_type);
	ret = __get_package_size_info(mpc, req_key, pkgid, get_type);

	return ret;
}

API int pkgmgr_client_get_package_size_info(pkgmgr_client *pc, const char *pkgid, pkgmgr_pkg_size_info_receive_cb event_cb, void *user_data)
{
	char *req_key = NULL;
	int req_id = 0;
	int ret = 0;
	int type = PM_GET_PKG_SIZE_INFO;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "The specified pc is NULL.");
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "The package id is NULL.");

	// total package size info
	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0) {
		type = PM_GET_TOTAL_PKG_SIZE_INFO;
	} else {
		pkgmgrinfo_pkginfo_h handle = NULL;
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		retvm_if(ret != PMINFO_R_OK, ret = PKGMGR_R_ENOPKG, "pkgmgr_pkginfo_get_pkginfo failed");
	}

	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	ret = __change_op_cb_for_getsize(mpc);
	retvm_if(ret < 0 , PKGMGR_R_ESYSTEM, "__change_op_cb_for_getsize is fail");

	req_key = __get_req_key(pkgid);
	retvm_if(req_key == NULL, PKGMGR_R_ENOMEM, "req_key is NULL");

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, __get_pkg_size_info_cb, event_cb, user_data);

	_LOGD("package=[%s], get_type=[%s][%d]", pkgid, __get_getsize_type_string(type), (int)type);
	ret = __get_package_size_info(mpc, req_key, pkgid, type);

	return ret;
}

API int pkgmgr_client_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb event_cb, void *user_data)
{	// total package size info
	return pkgmgr_client_get_package_size_info(pc, PKG_SIZE_INFO_TOTAL, (pkgmgr_pkg_size_info_receive_cb)event_cb, user_data);
}

#define __START_OF_OLD_API
API pkgmgr_info *pkgmgr_info_new(const char *pkg_type, const char *pkgid)
{
	const char *pkgtype;
	pkg_plugin_set *plugin_set = NULL;
	package_manager_pkg_detail_info_t *pkg_detail_info = NULL;

	/* 1. check argument */
	if (pkgid == NULL)
		return NULL;

	if (pkg_type == NULL) {
		pkgtype = _get_pkg_type_from_desktop_file(pkgid);
		if (pkgtype == NULL)
			return NULL;
	} else
		pkgtype = pkg_type;

	if (strlen(pkgid) >= PKG_STRING_LEN_MAX)
		return NULL;

	pkg_detail_info = calloc(1, sizeof(package_manager_pkg_detail_info_t));
	if (pkg_detail_info == NULL) {
		_LOGE("*** Failed to alloc package_handler_info.\n");
		return NULL;
	}

	plugin_set = _package_manager_load_library(pkgtype);
	if (plugin_set == NULL) {
		_LOGE("*** Failed to load library");
		free(pkg_detail_info);
		return NULL;
	}

	if (plugin_set->pkg_is_installed) {
		if (plugin_set->pkg_is_installed(pkgid) != 0) {
			_LOGE("*** Failed to call pkg_is_installed()");
			free(pkg_detail_info);
			return NULL;
		}

		if (plugin_set->get_pkg_detail_info) {
			if (plugin_set->get_pkg_detail_info(pkgid,
							    pkg_detail_info) != 0) {
				_LOGE("*** Failed to call get_pkg_detail_info()");
				free(pkg_detail_info);
				return NULL;
			}
		}
	}

	return (pkgmgr_info *) pkg_detail_info;
}

API char * pkgmgr_info_get_string(pkgmgr_info * pkg_info, const char *key)
{
	package_manager_pkg_detail_info_t *pkg_detail_info;

	if (pkg_info == NULL)
		return NULL;
	if (key == NULL)
		return NULL;

	pkg_detail_info = (package_manager_pkg_detail_info_t *) pkg_info;

	return _get_info_string(key, pkg_detail_info);
}

API int pkgmgr_info_free(pkgmgr_info * pkg_info)
{
	if (pkg_info == NULL)
		return PKGMGR_R_EINVAL;

	free(pkg_info);
	pkg_info = NULL;

	return 0;
}

#define __END_OF_OLD_API

API int pkgmgr_pkginfo_get_pkginfo(const char *pkgid, pkgmgr_pkginfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, handle);
	return ret;
}

API int pkgmgr_pkginfo_get_label(pkgmgr_pkginfo_h handle, char **label)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_label(handle, label);
	return ret;
}

API int pkgmgr_pkginfo_destroy_pkginfo(pkgmgr_pkginfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	return ret;
}

API int pkgmgr_appinfo_get_list(pkgmgr_pkginfo_h handle, pkgmgr_app_component component,
							pkgmgr_info_app_list_cb app_func, void *user_data)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_list(handle, component, app_func, user_data);
	return ret;
}

API int pkgmgr_appinfo_get_appinfo(const char *appid, pkgmgr_appinfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_appinfo(appid, handle);
	return ret;
}

API int pkgmgr_appinfo_get_appid(pkgmgr_appinfo_h  handle, char **appid)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_appid(handle, appid);
	return ret;
}

API int pkgmgr_appinfo_get_pkgname(pkgmgr_appinfo_h  handle, char **pkg_name)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_get_pkgname(handle, pkg_name);
	return ret;
}

API int pkgmgr_appinfo_destroy_appinfo(pkgmgr_appinfo_h  handle)
{
	int ret = 0;
	ret = pkgmgrinfo_appinfo_destroy_appinfo(handle);
	return ret;
}

API int pkgmgr_pkginfo_create_certinfo(pkgmgr_certinfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_create_certinfo(handle);
	return ret;
}

API int pkgmgr_pkginfo_load_certinfo(const char *pkgid, pkgmgr_certinfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, handle);
	return ret;
}

API int pkgmgr_pkginfo_get_cert_value(pkgmgr_certinfo_h handle, pkgmgr_cert_type cert_type, const char **cert_value)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_get_cert_value(handle, cert_type, cert_value);
	return ret;
}

API int pkgmgr_pkginfo_destroy_certinfo(pkgmgr_certinfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_pkginfo_destroy_certinfo(handle);
	return ret;
}

