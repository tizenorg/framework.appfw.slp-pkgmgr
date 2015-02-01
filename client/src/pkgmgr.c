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
#include "junk-manager.h"
#include "pkgmgr_parser.h"

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR"
#endif				/* LOG_TAG */

#define BINSH_NAME	"/bin/sh"
#define BINSH_SIZE	7
#define MAX_STMT_SIZE	512
#define MAX_FILENAME_SIZE	256

#define PKG_INFO_DB_LABEL "pkgmgr::db"
#define PKG_PARSER_DB_FILE "/opt/dbspace/.pkgmgr_parser.db"
#define PKG_PARSER_DB_FILE_JOURNAL "/opt/dbspace/.pkgmgr_parser.db-journal"

#define FACTORY_RESET_BACKUP_FILE		"/usr/system/RestoreDir/opt.zip"
#define OPT_USR_APPS					"/opt/usr/apps"
#define SOFT_RESET_PATH					"/usr/etc/package-manager/soft-reset"
#define PKGMGR_FOTA_PATH			"/opt/usr/data/pkgmgr/fota/"
#define PKG_DISABLED_LIST_FILE 		PKGMGR_FOTA_PATH"pkg_disabled_list.txt"

#define TOKEN_PATH_STR						"path="
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
} pkgmgr_client_t;

typedef struct _iter_data {
	pkgmgr_iter_fn iter_fn;
	void *data;
} iter_data;

typedef struct {
	pkgmgr_client *pc;
	void *junk_tb;
	char *db_path;
} junkmgr_s;

typedef struct {
	void *db;
	void *db_stmt;
} junkmgr_result_s;

typedef struct
{
	int junk_req_type;  //0: API for getting root junk dir, 1: API for getting junk files, 2: API for clearing all junk files
	int junk_storage;   //0: internal, 1: external, 2: all
	char *junk_root;    //root junk dir name
} junkmgr_info_s;

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

	_LOGD("tmp->req_key %s, req_key %s", tmp->req_key, req_key);

	while (tmp) {
		if (strncmp(tmp->req_key, req_key, strlen(tmp->req_key)) == 0)
			return tmp;
		tmp = tmp->next;
	}
	return NULL;
}

static void __remove_op_cbinfo(pkgmgr_client_t *pc, req_cb_info *info)
{
	req_cb_info *tmp;

	if (pc == NULL || pc->info.request.rhead == NULL || info == NULL)
		return;

	tmp = pc->info.request.rhead;
	while (tmp) {
		if (tmp->next == info) {
			tmp->next = info->next;
			free(info);
			return;
		}
		tmp = tmp->next;
	}
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

static void __operation_callback(void *cb_data, const char *req_id,
				 const char *pkg_type, const char *pkgid,
				 const char *key, const char *val)
{
	pkgmgr_client_t *pc;
	req_cb_info *cb_info;

	SECURE_LOGD("__operation_callback() req_id[%s] pkg_type[%s] pkgid[%s]"
	      "key[%s] val[%s]\n", req_id, pkg_type, pkgid, key, val);

	pc = (pkgmgr_client_t *) cb_data;

	/* find callback info */
	cb_info = __find_op_cbinfo(pc, req_id);
	if (cb_info == NULL)
		return;

	_LOGD("__find_op_cbinfo");

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
		_LOGD("event_cb is called");
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
			      const char *key, const char *val)
{
	pkgmgr_client_t *pc;
	listen_cb_info *tmp;

	SECURE_LOGD("__status_callback() req_id[%s] pkg_type[%s] pkgid[%s]"
	      "key[%s] val[%s]\n", req_id, pkg_type, pkgid, key, val);

	pc = (pkgmgr_client_t *) cb_data;

	tmp = pc->info.listening.lhead;
	while (tmp) {
		if (tmp->event_cb(tmp->request_id, pkg_type, pkgid, key, val,
				  NULL, tmp->data) != 0)
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

static int __is_core_tpk_csc(char *description)
{
	int ret = 0;
	char *path_str = NULL;
	char *pkg_type = NULL;
	char csc_str[PKG_STRING_LEN_MAX] = {'\0'};
	snprintf(csc_str, PKG_STRING_LEN_MAX - 1, "%s:", description);

	_LOGD("csc_str [%s]\n", csc_str);

	path_str = __get_str(csc_str, TOKEN_PATH_STR);
	tryvm_if(path_str == NULL, ret = PKGMGR_R_ERROR, "path_str is NULL");

	_LOGD("path_str [%s]\n", path_str);

	pkg_type = _get_type_from_zip(path_str);
	if (pkg_type) {
		if (strstr(pkg_type, "rpm"))
			ret = 1;
		else
			ret  =-1;
		free(pkg_type);
	}

catch:

	if(path_str)
		free(path_str);

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
				usleep(10 * 1000);	/* 10ms sleep*/
				continue;
			}

			fgets(buf, PKG_STRING_LEN_MAX, fp);
			fclose(fp);

			_LOGD("info_file file is generated, result = %s. \n", buf);
			result = atoi(buf);
			break;
		}

		_LOGD("file is not generated yet.... wait\n");
		usleep(10 * 1000);	/* 10ms sleep*/

		if (check_cnt > 6000) {	/* 60s time over*/
			_LOGD("wait time over!!\n");
			break;
		}
	}

	ret = remove(info_file);
	if (ret < 0)
		_LOGD("file is can not remove[%s, %d]\n", info_file, ret);

	return result;
}

static int __disable_pkg()
{
	int ret = 0;
	FILE *fp = NULL;
	char *file_path = PKG_DISABLED_LIST_FILE;
	char pkgid[PKG_STRING_LEN_MAX] = {'\0',};

	fp = fopen(file_path, "r");
	if (fp == NULL) {
		_LOGE("fopen is failed.\n");
		return -1;
	}

	while (fscanf(fp, "%s", pkgid) != EOF) {
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
				const char *coreinstaller_argv[] = { "/usr/bin/rpm-backend", "-k", "csc-core", "-s", des, NULL };
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
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

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

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	if(req_key)
		free(req_key);

	return ret;
}

static int __move_pkg_process(pkgmgr_client * pc, const char *pkgid, pkgmgr_move_type move_type, pkgmgr_handler event_cb, void *data)
{
	char *req_key = NULL;
//	int req_id = 0;
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
	_LOGE("move pkg[%s] start", pkgid);

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_pkginfo failed");

	pkgmgrinfo_pkginfo_get_install_location(handle, &location);
	tryvm_if(location == PMINFO_INSTALL_LOCATION_INTERNAL_ONLY, ret = PKGMGR_R_ERROR, "package[%s] is internal-only, can not be moved", pkgid);

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_type failed");

	installer_path = _get_backend_path_with_type(pkgtype);
	req_key = __get_req_key(pkgid);
//	req_id = _get_request_id();

	/* generate argv */
	snprintf(buf, 128, "%d", move_type);
	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
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
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

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

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	_LOGE("move pkg[%s] finish[%d]", pkgid, ret);
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
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_pkginfo failed");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "pkgmgr_pkginfo_get_type failed");

	/* 2. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 3. request activate */
	if (service_type == PM_REQUEST_KILL_APP)
		ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_KILL_APP, pkgtype, pkgid, NULL, NULL, 1);
	else if (service_type == PM_REQUEST_CHECK_APP)
		ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_CHECK_APP, pkgtype, pkgid, NULL, NULL, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "comm_client_request[type %d] failed, ret=%d\n", service_type, ret);

	pid  = __check_sync_process((char*)pkgid);
	* (int *) data = pid;

catch:
	if(req_key)
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

	snprintf(buf, 128, "%d", get_type);
	argv[argcnt++] = strdup(pkgid);
	argv[argcnt++] = strdup(buf);
	argv[argcnt++] = strdup(buf);

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

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
	if (ret < 0) {
		_LOGE("COMM_REQ_GET_SIZE failed, ret=%d\n", ret);
	}

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	return ret;
}

static int __change_op_cb_for_getjunkinfo(pkgmgr_client *pc)
{
	int ret = -1;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* free dbus connection */
	ret = comm_client_free(mpc->info.request.cc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "comm_client_free() failed - %d", ret);

	/* Manage pc for seperated event */
	mpc->ctype = PC_REQUEST;
	mpc->status_type = PKGMGR_CLIENT_STATUS_GET_JUNK_INFO;


	mpc->info.request.cc = comm_client_new();
	retvm_if(mpc->info.request.cc == NULL, PKGMGR_R_ERROR, "client creation failed");

	ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_GET_JUNK_INFO, mpc->info.request.cc, __operation_callback, pc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "set_status_callback() failed - %d", ret);

	return PKGMGR_R_OK;
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

static junkmgr_result_h
__junkmgr_create_junk_root_handle(const char *dbpath)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *db_stmt = NULL;
	char stmt[MAX_STMT_SIZE] = "SELECT root_name, category, root_file_type, storage_type, junk_total_size, root_path FROM junk_root";
	junkmgr_result_s *handle = NULL;
	int ret = 0;

	ret = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK)
	{
		LOGE("sqlite open error, ret: %d (%s)", ret, sqlite3_errmsg(db));
		goto error;
	}

	ret = sqlite3_prepare_v2(db, stmt, strlen(stmt), &db_stmt, NULL);
	if (ret != SQLITE_OK)
	{
		LOGE("sqlite prepare error, ret: %d (%s)", ret, sqlite3_errmsg(db));
		goto error;
	}

	handle = (junkmgr_result_s *)malloc(sizeof(junkmgr_result_s));
	handle->db = db;
	handle->db_stmt = db_stmt;

	return handle;

error:
	if (db_stmt)
	{
		ret = sqlite3_finalize(db_stmt);
		if (ret != SQLITE_OK)
		{
		    LOGE("sqlite finalize error, ret: %d (%s)", ret, sqlite3_errmsg(db));
		}
	}

	if (db)
	{
		ret = sqlite3_close(db);
		if (ret != SQLITE_OK)
		{
		    LOGE("sqlite close error, ret: %d (%s)", ret, sqlite3_errmsg(db));
		}
	}

	return NULL;
}

static junkmgr_result_h
__junkmgr_create_junk_file_handle(const char *dbpath, int storage, const char *junk_root)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *db_stmt = NULL;
	char stmt[MAX_STMT_SIZE] = "SELECT junk_file.file_name, junk_root.category, junk_file.file_type, junk_root.storage_type, junk_file.junk_file_size, junk_file.file_path FROM junk_root INNER JOIN junk_file ON junk_root.root_name = junk_file.root_name WHERE junk_root.storage_type = \0";
	junkmgr_result_s *handle = NULL;
	int ret = 0;

	if (storage == 0) // internal
	{
		strcat(stmt, "0 AND junk_root.root_name = '");
	}
	else if (storage == 1) // external
	{
		strcat(stmt, "1 AND junk_root.root_name = '");
	}

	strncat(stmt, junk_root, MAX_STMT_SIZE - strlen(stmt) - 2);
	strcat(stmt, "'");
	_LOGS("stmt: %s", stmt);

	ret = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK)
	{
		LOGE("sqlite open error, ret: %d (%s)", ret, sqlite3_errmsg(db));
		goto error;
	}

	ret = sqlite3_prepare_v2(db, stmt, strlen(stmt), &db_stmt, NULL);
	if (ret != SQLITE_OK)
	{
		LOGE("sqlite prepare error, ret: %d (%s)", ret, sqlite3_errmsg(db));
		goto error;
	}

	handle = (junkmgr_result_s *)malloc(sizeof(junkmgr_result_s));
	handle->db = db;
	handle->db_stmt = db_stmt;

	return handle;

error:
	if (db_stmt)
	{
		ret = sqlite3_finalize(db_stmt);
		if (ret != SQLITE_OK)
		{
		    LOGE("sqlite finalize error, ret: %d (%s)", ret, sqlite3_errmsg(db));
		}
	}

	if (db)
	{
		ret = sqlite3_close(db);
		if (ret != SQLITE_OK)
		{
		    LOGE("sqlite close error, ret: %d (%s)", ret, sqlite3_errmsg(db));
		}
	}

	return NULL;
}

static int
__junkmgr_destroy_junk_handle(junkmgr_result_h hnd)
{
	int ret = -1;

    junkmgr_result_s *handle = (junkmgr_result_s *)hnd;

	if (!handle || !handle->db || !handle->db_stmt)
	{
		return -1;
	}

	ret = sqlite3_finalize((sqlite3_stmt *)(handle->db_stmt));
	if (ret != SQLITE_OK)
	{
		printf("error %d", __LINE__);
		return -1;
	}

	ret = sqlite3_close((sqlite3 *)(handle->db));
	if (ret != SQLITE_OK)
	{
		printf("error %d", __LINE__);
		return -1;
	}
	return 0;
}

static int __get_junk_info_cb(int req_id, const char *req_type,
		const char *pkgid, const char *key,
		const char *value, const void *pc, void *user_data)
{
	int ret = 0;
	const char *caller = pkgid;
	const char *dbpath = value;
	junkmgr_result_s *handle = NULL;
    char tb_key[16] = { 0, };

	_LOGS("req_id: %d, caller: %s, dbpath: %s", req_id, caller, dbpath);

	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

    junkmgr_s *junkmgr = (junkmgr_s *)(mpc->extension);
    if (junkmgr && junkmgr->junk_tb)
    {
        snprintf(tb_key, 16, "%d", req_id);
        junkmgr_info_s *junk_info = (junkmgr_info_s *)g_hash_table_lookup(junkmgr->junk_tb, tb_key);
        if (junk_info)
        {
			if (junkmgr->db_path == NULL)
			{
				junkmgr->db_path = strdup(dbpath);
			}

            if (junk_info->junk_req_type == 0)
            {
				junkmgr_result_receive_cb callback = (junkmgr_result_receive_cb)(mpc->new_event_cb);
                handle = __junkmgr_create_junk_root_handle(dbpath);

				callback(req_id, handle, user_data);
            }
            else if (junk_info->junk_req_type == 1)
            {
				junkmgr_result_receive_cb callback = (junkmgr_result_receive_cb)(mpc->new_event_cb);
                handle = __junkmgr_create_junk_file_handle(dbpath, junk_info->junk_storage, junk_info->junk_root);

				callback(req_id, handle, user_data);
            }
            else if (junk_info->junk_req_type == 2)
            {
				junkmgr_clear_completed_cb callback = (junkmgr_clear_completed_cb)(mpc->new_event_cb);
				callback(req_id, user_data);
            }

			if (junk_info->junk_root)
	            free(junk_info->junk_root);
            g_hash_table_remove(junkmgr->junk_tb, tb_key);

            if (handle)
            {
                __junkmgr_destroy_junk_handle(handle);
            }
        }
        else
        {
            LOGD("junk_info null");
        }
    }
    else
    {
        LOGD("junkmgr null");
    }

	return ret;
}

static int __get_pkg_size_info_cb(int req_id, const char *req_type,
		const char *pkgid, const char *key,
		const char *value, const void *pc, void *user_data)
{
	int ret = 0;
	_LOGS("reqid: %d, req type: %s, pkgid: %s, unused key: %s, size info: %s",
			req_id, req_type, pkgid, key, value);

	pkg_size_info_t *size_info = (pkg_size_info_t *)malloc(sizeof(pkg_size_info_t));
	retvm_if(size_info == NULL, -1, "The memory is insufficient.");

	char *save_ptr = NULL;
	char *token = strtok_r((char*)value, ":", &save_ptr);
	size_info->data_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	size_info->cache_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	size_info->app_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	size_info->ext_data_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	size_info->ext_cache_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
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

static int __get_junk_info(junkmgr_s *junkmgr, const char *junk_path, junkmgr_info_s *junk_info, void *event_cb, void *user_data, int *reqid)
{
	int ret = 0;
	int req_id = 0;
	char *req_key = NULL;
	char *pkg_type = "junk";
	char junk_req_type[4] = { 0, };
	char junk_storage[4] = { 0, };
	char *argv[PKG_ARGC_MAX] = {0,};
	char *args = NULL;
	int argcnt = 0;
	int len = 0;
	char *temp = NULL;
	int i = 0;
	char *cookie = NULL;
	char pid_str[8] = {0,};
	int res = 0;

	/* Check for NULL value of pc */
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)(junkmgr->pc);
	retvm_if(mpc == NULL, JUNKMGR_E_INVALID, "package manager client handle is NULL");

	/* check the mpc type */
	retvm_if(mpc->ctype != PC_REQUEST, JUNKMGR_E_SYSTEM, "mpc->ctype is not PC_REQUEST");

	/* generate req_key by pid */
	snprintf(pid_str, sizeof(pid_str), "%d", getpid());
	req_key = __get_req_key(pid_str);

	/* add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();

	ret = __change_op_cb_for_getjunkinfo(mpc);
	if (ret < 0)
	{
		LOGE("__change_op_cb_for_getjunkinfo is fail");
		free(req_key);
		return JUNKMGR_E_SYSTEM;
	}

	__add_op_cbinfo(mpc, req_id, req_key, __get_junk_info_cb, event_cb, user_data);

	/* generate argv */

	/* exec path */
	argv[argcnt++] = strdup("pkg_getjunkinfo");
	/* argv[1] pid */
	argv[argcnt++] = strdup("-p");
	argv[argcnt++] = strdup(pid_str);
	/* pid+timestamp */
	argv[argcnt++] = strdup("-k");
	argv[argcnt++] = strdup(req_key);
	/* request type */
	switch (junk_info->junk_req_type) {
		case 0:
			strncpy(junk_req_type, "0", 1);
			break;
		case 1:
			strncpy(junk_req_type, "1", 1);
			break;
		case 2:
			strncpy(junk_req_type, "2", 1);
			break;
		default:
			LOGE("Junk request type is invalid.");
			break;
	}
	argv[argcnt++] = strdup("-t");
	argv[argcnt++] = strdup(junk_req_type);
	/* request storage */
	switch (junk_info->junk_storage) {
		case 0:
			strncpy(junk_storage, "INT", 3);
			break;
		case 1:
			strncpy(junk_storage, "EXT", 3);
			break;
		case 2:
			strncpy(junk_storage, "ALL", 3);
			break;
		default:
			LOGE("Storage type is invalid.");
			break;
	}
	argv[argcnt++] = strdup("-w");
	argv[argcnt++] = strdup(junk_storage);
	/* junk path */
	argv[argcnt++] = strdup("-j");
	if (junk_path) {
		argv[argcnt++] = strdup(junk_path);
	}
	else {
		argv[argcnt++] = strdup("ALL");
	}

	/*** add quote in all string for special charactor like '\n'***   FIX */
	for (i = 0; i < argcnt; i++) {
		temp = g_shell_quote(argv[i]);
		len += (strlen(temp) + 1);
		g_free(temp);
	}

	args = (char *)calloc(len, sizeof(char));
	tryvm_if(args == NULL, ret = JUNKMGR_E_NOMEM, "calloc failed");

	strncpy(args, argv[0], len - 1);

	for (i = 1; i < argcnt; i++) {
		strncat(args, " ", strlen(" "));
		temp = g_shell_quote(argv[i]);
		strncat(args, temp, strlen(temp));
		g_free(temp);
	}
	_LOGD("[args] %s [len] %d\n", args, len);

	char *tb_key = (char *)malloc(16);
	snprintf(tb_key, 16, "%d", req_id);
	g_hash_table_insert(junkmgr->junk_tb, tb_key, junk_info);
	mpc->extension = junkmgr;

	/* get cookie from security-server */
	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = JUNKMGR_E_SYSTEM, "__get_cookie_from_security_server is NULL");
	/******************* end of quote ************************/

	/* 6. request install */
	res = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_GET_JUNK_INFO, pkg_type, pid_str, args, cookie, 1);
	trym_if(res < 0, "COMM_REQ_GET_JUNK_INFO failed, ret=%d", res);
	if (res < 0) {
		switch (res) {
			case PKGMGR_R_ENOMEM:
				LOGE("out of memory");
				ret = JUNKMGR_E_NOMEM;
				break;
			case PKGMGR_R_EPRIV:
				LOGE("privilege denied");
				ret = JUNKMGR_E_PRIV;
				break;
			default:
				LOGE("system error");
				ret = JUNKMGR_E_SYSTEM;
				break;
		}
	}

	*reqid = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		free(cookie);

	return ret;
}

static int __remove_junk_file(const char *dbpath, const char *junk_path)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *db_stmt = NULL;
	long long junk_file_size = 0;
	long long junk_total_size = 0;
	int res = 0;
	int ret = JUNKMGR_E_SUCCESS;
	char *query = NULL;
	char *root_name = NULL;
	char *error_message = NULL;

	res = sqlite3_open(dbpath, &db);
	if (SQLITE_OK != res)
	{
		LOGE("sqlite open error, res: %d (%s)", res, sqlite3_errmsg(db));
		goto error;
	}

	query = sqlite3_mprintf("SELECT junk_file.root_name, junk_file.junk_file_size, junk_root.junk_total_size, junk_file.file_path FROM junk_root INNER JOIN junk_file ON junk_root.root_name = junk_file.root_name WHERE junk_file.file_path='%q'", junk_path);
	if (query == NULL)
	{
		LOGE("unable to allocate enough memory to hold the resulting string");
		ret = JUNKMGR_E_NOMEM;
		goto error;
	}

	res = sqlite3_prepare_v2(db, query, strlen(query), &db_stmt, NULL);
	if (SQLITE_OK != res)
	{
		LOGE("sqlite prepare error, res: %d (%s)", res, sqlite3_errmsg(db));
		goto error;
	}

	res = sqlite3_step(db_stmt);
	if (SQLITE_ROW != res)
	{
		LOGE("sqlite step error, res: %d (%s)", res, sqlite3_errmsg(db));
		goto error;
	}

	root_name = (char*)sqlite3_column_text(db_stmt, 0);
	junk_file_size = sqlite3_column_int64(db_stmt, 1);
	junk_total_size = sqlite3_column_int64(db_stmt, 2);

	sqlite3_free(query);
	query = sqlite3_mprintf("DELETE FROM junk_file WHERE file_path='%q'", junk_path);
	if (query == NULL)
	{
		LOGE("unable to allocate enough memory to hold the resulting string");
		ret = JUNKMGR_E_NOMEM;
		goto error;
	}

	res = sqlite3_exec(db, query, NULL, NULL, &error_message);
	if (SQLITE_OK != res)
	{
		LOGE("Don't execute query = %s error massage = %s", query, error_message);
		goto error;
	}

	junk_total_size -= junk_file_size;
	sqlite3_free(query);
	query = sqlite3_mprintf("UPDATE junk_root SET junk_total_size = %lld where root_name='%q'", junk_total_size, root_name);
	if (query == NULL)
	{
		LOGE("unable to allocate enough memory to hold the resulting string");
		ret = JUNKMGR_E_NOMEM;
		goto error;
	}

	res = sqlite3_exec(db, query, NULL, NULL, &error_message);
	if (SQLITE_OK != res)
	{
		LOGE("Don't execute query = %s error massage = %s", query, error_message);
		goto error;
	}

	ret = remove(junk_path);
	if (ret < 0)
	{
		LOGE("remove() failed. path: %s, errno %d (%s)", junk_path, errno, strerror(errno));
		switch (errno)
		{
			case EACCES:
				ret = JUNKMGR_E_ACCESS;
				break;
			case EIO:
				ret = JUNKMGR_E_IO;
				break;
			case ENOMEM:
				ret = JUNKMGR_E_NOMEM;
				break;
			default:
				ret = JUNKMGR_E_SYSTEM;
				break;
		}
	}

error:
	if (SQLITE_OK != res)
	{
		switch (res)
		{
			case SQLITE_DONE:
				ret = JUNKMGR_E_NOT_FOUND;
				break;
			case SQLITE_BUSY:
				ret = JUNKMGR_E_OBJECT_LOCKED;
				break;
			case SQLITE_CANTOPEN:
				ret = JUNKMGR_E_PRIV;
				break;
			default:
				ret = JUNKMGR_E_SYSTEM;
				break;
		}
	}

	if (query)
	{
		sqlite3_free(query);
	}
	if (error_message)
	{
		sqlite3_free(error_message);
	}
	if (db_stmt)
	{
		sqlite3_finalize(db_stmt);
	}
	if (db)
	{
		sqlite3_close(db);
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
	tryvm_if(args == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

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

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	return ret;
}

static int __uninstall_pkg_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid = NULL;
	char *pkgtype = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	retvm_if(ret != PMINFO_R_OK, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_pkgid failed\n");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	retvm_if(ret != PMINFO_R_OK, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_type failed\n");

	if (strcmp(pkgtype, "tpk") == 0) {
		const char *ospinstaller_argv[] = { "/usr/bin/osp-installer", "-u", pkgid, NULL };
		ret = __xsystem(ospinstaller_argv);
	} else if (strcmp(pkgtype, "wgt")== 0) {
		const char *wrtinstaller_argv[] = { "/usr/bin/wrt-installer", "-un", pkgid, NULL };
		ret = __xsystem(wrtinstaller_argv);
	} else if (strcmp(pkgtype, "rpm")== 0) {
		const char *rpminstaller_argv[] = { "/usr/bin/rpm-backend", "-k", "uninstall", "-d", pkgid, NULL };
		ret = __xsystem(rpminstaller_argv);
	} else {
		ret = -1;
	}

	_LOGF("[pkgtype = %s,  pkgid = %s, ret = %d] uninstalled \n", pkgtype, pkgid, ret);

	return ret;
}

static void __uninstall_downloaded_packages(void)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_filter_h handle = NULL;

	_LOGF("============================================\n");
	_LOGF("start __uninstall_downloaded_packages\n");

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	retm_if(ret != PMINFO_R_OK, "pkginfo filter handle create failed\n");

	_LOGF("success create handle\n");

	ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD, 0);
	trym_if(ret != PMINFO_R_OK, "PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD add_bool failed");

	_LOGF("success set PRELOAD value\n");

	ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE, 1);
	trym_if(ret != PMINFO_R_OK, "PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE add_bool failed");

	_LOGF("success set REMOVABLE value, call foreach cb!\n");

	pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __uninstall_pkg_cb, NULL);

catch :
	pkgmgrinfo_pkginfo_filter_destroy(handle);

	_LOGF("finish __uninstall_downloaded_packages\n");
	_LOGF("============================================\n");
}

static void __recovery_pkgmgr_db(void)
{
	int ret = 0;

	_LOGF("============================================\n");
	_LOGF("start __recovery_pkgmgr_db\n");

	/*unzip pkgmgr db from factoryrest data*/
	const char *unzip_argv[] = { "/usr/bin/unzip", "-o", FACTORY_RESET_BACKUP_FILE, "opt/dbspace/.pkgmgr_parser.db", "-d", "/", NULL };
	ret = __xsystem(unzip_argv);
	retm_if(ret != PMINFO_R_OK, "unzip_argv failed\n");

	_LOGF("success unzip PKG_PARSER_DB_FILE \n");

	const char *unzipjn_argv[] = { "/usr/bin/unzip", "-o", FACTORY_RESET_BACKUP_FILE, "opt/dbspace/.pkgmgr_parser.db-journal", "-d", "/", NULL };
	ret = __xsystem(unzipjn_argv);
	retm_if(ret != PMINFO_R_OK, "unzipjn_argv failed\n");

	_LOGF("success unzip PKG_PARSER_DB_FILE_JOURNAL \n");

	const char *argv_parser[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_PARSER_DB_FILE, NULL };
	ret = __xsystem(argv_parser);
	retm_if(ret != PMINFO_R_OK, "chsmack PKG_PARSER_DB_FILE failed\n");

	_LOGF("success chsmack PKG_PARSER_DB_FILE \n");

	const char *argv_parserjn[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_PARSER_DB_FILE_JOURNAL, NULL };
	ret = __xsystem(argv_parserjn);
	retm_if(ret != PMINFO_R_OK, "chsmack PKG_PARSER_DB_FILE_JOURNAL failed\n");

	_LOGF("success chsmack PKG_PARSER_DB_FILE_JOURNAL \n");

	_LOGF("finish __recovery_pkgmgr_db\n");
	_LOGF("============================================\n");
}

static void __rm_and_unzip_pkg(char *pkgid)
{
	int ret = 0;
	char dirpath[PKG_STRING_LEN_MAX] = {'\0'};

	//root path
	snprintf(dirpath, PKG_STRING_LEN_MAX, "%s/%s", OPT_USR_APPS, pkgid);

	if (access(dirpath, F_OK)==0) {
		const char *deldata_argv[] = { "/bin/rm", "-rf", dirpath, NULL };
		__xsystem(deldata_argv);

		_LOGF("pkgpath = %s deleted \n", dirpath);

		//unzip data from factoryrest data
		memset(dirpath,'\0',PKG_STRING_LEN_MAX);
		snprintf(dirpath, PKG_STRING_LEN_MAX, "opt/usr/apps/%s\*", pkgid);
		const char *unzipdata_argv[] = { "/usr/bin/unzip", "-oX", FACTORY_RESET_BACKUP_FILE, dirpath, "-d", "/", NULL };
		__xsystem(unzipdata_argv);

		_LOGF("pkgpath = %s made \n", dirpath);

		const char *rpmsmack_argv[] = { "/usr/bin/rpm-backend", "-k", "soft-reset", "-s", pkgid, NULL };
		__xsystem(rpmsmack_argv);

		_LOGF("pkgid = %s smack \n", pkgid);
	} else {
		_LOGF("pkgid = %s dont have data directory \n", pkgid);
	}

}

static int __soft_reset_pkg_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid = NULL;
	char *pkgtype = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	retvm_if(ret != PMINFO_R_OK, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_pkgid failed\n");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	retvm_if(ret != PMINFO_R_OK, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_type failed\n");

	if (strstr(pkgtype, "wgt")) {
		_LOGF("[pkgid = %s] is wgt, it need skip\n", pkgid);
		return PMINFO_R_OK;
	}

	_LOGF("[pkgid = %s] found as soft reset pkg\n", pkgid);

	__rm_and_unzip_pkg(pkgid);

	return PMINFO_R_OK;
}

static void __soft_reset_pkg(void)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_filter_h handle = NULL;

	_LOGF("============================================\n");
	_LOGF("start NO 'support-reset' tag on xml \n");

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	retm_if(ret != PMINFO_R_OK, "pkginfo filter handle create failed\n");

	ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_USE_RESET, 1);
	trym_if(ret != PMINFO_R_OK, "PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD add_bool failed");

	pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __soft_reset_pkg_cb, NULL);

catch :
	pkgmgrinfo_pkginfo_filter_destroy(handle);

	_LOGF("finish soft reset pkg\n");
	_LOGF("============================================\n");

}

static int __none_reset_pkg_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid = NULL;
	char *pkgtype = NULL;
	char *root_path = NULL;
	char *support_reset = NULL;
	char script_path[PKG_STRING_LEN_MAX] = {'\0'};

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	retvm_if(ret != PMINFO_R_OK, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_pkgid failed\n");

	ret = pkgmgrinfo_pkginfo_get_root_path(handle, &root_path);
	retvm_if(ret != PMINFO_R_OK, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_root_path failed\n");

	ret = pkgmgrinfo_pkginfo_get_support_reset(handle, &support_reset);
	retvm_if(ret != PMINFO_R_OK, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_support_reset failed\n");

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	retvm_if(ret != PMINFO_R_OK, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_type failed\n");

	if (strstr(pkgtype, "wgt")) {
		_LOGF("[pkgid = %s] is wgt, it need skip\n", pkgid);
		return PMINFO_R_OK;
	}

	_LOGF("pkgid = %s, support_reset = %s \n", pkgid, support_reset);

	snprintf(script_path, PKG_STRING_LEN_MAX, "%s/%s", root_path, support_reset);

	if (access(script_path, F_OK)==0) {
		const char *scriptt_argv[] = {script_path, NULL };
		__xsystem(scriptt_argv);
		_LOGF("success [script = %s]\n", script_path);
	} else {
		if (strcasestr(support_reset, "true")) {
			__rm_and_unzip_pkg(pkgid);

			char *save_ptr = NULL;
			char *token = strtok_r((char*)support_reset, "|", &save_ptr);
			if (token != NULL) {
				memset(script_path,'\0',PKG_STRING_LEN_MAX);
				snprintf(script_path, PKG_STRING_LEN_MAX, "%s/%s", root_path, save_ptr);
				if (access(script_path, F_OK)==0) {
					const char *srt_argv[] = {script_path, NULL };
					__xsystem(srt_argv);
					_LOGF("success [script = %s]\n", script_path);
				}
			}
		} else {
			_LOGF("can not access [script file = %s]\n", script_path);
		}
	}

	return ret;
}

static void __none_reset_pkg(void)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_filter_h handle = NULL;

	_LOGF("============================================\n");
	_LOGF("start 'support-reset' tag on xml \n");

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	retm_if(ret != PMINFO_R_OK, "pkginfo filter handle create failed\n");

	ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_USE_RESET, 0);
	trym_if(ret != PMINFO_R_OK, "PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD add_bool failed");

	pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __none_reset_pkg_cb, NULL);

catch :
	pkgmgrinfo_pkginfo_filter_destroy(handle);

	_LOGF("finish 'support-reset' \n");
	_LOGF("============================================\n");

}

static void __run_reset_script(void)
{
	DIR *dir;
	struct dirent entry;
	struct dirent *result;
	int ret = 0;

	_LOGF("============================================\n");
	_LOGF("start __run_reset_script\n");

	dir = opendir(SOFT_RESET_PATH);
	if (!dir) {
		_LOGF("opendir(%s) failed\n", SOFT_RESET_PATH);
		return;
	}

	_LOGF("loading script files from %s\n", SOFT_RESET_PATH);

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {

		char script_path[PKG_STRING_LEN_MAX] = {'\0'};

		if (!strcmp(entry.d_name, ".") ||
			!strcmp(entry.d_name, "..")) {
			continue;
		}

		snprintf(script_path, PKG_STRING_LEN_MAX, "%s/%s", SOFT_RESET_PATH, entry.d_name);

		const char *script_argv[] = { script_path, NULL };
		ret = __xsystem(script_argv);

		_LOGF("reset script = [%s], ret = %d\n", entry.d_name, ret);
	}

	closedir(dir);

	_LOGF("finish __run_reset_script\n");
	_LOGF("============================================\n");
}

static void __pkgmgr_log_init()
{
	char *req_key = NULL;
	char log_path[PKG_STRING_LEN_MAX] = {'\0'};

	if (access(SOFT_RESET_TEST_FLAG, F_OK) != 0) {
		return;
	}

	req_key = __get_req_key("soft-reset");
	retm_if(req_key == NULL, "can not make log file\n");

	snprintf(log_path, PKG_STRING_LEN_MAX, "%s/%s", OPT_USR_MEDIA, req_key);

	logfile = fopen(log_path, "w");
	if (logfile == NULL) {
		_LOGF("fail  pkgmgr logging\n");
	} else {
		_LOGF("============================================\n");
		_LOGF("start pkgmgr logging [%s] \n", req_key);
	}
	free(req_key);
}

static void __pkgmgr_log_deinit()
{
	int fd = 0;
	if (logfile != NULL) {
		_LOGF("finish pkgmgr logging \n");
		_LOGF("============================================\n");

		fd = fileno(logfile);\
		fsync(fd);\
		fclose(logfile);\
	}
}

API pkgmgr_client *pkgmgr_client_new(client_type ctype)
{
	pkgmgr_client_t *pc = NULL;
	int ret = -1;

	retvm_if(ctype != PC_REQUEST && ctype != PC_LISTENING && ctype != PC_BROADCAST, NULL, "ctype is not client_type");

	/* Allocate memory for ADT:pkgmgr_client */
	pc = calloc(1, sizeof(pkgmgr_client_t));
	retvm_if(pc == NULL, NULL, "No memory");

	/* Manage pc */
	pc->ctype = ctype;
	pc->status_type = PKGMGR_CLIENT_STATUS_ALL;

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
	}

	return (pkgmgr_client *) pc;

catch:
	if (pc)
		free(pc);
	return NULL;
}

API junkmgr_h junkmgr_create_handle(void)
{

	junkmgr_s *junkmgr = (junkmgr_s *)malloc(sizeof(junkmgr_s));
	if (!junkmgr)
	{
		LOGE("malloc() failed. The memory is insufficient.");
		return NULL;
	}
	junkmgr->pc = NULL;
	junkmgr->junk_tb = NULL;
	junkmgr->db_path = NULL;

	pkgmgr_client *pc = pkgmgr_client_new(PC_REQUEST);
	if (!pc)
	{
		free(junkmgr);
		return NULL;
	}

	GHashTable *table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (!table)
	{
		free(junkmgr);
		pkgmgr_client_free(pc);
		return NULL;
	}

	junkmgr->pc = pc;
	junkmgr->junk_tb = table;

	return junkmgr;
}

API int junkmgr_destroy_handle(junkmgr_h mgr)
{
    if (!mgr)
	{
        LOGE("junkmgr handle is null.");
        return JUNKMGR_E_INVALID;
	}

    junkmgr_s *junkmgr = (junkmgr_s *)mgr;

    pkgmgr_client_free((pkgmgr_client *)(junkmgr->pc));
    g_hash_table_destroy(junkmgr->junk_tb);

	if (!junkmgr->db_path)
		free(junkmgr->db_path);

	free(junkmgr);

    return JUNKMGR_E_SUCCESS;
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
		retvm_if(strlen(descriptor_path) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "descriptor_path over PKG_STRING_LEN_MAX");
		retvm_if(access(descriptor_path, F_OK) != 0, PKGMGR_R_EINVAL, "descriptor_path access fail");
	}

	retvm_if(pkg_path == NULL, PKGMGR_R_EINVAL, "pkg_path is NULL");
	retvm_if(strlen(pkg_path) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "pkg_path over PKG_STRING_LEN_MAX");
	retvm_if(access(pkg_path, F_OK) != 0, PKGMGR_R_EINVAL, "pkg_path access fail");

	if (optional_file)
		retvm_if(strlen(optional_file) >= PKG_STRING_LEN_MAX, PKGMGR_R_EINVAL, "optional_file over PKG_STRING_LEN_MAX");

	/* 3. generate req_key */
	req_key = __get_req_key(pkg_path);

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
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALLER, pkg_type, pkg_path, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_INSTALLER failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		free(cookie);
	if (caller_pkgid)
		free(caller_pkgid);

	return ret;
}

API int pkgmgr_client_reinstall(pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
				  const char *optional_file, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data)
{
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

	installer_path = _get_backend_path_with_type(pkgtype);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path is null");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	/* 5. generate argv */

	/*  argv[0] installer path */
	argv[argcnt++] = installer_path;
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
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALLER, pkgtype, pkgid, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_INSTALLER failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if (args)
		free(args);
	if (cookie)
		free(cookie);
	if (handle)
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;
}

API int pkgmgr_client_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data)
{
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

	pkgmgrinfo_pkginfo_h handle;
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);

	/*check package id	*/
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_pkginfo fail");
	tryvm_if(handle == NULL, ret = PKGMGR_R_EINVAL, "Pkgid(%s) can not find in installed pkg DB! \n", pkgid);

	/*check type	*/
	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_type fail");
	tryvm_if(pkgtype == NULL, ret = PKGMGR_R_ERROR, "pkgtype is NULL");

	/*check removable*/
	pkgmgrinfo_pkginfo_is_removable(handle, &removable);
	tryvm_if(removable == false, ret = PKGMGR_R_ERROR, "Pkgid(%s) can not be removed, This is non-removalbe package...\n", pkgid);

	/*check pkgid length	*/
	tryvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "pkgid is too long");

	/* 2. get installer path using pkgtype */
	installer_path = _get_backend_path_with_type(pkgtype);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	caller_pkgid = __get_caller_pkgid();
	if (caller_pkgid != NULL)
		_LOGE("caller pkgid = %s\n", caller_pkgid);

	/* 5. generate argv */

	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
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

	/* 6. request install */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_TO_INSTALLER, pkgtype, pkgid, args, cookie, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_INSTALLER failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	PKGMGR_END();\
	return ret;
}

API int pkgmgr_client_move(pkgmgr_client *pc, const char *pkgid, pkgmgr_move_type move_type, pkgmgr_handler event_cb, void *data)
{
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
	_LOGE("move pkg[%s] start", pkgid);

	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check the pc type */
	retv_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL);

	/* 1. check argument */
	retv_if(pkgid == NULL, PKGMGR_R_EINVAL);

	pkgmgrinfo_pkginfo_h handle;
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);

	/*check package id	*/
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_pkginfo fail");
	tryvm_if(handle == NULL, ret = PKGMGR_R_EINVAL, "Pkgid(%s) can not find in installed pkg DB! \n", pkgid);

	pkgmgrinfo_pkginfo_get_install_location(handle, &location);
	tryvm_if(location == PMINFO_INSTALL_LOCATION_INTERNAL_ONLY, ret = PKGMGR_R_ERROR, "package[%s] is internal-only, can not be moved", pkgid);

	/*check type	*/
	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	tryvm_if(ret < 0, ret = PKGMGR_R_EINVAL, "pkgmgr_pkginfo_get_type fail");
	tryvm_if(pkgtype == NULL, ret = PKGMGR_R_ERROR, "pkgtype is NULL");

	/*check pkgid length	*/
	tryvm_if(strlen(pkgid) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "pkgid is too long");

	/*check move_type	*/
	tryvm_if((move_type < PM_MOVE_TO_INTERNAL) || (move_type > PM_MOVE_TO_SDCARD), ret = PKGMGR_R_EINVAL, "move_type is not supported");

	/* 2. get installer path using pkgtype */
	installer_path = _get_backend_path_with_type(pkgtype);
	tryvm_if(installer_path == NULL, ret = PKGMGR_R_EINVAL, "installer_path fail");

	/* 3. generate req_key */
	req_key = __get_req_key(pkgid);

	/* 4. add callback info - add callback info to pkgmgr_client */
	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	/* 5. generate argv */
	snprintf(buf, 128, "%d", move_type);
	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
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
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_MOVER failed, ret=%d", ret);

	ret = req_id;

catch:
	for (i = 0; i < argcnt; i++)
		free(argv[i]);

	if(args)
		free(args);
	if (cookie)
		free(cookie);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	PKGMGR_END();\

	_LOGE("move pkg[%s] finish[%d]", pkgid, ret);
	return ret;
}

API int pkgmgr_client_activate(pkgmgr_client * pc, const char *pkg_type, const char *pkgid)
{
	_LOGE("pkgmgr_client_activate[%s] start", pkgid);

	char *req_key = NULL;
	int ret = 0;
	pkgmgrinfo_pkginfo_h handle = NULL;

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
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_ACTIVATE_PKG, "pkg", pkgid, NULL, NULL, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_ACTIVATE_PKG failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	if (req_key)
		free(req_key);
	_LOGE("pkgmgr_client_activate[%s] finish[%d]", pkgid, ret);

	return ret;
}

API int pkgmgr_client_deactivate(pkgmgr_client *pc, const char *pkg_type, const char *pkgid)
{
	_LOGE("pkgmgr_client_deactivate[%s] start", pkgid);

	char *req_key = NULL;
	int ret = 0;
	pkgmgrinfo_pkginfo_h handle = NULL;

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
	tryvm_if(req_key == NULL, ret = PKGMGR_R_ERROR, "req_key is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_DEACTIVATE_PKG, "pkg", pkgid, NULL, NULL, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_DEACTIVATE_PKG failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	if (req_key)
		free(req_key);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	_LOGE("pkgmgr_client_deactivate[%s] finish[%d]", pkgid, ret);

	return ret;
}

API int pkgmgr_client_activate_app(pkgmgr_client * pc, const char *appid)
{
	_LOGE("pkgmgr_client_activate_app[%s] start", appid);

	char *req_key = NULL;
	int ret = 0;
	int fd = 0;
	FILE *fp = NULL;
	char activation_info_file[PKG_STRING_LEN_MAX] = { 0, };

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
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	snprintf(activation_info_file, PKG_STRING_LEN_MAX, "%s/%s", PKG_DATA_PATH, appid);
	fp = fopen(activation_info_file, "w");
	tryvm_if(fp == NULL, ret = PMINFO_R_ERROR, "rev_file[%s] is null\n", activation_info_file);

	fflush(fp);
	fd = fileno(fp);
	fsync(fd);
	fclose(fp);

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_ACTIVATE_APP, "pkg", appid, NULL, NULL, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_ACTIVATE_APP failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	if (req_key)
		free(req_key);
	_LOGE("pkgmgr_client_activate_app[%s] finish[%d]", appid, ret);

	return ret;
}

API int pkgmgr_client_activate_appv(pkgmgr_client * pc, const char *appid, char *const argv[])
{
	_LOGE("pkgmgr_client_activate_appv[%s] start.", appid);

	char *req_key = NULL;
	char *args = NULL;
	int ret = 0;
	int fd = 0;
	FILE *fp = NULL;
	char activation_info_file[PKG_STRING_LEN_MAX] = { 0, };

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
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	snprintf(activation_info_file, PKG_STRING_LEN_MAX, "%s/%s", PKG_DATA_PATH, appid);
	fp = fopen(activation_info_file, "w");
	tryvm_if(fp == NULL, ret = PKGMGR_R_ERROR, "fopen failed");

	if(argv) {
		if (argv[1]) {
			_LOGE("activate_appv label[%s]", argv[1]);
			fwrite(argv[1], sizeof(char), strlen(argv[1]), fp);

			args = (char *)calloc(strlen(argv[1]) + 1, sizeof(char));
			tryvm_if(args == NULL, ret = PKGMGR_R_ERROR, "calloc failed");
			strncpy(args, argv[1], strlen(argv[1]));
		}
	}
	fflush(fp);
	fd = fileno(fp);
	fsync(fd);
	fclose(fp);

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_ACTIVATE_APP_WITH_LABEL, "pkg", appid, args, NULL, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_ACTIVATE_APP_WITH_LABEL failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:

	if (args)
		free(args);
	if (req_key)
		free(req_key);

	_LOGE("pkgmgr_client_activate_appv[%s] finish[%d]", appid, ret);

	return ret;
}

API int pkgmgr_client_deactivate_app(pkgmgr_client *pc, const char *appid)
{
	_LOGE("pkgmgr_client_deactivate_app[%s] start.", appid);

	char *req_key = NULL;
	int ret = 0;
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
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	/* 3. request activate */
	ret = comm_client_request(mpc->info.request.cc, req_key, COMM_REQ_DEACTIVATE_APP, "pkg", appid, NULL, NULL, 1);
	tryvm_if(ret < 0, ret = PKGMGR_R_ECOMM, "COMM_REQ_TO_DEACTIVATOR failed, ret=%d", ret);

	ret = PKGMGR_R_OK;

catch:
	free(req_key);
	_LOGE("pkgmgr_client_deactivate_app[%s] finish[%d]", appid, ret);
	return ret;
}


API int pkgmgr_client_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				      const char *appid, pkgmgr_mode mode)
{
	const char *pkgtype = NULL;
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

	/* 2. get installer path using pkg_path */
	installer_path = _get_backend_path_with_type(pkgtype);
	if (installer_path == NULL)
		return PKGMGR_R_EINVAL;

	/* 3. generate req_key */
	req_key = __get_req_key(appid);

	/* 4. generate argv */

	/* argv[0] installer path */
	argv[argcnt++] = installer_path;
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
	if (args == NULL) {
		_LOGD("calloc failed");

		for (i = 0; i < argcnt; i++)
			free(argv[i]);

		return PKGMGR_R_ERROR;
	}
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

	if(args)
		free(args);

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
	char *pkgtype = NULL;
	pkg_plugin_set *plugin_set = NULL;
	package_manager_pkg_detail_info_t *pkg_detail_info = NULL;

	retvm_if(pkg_path == NULL, NULL, "pkg_path is NULL");

	pkg_detail_info = calloc(1, sizeof(package_manager_pkg_detail_info_t));
	retvm_if(pkg_detail_info == NULL, NULL, "pkg_detail_info calloc failed for path[%s]", pkg_path);

	pkgtype = _get_type_from_zip(pkg_path);
	tryvm_if(pkgtype == NULL, ret = PKGMGR_R_ERROR, "type is NULL for path[%s]", pkg_path);

	plugin_set = _package_manager_load_library(pkgtype);
	tryvm_if(plugin_set == NULL, ret = PKGMGR_R_ERROR, "load_library failed for path[%s]", pkg_path);

	ret = plugin_set->get_pkg_detail_info_from_package(pkg_path, pkg_detail_info);
	tryvm_if(ret != 0, ret = PKGMGR_R_ERROR, "get_pkg_detail_info_from_package failed for path[%s]", pkg_path);

	ret = PKGMGR_R_OK;

catch:
	if (pkgtype)
		free(pkgtype);

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

	ret = __request_size_info(pc);
	if (ret < 0) {
		_LOGE("__request_size_info fail \n");
	}

	pkgmgr_client_free(pc);
	return ret;
}

API int pkgmgr_client_clear_cache_dir(const char *pkgid)
{
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
		pkg_type = (char *)malloc(strlen("rpm") + 1);
		strcpy(pkg_type, "rpm");
		is_type_malloced = 1;
	}

	cookie = __get_cookie_from_security_server();
	tryvm_if(cookie == NULL, ret = PKGMGR_R_ESYSTEM, "__get_cookie_from_security_server is NULL");

	ret = comm_client_request(pc->info.request.cc, NULL, COMM_REQ_CLEAR_CACHE_DIR, pkg_type, pkgid, NULL, cookie, 0);
	tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "COMM_REQ_CLEAR_CACHE_DIR failed, ret=%d\n", ret);

	ret = PKGMGR_R_OK;
catch:
	if (cookie)
		free(cookie);

	if (pc)
		pkgmgr_client_free(pc);

	if(is_type_malloced)
		free(pkg_type);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;
}

API int pkgmgr_client_clear_all_cache_dir(void)
{
	int ret = 0;
	ret = pkgmgr_client_clear_cache_dir(PKG_CLEAR_ALL_CACHE);
	return ret;
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
	retvm_if(req_key == NULL, PKGMGR_R_EINVAL, "req_key is NULL");

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	ret = __get_package_size_info(mpc, req_key, pkgid, get_type);

	return ret;
}

API int pkgmgr_client_get_package_size_info(pkgmgr_client *pc, const char *pkgid, pkgmgr_pkg_size_info_receive_cb event_cb, void *user_data)
{
	pkgmgrinfo_pkginfo_h pkginfo = NULL;
	char *req_key = NULL;
	int req_id = 0;
	int res = 0;
	int type = PM_GET_PKG_SIZE_INFO;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "The specified pc is NULL.");
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "The package id is NULL.");

	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0)
	{	// total package size info
		type = PM_GET_TOTAL_PKG_SIZE_INFO;
	}
	else
	{
		res = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkginfo);
		retvm_if(res != 0, PKGMGR_R_ENOPKG, "The package id is not installed.");

		if (pkginfo) {
			pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
		}
	}

	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;
	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST");

	res = __change_op_cb_for_getsize(mpc);
	retvm_if(res < 0 , PKGMGR_R_ESYSTEM, "__change_op_cb_for_getsize is fail");

	req_key = __get_req_key(pkgid);
	retvm_if(req_key == NULL, PKGMGR_R_ESYSTEM, "req_key is NULL");

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, __get_pkg_size_info_cb, event_cb, user_data);

	res = __get_package_size_info(mpc, req_key, pkgid, type);

	return res;
}

API int pkgmgr_client_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb event_cb, void *user_data)
{	// total package size info
	return pkgmgr_client_get_package_size_info(pc, PKG_SIZE_INFO_TOTAL, (pkgmgr_pkg_size_info_receive_cb)event_cb, user_data);
}

API int junkmgr_get_junk_root_dirs(junkmgr_h junkmgr, junkmgr_result_receive_cb result_cb, void *user_data, int *reqid)
{
	if (!junkmgr)
	{
		LOGE("Invalid argument");
		return JUNKMGR_E_INVALID;
	}

	junkmgr_info_s *junk_info = (junkmgr_info_s *)malloc(sizeof(junkmgr_info_s));
	if (junk_info == NULL)
	{
		LOGE("out of memory");
		return JUNKMGR_E_NOMEM;
	}

	junk_info->junk_req_type = 0;
	junk_info->junk_storage = 2;
	junk_info->junk_root = NULL;

	return __get_junk_info((junkmgr_s *)junkmgr, NULL, junk_info, (void *)result_cb, user_data, reqid);
}

API int junkmgr_get_junk_files(junkmgr_h junkmgr, char const *junk_path, junkmgr_result_receive_cb result_cb, void *user_data, int *reqid)
{
	char *entry = NULL;
	struct stat st;
	int storage = -1; //0: internal, 1: external, 2: all
	char *name = NULL;
	char filename[MAX_FILENAME_SIZE] = { 0, };
	int delimiter = 0;

	if (!junkmgr || !junk_path)
	{
		LOGE("Invalid argument");
		return JUNKMGR_E_INVALID;
	}

	entry = strstr(junk_path, "/opt/usr/media/");
	if (entry)
	{
		LOGD("junk entry: %s", entry);
		storage = 0;
	}
	else
	{
		entry = strstr(junk_path, "/opt/storage/sdcard/");
		if (entry)
		{
			LOGD("junk entry: %s", entry);
			storage = 1;
		}
		else
		{
			LOGE("Invalid junk file path");
			return JUNKMGR_E_INVALID;
		}
	}

	stat(junk_path, &st);
	if (!S_ISDIR(st.st_mode))
	{
		LOGE("This is not directory.");
		return JUNKMGR_E_INVALID;
	}

	name = (char *)g_strrstr(junk_path, "/");
	if (name && strlen(name) == 1)
	{
		name = (char *)g_strrstr(entry, "/");
		delimiter = 1;
	}

	if (NULL == name + 1)
	{
		LOGE("Invalid name.");
		return JUNKMGR_E_INVALID;
	}

	strncpy(filename, name + 1, MAX_FILENAME_SIZE);
	if (delimiter) {
		filename[strlen(filename) - 1] = '\0';
	}

	junkmgr_info_s *junk_info = (junkmgr_info_s *)malloc(sizeof(junkmgr_info_s));
	if (junk_info == NULL)
	{
		LOGE("out of memory");
		return JUNKMGR_E_NOMEM;
	}

	junk_info->junk_req_type = 1;
	junk_info->junk_storage = storage;
	junk_info->junk_root = strdup(filename);

	return __get_junk_info((junkmgr_s *)junkmgr, junk_path, junk_info, (void *)result_cb, user_data, reqid);
}

API int junkmgr_remove_junk_file(junkmgr_h junkmgr, char const *junk_path)
{
    struct stat st;

	if (!junkmgr)
	{
        LOGE("Invalid argument");
		return JUNKMGR_E_INVALID;
	}

	junkmgr_s *junk_mgr = (junkmgr_s *)junkmgr;
	if (!junk_mgr->db_path)
	{
        LOGE("Invalid argument");
		return JUNKMGR_E_INVALID;
	}

    stat(junk_path, &st);
    if (S_ISDIR(st.st_mode))
    {
        LOGE("This is directory.");
        return JUNKMGR_E_INVALID;
    }

	return __remove_junk_file(junk_mgr->db_path, junk_path);
}

static int __clear_all_junk_files(junkmgr_s *junkmgr, junkmgr_clear_completed_cb result_cb, void *user_data, int *reqid)
{
	junkmgr_info_s *junk_info = (junkmgr_info_s *)malloc(sizeof(junkmgr_info_s));
	if (junk_info == NULL)
	{
		LOGE("out of memory");
		return JUNKMGR_E_NOMEM;
	}

	junk_info->junk_req_type = 2;
	junk_info->junk_storage = 2;
	junk_info->junk_root = NULL;

	return __get_junk_info((junkmgr_s *)junkmgr, NULL/*all*/, junk_info, (void *)result_cb, user_data, reqid);
}

API int junkmgr_clear_all_junk_files(junkmgr_h junkmgr, junkmgr_clear_completed_cb result_cb, void *user_data, int *reqid)
{
	if (!junkmgr)
	{
        LOGE("Invalid argument");
		return JUNKMGR_E_INVALID;
	}

	junkmgr_s *junk_mgr = (junkmgr_s *)junkmgr;
	if (!junk_mgr->db_path)
	{
		LOGE("Invalid argument");
		return JUNKMGR_E_INVALID;
	}

	return __clear_all_junk_files((junkmgr_s *)junkmgr, result_cb, user_data, reqid);
}

API int pkgmgr_client_enable_pkg(const char *pkgid)
{
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");

	int ret = 0;
	pkgmgrinfo_pkginfo_h handle = NULL;

	if (strstr(pkgid,":")==NULL) {
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
		if ((ret == 0) && (handle != NULL)) {
			SECURE_LOGD("pkg[%s] is already installed.", pkgid);
			pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
			// This package is already installed. skip the activation event.
			return PKGMGR_R_OK;
		}
	}

	const char *enable_argv[] = { "/usr/bin/rpm-backend", "-k", "change-state", "-i", pkgid, NULL };
	ret = __xsystem(enable_argv);
	if (ret < 0)
		SECURE_LOGD("enable pkg[%s] failed\n", pkgid);
	else
		SECURE_LOGD("enable pkg[%s] success\n", pkgid);
	return ret;
}

API int pkgmgr_client_disable_pkg(const char *pkgid)
{
	retvm_if(pkgid == NULL, PKGMGR_R_EINVAL, "pkgid is NULL");

	int ret = 0;
	pkgmgrinfo_pkginfo_h handle = NULL;

	if (strstr(pkgid,":")==NULL) {
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
		// This package is not installed. skip the deactivation event.
		if ((ret < 0) || (handle == NULL)) {
			SECURE_LOGD("pkg[%s] is not installed.", pkgid);
			return PKGMGR_R_OK;
		}
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}

	const char *disable_argv[] = { "/usr/bin/rpm-backend", "-k", "change-state", "-d", pkgid, NULL };
	ret = __xsystem(disable_argv);
	if (ret < 0)
		SECURE_LOGD("disable pkg[%s] failed\n", pkgid);
	else
		SECURE_LOGD("disable pkg[%s] success\n", pkgid);
	return ret;
}

API int pkgmgr_client_reset_device(void)
{
	int ret = 0;
	PKGMGR_BEGIN();

	__pkgmgr_log_init();

	//0. check authorized
	uid_t uid = getuid();
	retvm_if(uid != (uid_t)0, PKGMGR_R_ERROR, "You are not an authorized user!!!\n");

	// display ui
	const char *displayui_argv[] = { "/usr/etc/package-manager/pkgmgr-soft-reset-ui.sh", NULL };
	__xsystem(displayui_argv);

	//1. uninstall download package
	 __uninstall_downloaded_packages();

	//2. pkg db rollback form opt.zip
//	__recovery_pkgmgr_db();

	//3. delete pkg directory, data and make new
	__soft_reset_pkg();

	//4. apply support reset script
	__none_reset_pkg();

	//5. run pkg's script
	__run_reset_script();

	__pkgmgr_log_deinit();

	PKGMGR_END();

	const char *reboot_cmd[] = {"/usr/sbin/reboot", NULL, NULL};
	__xsystem(reboot_cmd);

	return ret;
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

API int junkmgr_result_cursor_step_next(junkmgr_result_h hnd)
{
    junkmgr_result_s *handle = (junkmgr_result_s *)hnd;

    int ret = sqlite3_step((sqlite3_stmt *)(handle->db_stmt));
    switch (ret)
    {
        case SQLITE_ROW:
            return JUNKMGR_E_SUCCESS;
        case SQLITE_DONE:
            return JUNKMGR_E_END_OF_RESULT;
        case SQLITE_BUSY:
            return JUNKMGR_E_OBJECT_LOCKED;
        default:
            return JUNKMGR_E_SYSTEM;
    }

    return JUNKMGR_E_SYSTEM;
}

API int junkmgr_result_cursor_get_junk_name(junkmgr_result_h hnd, char **junk_name)
{
    junkmgr_result_s *handle = (junkmgr_result_s *)hnd;

    int size = sqlite3_column_bytes((sqlite3_stmt *)(handle->db_stmt), 0);
    char *name = (char *)sqlite3_column_text((sqlite3_stmt *)(handle->db_stmt), 0);

    *junk_name = (char *)malloc(size + 1);
    strncpy(*junk_name, name, size);
    (*junk_name)[size] = '\0';

    return JUNKMGR_E_SUCCESS;
}

API int junkmgr_result_cursor_get_category(junkmgr_result_h hnd, junkmgr_category_e *category)
{
    junkmgr_result_s *handle = (junkmgr_result_s *)hnd;

	int media_subdir = sqlite3_column_int((sqlite3_stmt *)(handle->db_stmt), 1);
    *category = (junkmgr_category_e)media_subdir;
    return JUNKMGR_E_SUCCESS;
}

API int junkmgr_result_cursor_get_file_type(junkmgr_result_h hnd, junkmgr_file_type_e *file_type)
{
    junkmgr_result_s *handle = (junkmgr_result_s *)hnd;

	int type = sqlite3_column_int((sqlite3_stmt *)(handle->db_stmt), 2);
    *file_type = (junkmgr_file_type_e)type;
    return JUNKMGR_E_SUCCESS;
}

API int junkmgr_result_cursor_get_storage_type(junkmgr_result_h hnd, junkmgr_storage_type_e *storage)
{
    junkmgr_result_s *handle = (junkmgr_result_s *)hnd;

	int where = sqlite3_column_int((sqlite3_stmt *)(handle->db_stmt), 3);
    *storage = (junkmgr_storage_type_e)where;
    return JUNKMGR_E_SUCCESS;
}

API int junkmgr_result_cursor_get_junk_size(junkmgr_result_h hnd, long long *junk_size)
{
    junkmgr_result_s *handle = (junkmgr_result_s *)hnd;

	*junk_size = sqlite3_column_int64((sqlite3_stmt *)(handle->db_stmt), 4);
    return JUNKMGR_E_SUCCESS;
}

API int junkmgr_result_cursor_get_junk_path(junkmgr_result_h hnd, char **junk_path)
{
    junkmgr_result_s *handle = (junkmgr_result_s *)hnd;

    int size = sqlite3_column_bytes((sqlite3_stmt *)(handle->db_stmt), 5);
    char *path = (char *)sqlite3_column_text((sqlite3_stmt *)(handle->db_stmt), 5);

    *junk_path = (char *)malloc(size + 1);
    strncpy(*junk_path, path, size);
    (*junk_path)[size] = '\0';

    return JUNKMGR_E_SUCCESS;
}
