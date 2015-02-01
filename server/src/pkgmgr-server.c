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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <glib.h>
#include <signal.h>
#include <dbus/dbus.h>
#include <security-server.h>
#include <vconf.h>
#include <pkgmgr-info.h>
#include <pkgmgr_parser.h>

#include "pm-queue.h"
#include "pkgmgr_installer.h"
#include "pkgmgr-server.h"
#include "comm_pkg_mgr_server.h"
#include "comm_config.h"
#include "package-manager.h"
#include "package-manager-debug.h"
#include "package-manager-internal.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "PKGMGR_SERVER"

#define IS_WHITESPACE(CHAR) \
((CHAR == ' ' || CHAR == '\t' || CHAR == '\r' || CHAR == '\n') ? TRUE : FALSE)

#define PACKAGE_RECOVERY_DIR "/opt/share/packages/.recovery/pkgmgr"

#define DESKTOP_W   720.0

#define NO_MATCHING_FILE 11

static int backend_flag = 0;	/* 0 means that backend process is not running */

/*
8 bit value to represent maximum 8 backends.
Each bit position corresponds to a queue slot which
is dynamically determined.
*/
char backend_busy = 0;
/*
8 bit value to represent quiet mode operation for maximum 8 backends
1->quiet 0->non-quiet
Each bit position corresponds to a queue slot which
is dynamically determined.
*/
char backend_mode = 63; /*00111111*/
extern int num_of_backends;

backend_info *begin;
extern queue_info_map *start;
extern int entries;
int pos = 0;
/*To store info in case of backend crash*/
char pname[MAX_PKG_NAME_LEN] = {'\0'};
char ptype[MAX_PKG_TYPE_LEN] = {'\0'};
char args[MAX_PKG_ARGS_LEN] = {'\0'};

GMainLoop *mainloop = NULL;

static int __check_backend_status_for_exit();
static int __check_queue_status_for_exit();
static int __is_backend_busy(int position);
static void __set_backend_busy(int position);
static void __set_backend_free(int position);
static void __set_backend_mode(int position);
static void __unset_backend_mode(int position);

static void sighandler(int signo);
gboolean queue_job(void *data);
gboolean send_fail_signal(void *data);
gboolean exit_server(void *data);

/* To check whether a particular backend is free/busy*/
static int __is_backend_busy(int position)
{
	return backend_busy & 1<<position;
}
/*To set a particular backend as busy*/
static void __set_backend_busy(int position)
{
	backend_busy = backend_busy | 1<<position;
}
/*To set a particular backend as free */
static void __set_backend_free(int position)
{
	backend_busy = backend_busy & ~(1<<position);
}

/*To set a particular backend mode as quiet*/
static void __set_backend_mode(int position)
{
	backend_mode = backend_mode | 1<<position;
}
/*To unset a particular backend mode */
static void __unset_backend_mode(int position)
{
	backend_mode = backend_mode & ~(1<<position);
}

static void __set_recovery_mode(char *pkgid, char *pkg_type)
{
	char recovery_file[MAX_PKG_NAME_LEN] = { 0, };
	char buffer[MAX_PKG_NAME_LEN] = { 0 };
	char *pkgid_tmp = NULL;
	FILE *rev_file = NULL;

	if (pkgid == NULL) {
		_LOGE("pkgid is null\n");
		return;
	}

	/*if pkgid has a "/"charactor, that is a path name for installation, then extract pkgid from absolute path*/
	if (strstr(pkgid, "/")) {
		pkgid_tmp = strrchr(pkgid, '/') + 1;
		if (pkgid_tmp == NULL) {
			_LOGD("pkgid_tmp[%s] is null\n", pkgid);
			return;
		}
		snprintf(recovery_file, MAX_PKG_NAME_LEN, "%s/%s", PACKAGE_RECOVERY_DIR, pkgid_tmp);
	} else {
		snprintf(recovery_file, MAX_PKG_NAME_LEN, "%s/%s", PACKAGE_RECOVERY_DIR, pkgid);
	}

	rev_file = fopen(recovery_file, "w");
	if (rev_file== NULL) {
		_LOGD("rev_file[%s] is null\n", recovery_file);
		return;
	}

	snprintf(buffer, MAX_PKG_NAME_LEN, "pkgid : %s\n", pkgid);
	fwrite(buffer, sizeof(char), strlen(buffer), rev_file);

	fclose(rev_file);
}

static void __unset_recovery_mode(char *pkgid, char *pkg_type)
{
	int ret = -1;
	char recovery_file[MAX_PKG_NAME_LEN] = { 0, };
	char *pkgid_tmp = NULL;

	if (pkgid == NULL) {
		_LOGE("pkgid is null\n");
		return;
	}

	/*if pkgid has a "/"charactor, that is a path name for installation, then extract pkgid from absolute path*/
	if (strstr(pkgid, "/")) {
		pkgid_tmp = strrchr(pkgid, '/') + 1;
		if (pkgid_tmp == NULL) {
			_LOGD("pkgid_tmp[%s] is null\n", pkgid);
			return;
		}
		snprintf(recovery_file, MAX_PKG_NAME_LEN, "%s/%s", PACKAGE_RECOVERY_DIR, pkgid_tmp);
	} else {
		snprintf(recovery_file, MAX_PKG_NAME_LEN, "%s/%s", PACKAGE_RECOVERY_DIR, pkgid);
	}

	ret = remove(recovery_file);
	if (ret < 0)
		_LOGD("remove recovery_file[%s] fail\n", recovery_file);
}

static int __check_privilege_by_cookie(const char *e_cookie, int req_type)
{
	guchar *cookie = NULL;
	gsize size;
	int ret = PMINFO_R_ERROR;

	if (e_cookie == NULL)	{
		_LOGE("e_cookie is NULL!!!\n");
		return PMINFO_R_ERROR;
	}

	cookie = g_base64_decode(e_cookie, &size);
	if (cookie == NULL)	{
		_LOGE("Unable to decode cookie!!!\n");
		return PMINFO_R_ERROR;
	}

	switch (req_type) {
		case COMM_REQ_TO_INSTALLER:
			ret = security_server_check_privilege_by_cookie((const char*)cookie, "pkgmgr::svc", "r");
			if (SECURITY_SERVER_API_SUCCESS == ret)
				ret = PMINFO_R_OK;
			break;

		case COMM_REQ_TO_MOVER:
			ret = security_server_check_privilege_by_cookie((const char*)cookie, "pkgmgr::svc", "x");
			if (SECURITY_SERVER_API_SUCCESS == ret)
				ret = PMINFO_R_OK;
			break;
		case COMM_REQ_GET_JUNK_INFO:
			ret = security_server_check_privilege_by_cookie((const char*)cookie, "junkmgr::scan", "x");
			if (SECURITY_SERVER_API_SUCCESS == ret)
				ret = PMINFO_R_OK;
			break;
		case COMM_REQ_GET_SIZE:
			ret = security_server_check_privilege_by_cookie((const char*)cookie, "pkgmgr::info", "r");
			if (SECURITY_SERVER_API_SUCCESS == ret)
				ret = PMINFO_R_OK;
			break;

		case COMM_REQ_CLEAR_CACHE_DIR:
			ret = security_server_check_privilege_by_cookie((const char*)cookie, "pkgmgr::svc", "x");
			if (SECURITY_SERVER_API_SUCCESS == ret)
				ret = PMINFO_R_OK;
			break;

		default:
			_LOGD("Check your request[%d]..\n", req_type);
			break;
	}

	_LOGD("security_server[req-type:%d] check cookie result = %d, \n", req_type, ret);

	if (cookie){
		g_free(cookie);
		cookie = NULL;
	}

	return ret;
}

static int __get_position_from_pkg_type(char *pkgtype)
{
	int i = 0;
	queue_info_map *ptr;
	ptr = start;
	for(i = 0; i < entries; i++)
	{
		if (!strncmp(ptr->pkgtype, pkgtype, MAX_PKG_TYPE_LEN))
			return ptr->queue_slot;
		else
			ptr++;

	}
	return -1;
}

void __get_type_from_msg(pm_dbus_msg *item)
{
	char *pkgtype = NULL;

	pkgtype = _get_type_from_zip(item->pkgid);
	retm_if(pkgtype == NULL, "pkgtype is null for %s \n", item->pkgid);

	_LOGD("pkg type = %s, file = %s \n", pkgtype, item->pkgid);

	memset((item->pkg_type),0,MAX_PKG_TYPE_LEN);
	strncpy(item->pkg_type, pkgtype, sizeof(item->pkg_type) - 1);
	free(pkgtype);
}

gboolean send_fail_signal(void *data)
{
	_LOGD("send_fail_signal start\n");
	gboolean ret_parse;
	gint argcp;
	gchar **argvp;
	GError *gerr = NULL;
	pkgmgr_installer *pi;
	pi = pkgmgr_installer_new();
	if (!pi) {
		_LOGD("Failure in creating the pkgmgr_installer object");
		return FALSE;
	}
	ret_parse = g_shell_parse_argv(args,
				       &argcp, &argvp, &gerr);
	if (FALSE == ret_parse) {
		_LOGD("Failed to split args: %s", args);
		_LOGD("messsage: %s", gerr->message);
		pkgmgr_installer_free(pi);
		return FALSE;
	}

	pkgmgr_installer_receive_request(pi, argcp, argvp);
	pkgmgr_installer_send_signal(pi, ptype, pname, "end", "fail");
	pkgmgr_installer_free(pi);
	return FALSE;
}

static void sighandler(int signo)
{
	int status;
	pid_t cpid;
	int i = 0;
	backend_info *ptr = NULL;
	ptr = begin;

	while ((cpid = waitpid(-1, &status, WNOHANG)) > 0) {
		_LOGD("child exit [%d]\n", cpid);
		if (WIFEXITED(status)) {
			for(i = 0; i < num_of_backends; i++)
			{
				if (cpid == (ptr + i)->pid) {
					__set_backend_free(i);
					__set_backend_mode(i);
					__unset_recovery_mode((ptr + i)->pkgid, (ptr + i)->pkgtype);
					if (WEXITSTATUS(status)) {
						strncpy(pname, (ptr + i)->pkgid, MAX_PKG_NAME_LEN-1);
						strncpy(ptype, (ptr + i)->pkgtype, MAX_PKG_TYPE_LEN-1);
						strncpy(args, (ptr + i)->args, MAX_PKG_ARGS_LEN-1);
						g_idle_add(send_fail_signal, NULL);
						_LOGD("child exit [%d] with error code:%d\n", cpid, WEXITSTATUS(status));
					} else {
						_LOGD("child NORMAL exit [%d]\n", cpid);
					}
					break;
				}
			}
		}
		else if (WIFSIGNALED(status)) {
			_LOGD("child SIGNALED exit [%d]\n", cpid);
			/*get the pkgid and pkgtype to send fail signal*/
			for(i = 0; i < num_of_backends; i++)
			{
				if (cpid == (ptr + i)->pid) {
					__set_backend_free(i);
					__set_backend_mode(i);
					__unset_recovery_mode((ptr + i)->pkgid, (ptr + i)->pkgtype);
					strncpy(pname, (ptr + i)->pkgid, MAX_PKG_NAME_LEN-1);
					strncpy(ptype, (ptr + i)->pkgtype, MAX_PKG_TYPE_LEN-1);
					strncpy(args, (ptr + i)->args, MAX_PKG_ARGS_LEN-1);
					g_idle_add(send_fail_signal, NULL);
					break;
				}
			}
		}
	}

}

static void __register_signal_handler(void)
{
	static int sig_reg = 0;

	if (sig_reg == 0) {
		struct sigaction act;

		act.sa_handler = sighandler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_NOCLDSTOP;

		if (sigaction(SIGCHLD, &act, NULL) < 0) {
			_LOGD("signal: SIGCHLD failed\n");
		} else
			_LOGD("signal: SIGCHLD succeed\n");
		if (g_timeout_add_seconds(2, exit_server, NULL))
			_LOGD("g_timeout_add_seconds() Added to Main Loop");

		sig_reg = 1;
	}
}

int create_external_dir_cb(void)
{
	int err = -1;
	int p = 0;

	SECURE_LOGD(">> in callback >> External storage has been mounted");

	__register_signal_handler();

	pm_dbus_msg *item = calloc(1, sizeof(pm_dbus_msg));
	if (item == NULL)
	{
		_LOGE("Out of memory");
		return err;
	}

	item->req_type = COMM_REQ_MAKE_EXTERNAL_DIR;
	strcpy(item->pkg_type, "rpm");

	err = _pm_queue_push(item);
	p = __get_position_from_pkg_type(item->pkg_type);
	__set_backend_mode(p);
	if (err == 0)
	{
		g_idle_add(queue_job, NULL);
	}

	free(item);

	return err;
}

void req_cb(void *cb_data, const char *req_id, const int req_type,
	    const char *pkg_type, const char *pkgid, const char *args,
	    const char *cookie, int *ret)
{
	int err = -1;
	int p = 0;
	int cookie_result = 0;

	SECURE_LOGD(">> in callback >> Got request: [%s] [%d] [%s] [%s] [%s] [%s]",
	    req_id, req_type, pkg_type, pkgid, args, cookie);

	__register_signal_handler();

	pm_dbus_msg *item = calloc(1, sizeof(pm_dbus_msg));
	if (item == NULL)
	{
		_LOGE("Out of memory");
		return;
	}

	strncpy(item->req_id, req_id, sizeof(item->req_id) - 1);
	item->req_type = req_type;
	strncpy(item->pkg_type, pkg_type, sizeof(item->pkg_type) - 1);

	strncpy(item->pkgid, pkgid, sizeof(item->pkgid) - 1);
	strncpy(item->args, args, sizeof(item->args) - 1);
	strncpy(item->cookie, cookie, sizeof(item->cookie) - 1);

	_LOGD("req_type=(%d)  backend_flag=(%d)\n", req_type,backend_flag);



	switch (item->req_type) {
	case COMM_REQ_TO_INSTALLER:
		/* check caller privilege */
		cookie_result = __check_privilege_by_cookie(cookie, item->req_type);
		if (cookie_result < 0){
			_LOGD("__check_privilege_by_cookie result fail[%d]\n", cookie_result);
			*ret = PKGMGR_R_EPRIV;
			goto err;
		}

		/* get pkgtype from msg-args */
		__get_type_from_msg(item);

		/* quiet mode */
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		if (p < 0) {
			_LOGE("invalid or unsupported package");
			*ret = PKGMGR_R_ERROR;
			break;
		}
		__set_backend_mode(p);
		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_ACTIVATE_PKG:
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_DEACTIVATE_PKG:
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_ACTIVATE_APP:
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_DEACTIVATE_APP:
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_ACTIVATE_APP_WITH_LABEL:
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_TO_CLEARER:
		/* In case of clearer, there is no popup */
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		/*the backend shows the success/failure popup
		so this request is non quiet*/
		__unset_backend_mode(p);

/*		g_idle_add(queue_job, NULL); */
		if (err == 0)
			queue_job(NULL);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_TO_MOVER:
		/* check caller privilege */
		cookie_result = __check_privilege_by_cookie(cookie, item->req_type);
		if (cookie_result < 0){
			_LOGD("__check_privilege_by_cookie result fail[%d]\n", cookie_result);
			*ret = PKGMGR_R_EPRIV;
			goto err;
		}

		/* In case of mover, there is no popup */
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		/*the backend shows the success/failure popup
		so this request is non quiet*/
		__unset_backend_mode(p);
		if (err == 0)
			queue_job(NULL);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_CANCEL:
		_pm_queue_delete(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__unset_backend_mode(p);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_GET_JUNK_INFO:
		/* check caller privilege */
#ifdef _APPFW_PKGMGR_PRIV_SUPPORT //XXX: Temporary define
		cookie_result = __check_privilege_by_cookie(cookie, item->req_type);
		if (cookie_result < 0){
			_LOGE("__check_privilege_by_cookie result fail[%d]\n", cookie_result);
			*ret = PKGMGR_R_EPRIV;
			goto err;
		}
#endif
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = PKGMGR_R_OK;
		break;
	case COMM_REQ_GET_SIZE:
		/* check caller privilege */
#ifdef _APPFW_PKGMGR_PRIV_SUPPORT //XXX: Temporary define
		cookie_result = __check_privilege_by_cookie(cookie, item->req_type);
		if (cookie_result < 0){
			_LOGE("__check_privilege_by_cookie result fail[%d]\n", cookie_result);
			*ret = PKGMGR_R_EPRIV;
			goto err;
		}
#endif
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);
		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = PKGMGR_R_OK;
		break;

	case COMM_REQ_CHECK_APP:
	case COMM_REQ_KILL_APP:
		/* In case of activate, there is no popup */
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);

/*		g_idle_add(queue_job, NULL); */
		if (err == 0)
			queue_job(NULL);
		*ret = PKGMGR_R_OK;
		break;

	case COMM_REQ_CLEAR_CACHE_DIR:
		/* check caller privilege */
#ifdef _APPFW_PKGMGR_PRIV_SUPPORT //XXX: Temporary define
		cookie_result = __check_privilege_by_cookie(cookie, item->req_type);
		if (cookie_result < 0){
			_LOGE("__check_privilege_by_cookie result fail[%d]\n", cookie_result);
			*ret = PKGMGR_R_EPRIV;
			goto err;
		}
#endif
		err = _pm_queue_push(item);
		p = __get_position_from_pkg_type(item->pkg_type);
		__set_backend_mode(p);

		if (err == 0)
			g_idle_add(queue_job, NULL);
		*ret = PKGMGR_R_OK;
		break;

	default:
		_LOGD("Check your request..\n");
		*ret = PKGMGR_R_ERROR;
		break;
	}
err:
	if (*ret != PKGMGR_R_OK) {
		_LOGD("Failed to handle request %s %s\n",item->pkg_type, item->pkgid);
		pkgmgr_installer *pi;
		gboolean ret_parse;
		gint argcp;
		gchar **argvp;
		GError *gerr = NULL;

		pi = pkgmgr_installer_new();
		if (!pi) {
			_LOGD("Failure in creating the pkgmgr_installer object");
			if(item){
				free(item);
				item = NULL;
			}
			return;
		}

		ret_parse = g_shell_parse_argv(args, &argcp, &argvp, &gerr);
		if (FALSE == ret_parse) {
			_LOGD("Failed to split args: %s", args);
			_LOGD("messsage: %s", gerr->message);
			pkgmgr_installer_free(pi);
			if(item){
				free(item);
				item = NULL;
			}
			return;
		}

		pkgmgr_installer_receive_request(pi, argcp, argvp);

		pkgmgr_installer_send_signal(pi, item->pkg_type,
					     item->pkgid, "end",
					     "fail");

		pkgmgr_installer_free(pi);

	}

	if(item){
		free(item);
		item = NULL;
	}
	return;
}

static int __check_backend_status_for_exit()
{
	int i = 0;
	for(i = 0; i < num_of_backends; i++)
	{
		if (!__is_backend_busy(i))
			continue;
		else
			return 0;
	}
	return 1;
}

static int __check_queue_status_for_exit()
{
	pm_queue_data *head[MAX_QUEUE_NUM] = {NULL,};
	queue_info_map *ptr = NULL;
	ptr = start;
	int i = 0;
	int c = 0;
	int slot = -1;
	for(i = 0; i < entries; i++)
	{
		if (ptr->queue_slot <= slot) {
			ptr++;
			continue;
		}
		else {
			head[c] = ptr->head;
			slot = ptr->queue_slot;
			c++;
			ptr++;
		}
	}
	for(i = 0; i < num_of_backends; i++)
	{
		if (!head[i])
			continue;
		else
			return 0;
	}
	return 1;
}

gboolean exit_server(void *data)
{
	_LOGD("exit_server Start\n");
	if (__check_backend_status_for_exit() && __check_queue_status_for_exit()) {
		if (!getenv("PMS_STANDALONE")) {
			g_main_loop_quit(mainloop);
			return FALSE;
		}
	}
	return TRUE;
}

static int __pkgcmd_read_proc(const char *path, char *buf, int size)
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

static int __pkgcmd_find_pid_by_cmdline(const char *dname,
			const char *cmdline, const char *apppath)
{
	int pid = 0;

	if (strcmp(cmdline, apppath) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid))
			pid = 0;
	}
	return pid;
}

static int __pkgcmd_proc_iter_kill_cmdline(const char *apppath, int option)
{
	DIR *dp;
	struct dirent *dentry;
	int pid;
	int ret;
	char buf[1024] = {'\0'};
	int pgid;

	dp = opendir("/proc");
	if (dp == NULL) {
		return -1;
	}

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(buf, sizeof(buf), "/proc/%s/cmdline", dentry->d_name);
		ret = __pkgcmd_read_proc(buf, buf, sizeof(buf));
		if (ret <= 0)
			continue;

		pid = __pkgcmd_find_pid_by_cmdline(dentry->d_name, buf, apppath);
		if (pid > 0) {
			if (option == 0) {
				closedir(dp);
				return pid;
			}
			pgid = getpgid(pid);
			if (pgid <= 1) {
				closedir(dp);
				return -1;
			}
			if (killpg(pgid, SIGKILL) < 0) {
				closedir(dp);
				return -1;
			}
			closedir(dp);
			return pid;
		}
	}
	closedir(dp);
	return 0;
}

static void __make_pid_info_file(char *req_key, int size)
{
	int ret = 0;
	FILE* file = NULL;
	int fd = 0;
	char buf[MAX_PKG_TYPE_LEN] = {0};
	const char* app_info_label = "*";
	char info_file[MAX_PKG_TYPE_LEN] = {'\0', };

	if(req_key == NULL)
		return;

	snprintf(info_file, MAX_PKG_TYPE_LEN, "/tmp/%s", req_key);
	_LOGD("File path = %s\n", info_file);

	file = fopen(info_file, "w");
	if (file == NULL) {
		_LOGE("Couldn't open the file %s \n", info_file);
		return;
	}

	snprintf(buf, 128, "%d\n", size);
	fwrite(buf, 1, strlen(buf), file);

	fflush(file);
	fd = fileno(file);
	fsync(fd);
	fclose(file);

	if(lsetxattr(info_file, "security.SMACK64", app_info_label, strlen(app_info_label), 0)) {
		_LOGE("error(%d) in setting smack label",errno);
	}
	ret = chmod(info_file, 0777);
	if(ret < 0)
		return;
	ret = chown(info_file, 5000, 5000);
	if(ret < 0)
		return;
}

static int __pkgcmd_app_cb(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *pkgid = NULL;
	char *exec = NULL;
	int ret = 0;
	int pid = -1;
	if (handle == NULL) {
		perror("appinfo handle is NULL\n");
		exit(1);
	}
	ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	if (ret) {
		perror("Failed to get app exec path\n");
		exit(1);
	}
	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	if (ret) {
		perror("Failed to get appid\n");
		exit(1);
	}

	if (strcmp(user_data, "kill") == 0)
		pid = __pkgcmd_proc_iter_kill_cmdline(exec, 1);
	else if(strcmp(user_data, "check") == 0)
		pid = __pkgcmd_proc_iter_kill_cmdline(exec, 0);

//	vconf_set_int(VCONFKEY_PKGMGR_STATUS, pid);
	__make_pid_info_file(pkgid, pid);

	return 0;
}

void __pm_send_sub_signal(const char *req_id, const char *pkg_type, const char *pkgid, const char *key, const char *val)
{
	dbus_uint32_t serial = 0;
	DBusMessage *msg = NULL;
	DBusMessageIter args;
	DBusError err;
	DBusConnection *conn = NULL;
	const char *values[] = {
		req_id,
		pkg_type,
		pkgid,
		key,
		val
	};
	int i;

	dbus_error_init(&err);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) {
		_LOGE("Connection error: %s", err.message);
		dbus_error_free(&err);
	}
	dbus_error_free(&err);
	if (NULL == conn) {
		_LOGE("conn is NULL");
		return;
	}

	if (strcmp(key,PKGMGR_INSTALLER_START_KEY_STR) == 0) {
		if (strcmp(val,PKGMGR_INSTALLER_INSTALL_EVENT_STR) == 0) {
			msg = dbus_message_new_signal(COMM_STATUS_BROADCAST_DBUS_INSTALL_PATH, COMM_STATUS_BROADCAST_DBUS_INSTALL_INTERFACE, COMM_STATUS_BROADCAST_EVENT_INSTALL);
		} else if (strcmp(val,PKGMGR_INSTALLER_UNINSTALL_EVENT_STR) == 0) {
			msg = dbus_message_new_signal(COMM_STATUS_BROADCAST_DBUS_UNINSTALL_PATH, COMM_STATUS_BROADCAST_DBUS_UNINSTALL_INTERFACE, COMM_STATUS_BROADCAST_EVENT_UNINSTALL);
		} else if (strcmp(val,PKGMGR_INSTALLER_UPGRADE_EVENT_STR) == 0) {
			msg = dbus_message_new_signal(COMM_STATUS_BROADCAST_DBUS_UPGRADE_PATH, COMM_STATUS_BROADCAST_DBUS_UPGRADE_INTERFACE, COMM_STATUS_BROADCAST_EVENT_UPGRADE);
		}
	} else if (strcmp(key,PKGMGR_INSTALLER_END_KEY_STR) == 0) {
		if (strcmp(req_id,PKGMGR_INSTALLER_INSTALL_EVENT_STR) == 0) {
			msg = dbus_message_new_signal(COMM_STATUS_BROADCAST_DBUS_INSTALL_PATH, COMM_STATUS_BROADCAST_DBUS_INSTALL_INTERFACE, COMM_STATUS_BROADCAST_EVENT_INSTALL);
		} else if (strcmp(req_id,PKGMGR_INSTALLER_UNINSTALL_EVENT_STR) == 0) {
			msg = dbus_message_new_signal(COMM_STATUS_BROADCAST_DBUS_UNINSTALL_PATH, COMM_STATUS_BROADCAST_DBUS_UNINSTALL_INTERFACE, COMM_STATUS_BROADCAST_EVENT_UNINSTALL);
		} else if (strcmp(req_id,PKGMGR_INSTALLER_UPGRADE_EVENT_STR) == 0) {
			msg = dbus_message_new_signal(COMM_STATUS_BROADCAST_DBUS_UPGRADE_PATH, COMM_STATUS_BROADCAST_DBUS_UPGRADE_INTERFACE, COMM_STATUS_BROADCAST_EVENT_UPGRADE);
		}
	}
	if (NULL == msg) {
		_LOGE("msg NULL");
		return;
	}

	dbus_message_iter_init_append(msg, &args);

	for (i = 0; i < 5; i++) {
		if (!dbus_message_iter_append_basic
		    (&args, DBUS_TYPE_STRING, &(values[i]))) {
			_LOGE("dbus_message_iter_append_basic failed:"
			" Out of memory");
			return;
		}
	}
	if (!dbus_connection_send(conn, msg, &serial)) {
		_LOGE("dbus_connection_send failed: Out of memory");
		return;
	}
	dbus_connection_flush(conn);
	dbus_message_unref(msg);
}

void __pm_send_signal(const char *req_id, const char *pkg_type, const char *pkgid, const char *key, const char *val)
{
	dbus_uint32_t serial = 0;
	DBusMessage *msg;
	DBusMessageIter args;
	DBusError err;
	DBusConnection *conn;
	const char *values[] = {
		req_id,
		pkg_type,
		pkgid,
		key,
		val
	};
	int i;

	dbus_error_init(&err);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) {
		_LOGE("Connection error: %s", err.message);
		dbus_error_free(&err);
	}
	dbus_error_free(&err);
	if (NULL == conn) {
		_LOGE("conn is NULL");
		return;
	}

	msg = dbus_message_new_signal(COMM_STATUS_BROADCAST_DBUS_PATH, COMM_STATUS_BROADCAST_DBUS_INTERFACE, COMM_STATUS_BROADCAST_SIGNAL_STATUS);
	if (NULL == msg) {
		_LOGE("msg NULL");
		return;
	}

	dbus_message_iter_init_append(msg, &args);

	for (i = 0; i < 5; i++) {
		if (!dbus_message_iter_append_basic
		    (&args, DBUS_TYPE_STRING, &(values[i]))) {
			_LOGE("dbus_message_iter_append_basic failed: Out of memory");
			return;
		}
	}
	if (!dbus_connection_send(conn, msg, &serial)) {
		_LOGE("dbus_connection_send failed: Out of memory");
		return;
	}
	dbus_connection_flush(conn);
	dbus_message_unref(msg);

	__pm_send_sub_signal(req_id, pkg_type, pkgid, key, val);
}

void __change_item_info(pm_dbus_msg *item)
{
	int ret = 0;
	char *pkgid = NULL;
	pkgmgrinfo_appinfo_h handle = NULL;

	ret = pkgmgrinfo_appinfo_get_appinfo(item->pkgid, &handle);
	if (ret != PMINFO_R_OK)
		return;

	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return;
	}

	memset((item->pkgid),0,MAX_PKG_NAME_LEN);
	strncpy(item->pkgid, pkgid, sizeof(item->pkgid) - 1);

	pkgmgrinfo_appinfo_destroy_appinfo(handle);
}

static char **__generate_argv(const char *args)
{
	/* Create args vector
	 * req_id + pkgid + args
	 *
	 * vector size = # of args +
	 *(req_id + pkgid + NULL termination = 3)
	 * Last value must be NULL for execv.
	 */
	gboolean ret_parse;
	gint argcp;
	gchar **argvp;
	GError *gerr = NULL;
	ret_parse = g_shell_parse_argv(args,
					   &argcp, &argvp, &gerr);
	if (FALSE == ret_parse) {
		_LOGD("Failed to split args: %s", args);
		_LOGD("messsage: %s", gerr->message);
		exit(1);
	}

	/* Setup argument !!! */
	/*char **args_vector =
	   calloc(argcp + 4, sizeof(char *)); */
	char **args_vector = calloc(argcp + 1, sizeof(char *));
	if (args_vector == NULL)
	{
		_LOGE("Out of memory");
		exit(1);
	}
	/*args_vector[0] = strdup(backend_cmd);
	   args_vector[1] = strdup(item->req_id);
	   args_vector[2] = strdup(item->pkgid); */
	int arg_idx;
	for (arg_idx = 0; arg_idx < argcp; arg_idx++) {
		/* args_vector[arg_idx+3] = argvp[arg_idx]; */
		args_vector[arg_idx] = argvp[arg_idx];
	}

	/* dbg */
	/*for(arg_idx = 0; arg_idx < argcp+3; arg_idx++) { */
	for (arg_idx = 0; arg_idx < argcp + 1; arg_idx++) {
		_LOGD(">>>>>> args_vector[%d]=%s", arg_idx, args_vector[arg_idx]);
	}

	return args_vector;
}

static void __exec_with_arg_vector(const char* cmd, char** argv)
{
	char *backend_cmd = strdup(cmd);
	if (NULL == backend_cmd)
	{
		perror("Out of memory");
		exit(1);
	}

	_LOGD("Try to exec [%s]", backend_cmd);
	fprintf(stdout, "Try to exec [%s]\n", backend_cmd);

	/* Execute backend !!! */
	int ret = execv(backend_cmd, argv);

	/* Code below: exec failure. Should not be happened! */
	_LOGD(">>>>>> OOPS 2!!!");

	/* g_strfreev(args_vector); *//* FIXME: causes error */

	if (ret == -1) {
		perror("fail to exec");
		exit(1);
	}
	if (NULL != backend_cmd)
		free(backend_cmd);
}

static int __set_activation_info(char *pkgid, int is_active, char *label)
{
	char activation_info_file[MAX_PKG_NAME_LEN] = { 0, };
	snprintf(activation_info_file, MAX_PKG_NAME_LEN, "%s/%s", PKG_DATA_PATH, pkgid);

	if (is_active) {
		int ret = 0;
		const char* app_info_label = "_";

		if(lsetxattr(activation_info_file, "security.SMACK64", app_info_label, strlen(app_info_label), 0)) {
			_LOGE("error(%d) in setting smack label",errno);
			return PMINFO_R_ERROR;
		}
		ret = chmod(activation_info_file, 0755);
		if(ret < 0) {
			_LOGE("chmod[%s] fail",activation_info_file);
			return PMINFO_R_ERROR;
		}
		ret = chown(activation_info_file, 5000, 5000);
		if(ret < 0) {
			_LOGE("chmod[%s] fail",activation_info_file);
			return PMINFO_R_ERROR;
		}
	} else {
		(void)remove(activation_info_file);
	}
	return PMINFO_R_OK;
}

gboolean queue_job(void *data)
{
	/* _LOGD("queue_job start"); */
	pm_dbus_msg *item;
	backend_info *ptr = NULL;
	ptr = begin;
	int x = 0;
	pkgmgrinfo_pkginfo_h handle;

	/* Pop a job from queue */
pop:
	if (!__is_backend_busy(pos % num_of_backends)) {
		item = _pm_queue_pop(pos % num_of_backends);
		pos = (pos + 1) % num_of_backends;
	}
	else {
		pos = (pos + 1) % num_of_backends;
		goto pop;
	}

	int ret = 0;
	char *backend_cmd = NULL;

	/* queue is empty and backend process is not running */
	if ( (item == NULL) || (item->req_type == -1) ) {
		if(item)
			free(item);
		goto pop;
	}
	__set_backend_busy((pos + num_of_backends - 1) % num_of_backends);
	__set_recovery_mode(item->pkgid, item->pkg_type);

	/* fork */
	_save_queue_status(item, "processing");
	_LOGD("saved queue status. Now try fork()");
	/*save pkg type and pkg name for future*/
	x = (pos + num_of_backends - 1) % num_of_backends;
	strncpy((ptr + x)->pkgtype, item->pkg_type, MAX_PKG_TYPE_LEN-1);
	strncpy((ptr + x)->pkgid, item->pkgid, MAX_PKG_NAME_LEN-1);
	strncpy((ptr + x)->args, item->args, MAX_PKG_ARGS_LEN-1);
	(ptr + x)->pid = fork();
	_LOGD("child forked [%d] for request type [%d]", (ptr + x)->pid, item->req_type);

	switch ((ptr + x)->pid) {
	case 0:	/* child */
		switch (item->req_type) {
		case COMM_REQ_TO_INSTALLER:
			_LOGD("before run _get_backend_cmd()");
			backend_cmd = _get_backend_cmd(item->pkg_type);
			if (NULL == backend_cmd)
				break;

			_LOGD("Try to exec [%s][%s]", item->pkg_type, backend_cmd);
			fprintf(stdout, "Try to exec [%s][%s]\n", item->pkg_type, backend_cmd);

			char **args_vector = __generate_argv(item->args);
			args_vector[0] = backend_cmd;

			/* Execute backend !!! */
			__exec_with_arg_vector(backend_cmd, args_vector);
			free(backend_cmd);
			break;
		case COMM_REQ_ACTIVATE_PKG:
			_LOGE("ACTIVATE_PKG start [pkgid = %s]",item->pkgid);

			__pm_send_signal(PKGMGR_INSTALLER_INSTALL_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_START_KEY_STR, PKGMGR_INSTALLER_INSTALL_EVENT_STR);

			ret = pkgmgr_parser_enable_pkg(item->pkgid, NULL);
			if (ret < 0) {
				__pm_send_signal(PKGMGR_INSTALLER_INSTALL_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR);
				_LOGE("COMM_REQ_TO_ACTIVATOR failed\n");
				exit(1);
			}
			__pm_send_signal(PKGMGR_INSTALLER_INSTALL_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR);

			_LOGE("ACTIVATE_PKG end [pkgid = %s, ret = %d]",item->pkgid, ret);
			break;
		case COMM_REQ_DEACTIVATE_PKG:
			_LOGE("DEACTIVATE_PKG start [pkgid = %s]",item->pkgid);

			__pm_send_signal(PKGMGR_INSTALLER_UNINSTALL_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_START_KEY_STR, PKGMGR_INSTALLER_UNINSTALL_EVENT_STR);

			/*listener need 100ms sleep to get pkginfo */
			usleep(100 * 1000);
			ret = pkgmgr_parser_disable_pkg(item->pkgid, NULL);
			if (ret < 0) {
				__pm_send_signal(PKGMGR_INSTALLER_UNINSTALL_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR);
				_LOGE("COMM_REQ_DEACTIVATE_PKG failed\n");
				exit(1);
			}
			__pm_send_signal(PKGMGR_INSTALLER_UNINSTALL_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR);

			_LOGE("DEACTIVATE_PKG end [pkgid = %s, ret = %d]",item->pkgid, ret);
			break;
		case COMM_REQ_ACTIVATE_APP:
			_LOGE("ACTIVATE_APP [appid = %s]",item->pkgid);

			ret = __set_activation_info(item->pkgid, 1, NULL);

			__change_item_info(item);

			__pm_send_signal(PKGMGR_INSTALLER_UPGRADE_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_START_KEY_STR, PKGMGR_INSTALLER_UPGRADE_EVENT_STR);
			if (ret != PMINFO_R_OK) {
				__pm_send_signal(PKGMGR_INSTALLER_UPGRADE_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR);
				_LOGE("COMM_REQ_ACTIVATE_APP failed\n");
				exit(1);
			}
			__pm_send_signal(PKGMGR_INSTALLER_UPGRADE_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR);

			_LOGE("ACTIVATE_APP end [pkgid = %s, ret = %d]",item->pkgid, ret);
			break;
		case COMM_REQ_DEACTIVATE_APP:
			_LOGE("DEACTIVATE_APP [appid = %s]",item->pkgid);

			ret = __set_activation_info(item->pkgid, 0, NULL);

			__change_item_info(item);

			__pm_send_signal(PKGMGR_INSTALLER_UPGRADE_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_START_KEY_STR, PKGMGR_INSTALLER_UPGRADE_EVENT_STR);
			if (ret != PMINFO_R_OK) {
				__pm_send_signal(PKGMGR_INSTALLER_UPGRADE_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR);
				_LOGE("COMM_REQ_ACTIVATE_APP failed\n");
				exit(1);
			}
			__pm_send_signal(PKGMGR_INSTALLER_UPGRADE_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR);

			_LOGE("DEACTIVATE_APP end [pkgid = %s, ret = %d]",item->pkgid, ret);
			break;
		case COMM_REQ_ACTIVATE_APP_WITH_LABEL:
			_LOGE("ACTIVATE_APP_WITH_LABEL [appid = %s, label = %s]",item->pkgid, item->args);

			ret = __set_activation_info(item->pkgid, 1, item->args);

			__change_item_info(item);

			__pm_send_signal(PKGMGR_INSTALLER_UPGRADE_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_START_KEY_STR, PKGMGR_INSTALLER_UPGRADE_EVENT_STR);
			if (ret != PMINFO_R_OK) {
				__pm_send_signal(PKGMGR_INSTALLER_UPGRADE_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR);
				_LOGE("COMM_REQ_TO_ACTIVATOR failed\n");
				exit(1);
			}
			__pm_send_signal(PKGMGR_INSTALLER_UPGRADE_EVENT_STR, item->pkg_type, item->pkgid, PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR);

			_LOGE("ACTIVATE_APP_WITH_LABEL end [pkgid = %s, ret = %d]",item->pkgid, ret);
			break;
		case COMM_REQ_TO_MOVER:
		case COMM_REQ_TO_CLEARER:
			_LOGD("before run _get_backend_cmd()");
			backend_cmd = _get_backend_cmd(item->pkg_type);
			if (NULL == backend_cmd)
				break;

			_LOGD("Try to exec [%s][%s]", item->pkg_type, backend_cmd);
			fprintf(stdout, "Try to exec [%s][%s]\n", item->pkg_type, backend_cmd);

			char **args_vectors = __generate_argv(item->args);
			args_vectors[0] = backend_cmd;

			/* Execute backend !!! */
			__exec_with_arg_vector(backend_cmd, args_vectors);
			free(backend_cmd);
			break;
		case COMM_REQ_GET_JUNK_INFO:
			__exec_with_arg_vector("usr/bin/pkg_getjunkinfo", __generate_argv(item->args));
			break;
		case COMM_REQ_GET_SIZE:
			__exec_with_arg_vector("usr/bin/pkg_getsize", __generate_argv(item->args));
			break;

		case COMM_REQ_KILL_APP:
		case COMM_REQ_CHECK_APP:
			ret = pkgmgrinfo_pkginfo_get_pkginfo(item->pkgid, &handle);
			if (ret < 0) {
				_LOGD("Failed to get handle\n");
				exit(1);
			}
			if (item->req_type == COMM_REQ_KILL_APP) {
				ret = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __pkgcmd_app_cb, "kill");
				if (ret < 0) {
					_LOGD("pkgmgrinfo_appinfo_get_list() failed\n");
					pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
					exit(1);
				}
			} else if (item->req_type == COMM_REQ_CHECK_APP) {
				ret = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __pkgcmd_app_cb, "check");
				if (ret < 0) {
					_LOGD("pkgmgrinfo_appinfo_get_list() failed\n");
					pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
					exit(1);
				}
			}
			pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
			break;

		case COMM_REQ_CLEAR_CACHE_DIR:
			__exec_with_arg_vector("/usr/bin/pkg_clearcache", __generate_argv(item->pkgid));
			break;

		case COMM_REQ_MAKE_EXTERNAL_DIR:
			__exec_with_arg_vector("/usr/bin/pkg_mkext", NULL);
			break;
		}
		/* exit child */
		_save_queue_status(item, "done");
		exit(0);
		break;

	case -1:	/* error */
		fprintf(stderr, "Fail to execute fork()\n");
		exit(1);
		break;

	default:	/* parent */
		_LOGD("parent exit\n");
		_save_queue_status(item, "done");
		break;
	}

	free(item);

	return FALSE;
}

void _app_str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!IS_WHITESPACE(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

char *_get_backend_cmd(char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	char *command = NULL;
	int size = 0;
	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL) {
		return NULL;
	}

	char *path = NULL;
	while (fgets(buffer, 1024, fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		_app_str_trim(buffer);

		if ((path = strstr(buffer, PKG_BACKEND)) != NULL) {
//			_LOGD("buffer [%s]", buffer);
			path = path + strlen(PKG_BACKEND);
//			_LOGD("path [%s]", path);

			command = (char *)malloc(sizeof(char) * strlen(path) + strlen(type) + 1);
			if (command == NULL) {
				fclose(fp);
				_LOGE("command is null for [path=%s, type=%s]", path, type);
				return NULL;
			}

			size = strlen(path) + strlen(type) + 1;
			snprintf(command, size, "%s%s", path, type);
			command[strlen(path) + strlen(type)] = '\0';
//			_LOGD("command [%s]", command);

			if (fp != NULL)
				fclose(fp);

			return command;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	return NULL;		/* cannot find proper command */
}

int main(int argc, char *argv[])
{
	FILE *fp_status = NULL;
	char buf[32] = { 0, };
	pid_t pid;
	char *backend_cmd = NULL;
	char *backend_name = NULL;
	backend_info *ptr = NULL;
	int r;

	_LOGD("server start");

	if (argv[1]) {
		if (strcmp(argv[1], "init") == 0) {
			/* if current status is "processing",
			   execute related backend with '-r' option */
			if (!(fp_status = fopen(STATUS_FILE, "r")))
				return 0;	/*if file is not exist, terminated. */

			fgets(buf, 32, fp_status);
			/* if processing <-- unintended termination */
			if (strcmp(buf, "processing") == 0) {
				pid = fork();

				if (pid == 0) {	/* child */
					fgets(buf, 32, fp_status);
					backend_cmd = _get_backend_cmd(buf);
					if (!backend_cmd) {	/* if NULL, */
						_LOGD("fail to get backend command");
						goto err;
					}
					backend_name =
					    strrchr(backend_cmd, '/');

					execl(backend_cmd, backend_name, "-r",
					      NULL);
					if (backend_cmd)
						free(backend_cmd);
					fprintf(fp_status, " ");
 err:
					fclose(fp_status);
					exit(13);
				} else if (pid < 0) {	/* error */
					_LOGD("fork fail");
					fclose(fp_status);
					return 0;
				} else {	/* parent */

					_LOGD("parent end\n");
					fprintf(fp_status, " ");
					fclose(fp_status);
					return 0;
				}
			}
		}
	}

	r = _pm_queue_init();
	if (r) {
		_LOGE("Queue Initialization Failed\n");
		return -1;
	}

	/*Allocate memory for holding pid, pkgtype and pkgid*/
	ptr = (backend_info*)calloc(num_of_backends, sizeof(backend_info));
	if (ptr == NULL) {
		_LOGD("Malloc Failed\n");
		return -1;
	}
	memset(ptr, '\0', num_of_backends * sizeof(backend_info));
	begin = ptr;

	g_type_init();
	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop){
		_LOGD("g_main_loop_new failed\n");
		return -1;
	}

	_LOGD("Main loop is created.");

	PkgMgrObject *pkg_mgr;
	pkg_mgr = g_object_new(PKG_MGR_TYPE_OBJECT, NULL);
	pkg_mgr_set_request_callback(pkg_mgr, req_cb, NULL);
	_LOGD("pkg_mgr object is created, and request callback is registered.");

	pkg_mgr_set_callback_to_create_directory(pkg_mgr, create_external_dir_cb);

  	g_main_loop_run(mainloop);

	_LOGD("Quit main loop.");
	_pm_queue_final();
	/*Free backend info */
	if (begin) {
		free(begin);
		begin = NULL;
	}

	_LOGD("package manager server terminated.");

	return 0;
}
