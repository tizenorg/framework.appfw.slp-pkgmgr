/*
 * slp-pkgmgr
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <glib-object.h>
#include <glib.h>
#include <sys/types.h>
#include <db-util.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include "comm_config.h"

#include <pkgmgr-info.h>
#include "pkg.h"
#include "package-manager.h"
#include "package-manager-types.h"
#include "package-manager-debug.h"

static int __xsystem(const char *argv[]);
static void __do_print_usage();
static void __do_print_usage_api_test();
static int __do_list(pkg_tool_args *pkg_args);
static int __do_install(pkg_tool_args *pkg_args);
static int __do_uninstall(pkg_tool_args *pkg_args);
static int __do_enable(pkg_tool_args *pkg_args);
static int __do_disable(pkg_tool_args *pkg_args);
static int __do_move_to_internal(pkg_tool_args *pkg_args);
static int __do_move_to_external(pkg_tool_args *pkg_args);
static int __do_launch(pkg_tool_args *pkg_args);
static int __do_info(pkg_tool_args *pkg_args);
static int __pkgmgr_list_cb(pkgmgrinfo_pkginfo_h handle, void *user_data);
static int __pkgmgr_app_list_cb(pkgmgrinfo_appinfo_h handle, void *user_data);
static int __return_cb(int req_id, const char *pkg_type, const char *pkgid, const char *key, const char *val, const void *pmsg, void *priv_data);
static int __do_info_by_pkgid(const char* pkgid);
static int __do_info_by_appid(const char* appid);
static int __do_info_app_func(const pkgmgrinfo_appinfo_h handle, void *user_data);
static int __do_api_test(pkg_tool_args *pkg_args);

static GMainLoop *main_loop = NULL;


#define ZIP_PKGMGR_DB				PKGMGR_FOTA_PATH".pkgmgr_parser.db"
#define PKGID_LIST_FILE				PKGMGR_FOTA_PATH"pkgid_list.txt"
#define APPID_LIST_FILE				PKGMGR_FOTA_PATH"appid_list.txt"

#define TEST_PKGID "com.samsung.message-lite"
#define TEST_APPID "com.samsung.message-lite"

struct option long_options[] = {
	{"list", no_argument, 0, 'l'},
	{"install", required_argument, 0, 'i'},
	{"uninstall", required_argument, 0, 'u'},
	{"enable", required_argument, 0, 'e'},
	{"disable", required_argument, 0, 'd'},
	{"move-to-internal", required_argument, 0, 0},
	{"move-to-external", required_argument, 0, 0},
	{"launch", required_argument, 0, 0},
	{"info", no_argument, 0, 'q'},
	{"pkgid", required_argument, 0, 'x'},
	{"appid", required_argument, 0, 'y'},
	{"all", no_argument, 0, 'a'},
	{"api-test", no_argument, 0, 't'},
	{0, 0, 0, 0},
};

cmdinfo cmds[] =
{
	{__do_list},
	{__do_install},
	{__do_uninstall},
	{__do_enable},
	{__do_disable},
	{__do_move_to_internal},
	{__do_move_to_external},
	{__do_launch},
	{__do_info},
	{__do_api_test},
	{NULL}
};

int main(int argc, char *argv[])
{
	int opt_idx = 0;
	int c = -1;
	long starttime;
	long endtime;
	struct timeval tv;
	pkg_tool_args pkg_args = {0};

	uid_t uid = getuid();
	if ((uid_t) 0 != uid) {
		printf("You are not an authorized user!\n");
		exit(0);
	}

	if (argc == 1)
	{
		__do_print_usage();
		exit(0);
	}

	gettimeofday(&tv, NULL);
	starttime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;
	pkg_args.req = NONE_REQ;

	while (1)
	{
		c = getopt_long(argc, argv, "i:u:e:d:lat:x:y:q", long_options, &opt_idx); // 3rd param is short option.
		if (c == -1)
			break;

		switch (c)
		{
        case 0:
            printf("option %s", long_options[opt_idx].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;

		case 'l':
			pkg_args.req = LIST_REQ;
			break;

		case 'a':
			pkg_args.isListAll = true;
			break;

		case 'i':
			pkg_args.req = INSTALL_REQ;
			realpath(optarg, pkg_args.path);
			break;

		case 'u':
			pkg_args.req = UNINSTALL_REQ;
			sprintf(pkg_args.pkgid, optarg);
			break;

		case 'e':
			pkg_args.req = ENABLE_REQ;
			sprintf(pkg_args.pkgid, optarg);
			break;

		case 'd':
			pkg_args.req = DISABLE_REQ;
			sprintf(pkg_args.pkgid, optarg);
			break;

		case 'q':
			pkg_args.req = INFO_REQ;
			break;

		case 'x':
			sprintf(pkg_args.pkgid, optarg);
			printf("pkg_args.pkgid=%s\n", pkg_args.pkgid);
			break;

		case 'y':
			sprintf(pkg_args.appid, optarg);
			printf("pkg_args.appid=%s\n", pkg_args.appid);
			break;

		case 't':
			pkg_args.req = API_TEST_REQ;
			sprintf(pkg_args.pkgid, optarg);
			break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
    }

    // call each function
    if (pkg_args.req != NONE_REQ)
    {
    	printf("req=%d, path=%s, pkgid=%s, appid=%s, des_path=%s, lable=%s, result=%d, isListAll=%d\n",
    			(int)pkg_args.req, pkg_args.path, pkg_args.pkgid, pkg_args.appid, pkg_args.des_path,
    			pkg_args.label, pkg_args.result, (int)pkg_args.isListAll);
    	cmds[pkg_args.req].func(&pkg_args);
    }
    else
    {
    	printf("no operation\n");
    }

	gettimeofday(&tv, NULL);
	endtime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;
	printf("spend time is [%d]ms\n", (int)(endtime - starttime));

	exit(EXIT_SUCCESS);
}

int __xsystem(const char *argv[])
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

void __do_print_usage()
{
	printf("Package manager tool version: %s\n", PKG_TOOL_VERSION);
	printf("Copyright (C) 2013-2014 - Application framework team\n");
	printf("\n");
	printf("Usage:\n");
	printf("pkg [-l|--list]\n");
	printf("    [-i|--install <path>]\n");
	printf("    [-u|--uninstall <pkgid>]\n");
	printf("    [-e|--enable <pkgid>]\n");
	printf("    [-d|--disable <pkgid>]\n");
	printf("    [-t|--clear-cache <pkgid> | __ALL__]\n");
	printf("    [--move-to-internal <pkgid>]\n");
	printf("    [--move-to-external <pkgid>]\n");
	printf("    [--launch <appid>]\n");
	printf("\n");
	printf("Example:\n");
	printf("pkg -l\n");
	printf("pkg -i /opt/usr/media/com.samsung.hello_0.1.2_armv7l.tpk\n");
	printf("pkg -u com.samsung.hello\n");
	printf("pkg -e com.samsung.hello\n");
	printf("pkg -d com.samsung.hello\n");
	printf("pkg -t com.samsung.hello\n");
	printf("pkg -t __ALL__\n");
	printf("pkg --move-to-internal com.samsung.hello\n");
	printf("pkg --move-to-external com.samsung.hello\n");
	printf("\n");
}

void __do_print_usage_api_test()
{
	printf("Package manager tool version: %s\n", PKG_TOOL_VERSION);
	printf("Copyright (C) 2013-2014 - Application framework team\n");
	printf("\n");
	printf("Usage:\n");
	printf("pkg -t [option]\n");
	printf("\n");
	printf("Option\n");
	printf("1  --> check fota's result\n");
	printf("2  --> send signal to make external data directory\n");
	printf("3  --> clear cache directory\n");
	printf("4  --> API performance test\n");
	printf("\n");
}

int __do_list(pkg_tool_args *pkg_args)
{
	int ret = -1;

	printf("%-40s%-30s%-10s%-5s%-10s\n", "PKGID", "NAME", "VER", "EXT", "TYPE");
	ret = pkgmgrinfo_pkginfo_get_list(__pkgmgr_list_cb, pkg_args);
	trym_if(ret != 0, "__do_list:  pkgmgrinfo_pkginfo_get_list() is failed, ret=%d\n", ret);

catch:
	return 0;
}

int __pkgmgr_list_cb(pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid = NULL;
	char *pkg_type = NULL;
	char *pkg_version = NULL;
	char *pkg_label = NULL;
	bool is_core_pkg = false;
	bool is_osp_pkg = false;
	bool is_web_pkg = false;
	char buf[1024] = {0};
	pkg_tool_args *pkg_args = (pkg_tool_args *)user_data;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret == -1) {
		printf("Failed to get pkgmgr_pkginfo_get_pkgid\n");
		return ret;
	}
	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkg_type);
	if (ret == -1) {
		printf("Failed to get pkgmgr_pkginfo_get_type\n");
		return ret;
	}
	ret = pkgmgrinfo_pkginfo_get_version(handle, &pkg_version);
	if (ret == -1) {
		printf("Failed to get pkgmgr_pkginfo_get_version\n");
		return ret;
	}
	ret = pkgmgrinfo_pkginfo_get_label(handle, &pkg_label);
	if (ret == -1) {
		printf("Failed to get pkgmgr_pkginfo_get_label\n");
		return ret;
	}

	if (pkg_type && strcmp(pkg_type, "wgt") == 0)
	{
		snprintf(buf, 1023, "/opt/usr/apps/%s/tizen-manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_core_pkg = true;
		}

		snprintf(buf, 1023, "/usr/apps/%s/tizen-manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_core_pkg = true;
		}

		snprintf(buf, 1023, "/opt/usr/apps/%s/info/manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_osp_pkg = true;
		}

		snprintf(buf, 1023, "/usr/apps/%s/info/manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_osp_pkg = true;
		}

		is_web_pkg = true;
	}
	else if(pkg_type && strcmp(pkg_type, "rpm") == 0)
	{
		snprintf(buf, 1023, "/opt/usr/apps/%s/tizen-manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_core_pkg = true;
		}

		snprintf(buf, 1023, "/usr/apps/%s/tizen-manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_core_pkg = true;
		}
	}
	else if(pkg_type && strcmp(pkg_type, "tpk") == 0)
	{
		snprintf(buf, 1023, "/opt/usr/apps/%s/tizen-manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_core_pkg = true;
		}

		snprintf(buf, 1023, "/usr/apps/%s/tizen-manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_core_pkg = true;
		}

		snprintf(buf, 1023, "/opt/usr/apps/%s/info/manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_osp_pkg = true;
		}

		snprintf(buf, 1023, "/usr/apps/%s/info/manifest.xml", pkgid);
		if (access(buf, F_OK) == 0)
		{
			is_osp_pkg = true;
		}
	}

	printf("%-40.40s%-30.29s%-10.10s", pkgid, pkg_label, pkg_version);
	printf("%-5.3s", pkg_type);
	if (is_web_pkg == true)
	{
		printf("%-10s", "web");
	}
	if (is_core_pkg == true)
	{
		printf("%-10s", "core");
	}
	if (is_osp_pkg == true)
	{
		printf("%-10s", "osp");
	}
	printf("\n");

	if (pkg_args->isListAll == true)
	{
		ret = pkgmgrinfo_appinfo_get_list(handle, PM_ALL_APP, __pkgmgr_app_list_cb, user_data);
		if (ret == -1) {
			printf("Failed to get pkgmgr_pkginfo_get_type\n");
			return ret;
		}
	}

	return ret;
}

int __pkgmgr_app_list_cb(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = -1;
	char *appid = NULL;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret == -1) {
		printf("Failed to get pkgmgr_pkginfo_get_pkgid\n");
		return ret;
	}

	printf(" \\_ %s\n", appid);

	return 0;
}


int __do_install(pkg_tool_args *args)
{
	int ret = -1;
	pkgmgr_client *pc = NULL;

	g_type_init();
	main_loop = g_main_loop_new(NULL, FALSE);
	pc = pkgmgr_client_new(PC_REQUEST);
	tryvm_if(pc == NULL, ret = PKGCMD_ERR_FATAL_ERROR, "__do_install: pkgmgr client creation failed, ret=%d\n", ret);

	ret = pkgmgr_client_install(pc, NULL, NULL, args->path, NULL, 0, __return_cb, pc);
	if (ret < 0)
	{
		if (access(args->path, F_OK) != 0)
		{
			tryvm_if(ret != 0, ret = PKGCMD_ERR_PACKAGE_NOT_FOUND, "__do_install: package not found, ret=%d\n", ret);
		}
		else
		{
			tryvm_if(ret != 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_install: fatal error, ret=%d\n", ret);
		}
	}
	g_main_loop_run(main_loop);

	ret = 0;
catch:
	return ret;
}

int __return_cb(int req_id, const char *pkg_type,
		       const char *pkgid, const char *key, const char *val,
		       const void *pmsg, void *priv_data)
{
	int ret = -1;

	if (strncmp(key, "error", strlen("error")) == 0)
	{
		int ret_val;
		char delims[] = ":";
		char *extra_str = NULL;
		char *ret_result = NULL;

		ret_val = atoi(val);
		ret = ret_val;

		strtok((char*)val, delims);
		ret_result = strtok(NULL, delims);
		if (ret_result)
		{
			extra_str = strdup(ret_result);
			printf("  response:req_id=[%d]:[%s]:[%s]:[%s]:[%d]:[%s]\n", req_id, pkg_type, pkgid, key, ret_val, extra_str);
			free(extra_str);
		}
		else
		{
			printf("  response:req_id=[%d]:[%s]:[%s]:[%s]:[%d]\n", req_id, pkg_type, pkgid, key, ret_val);
		}
	}
	else
	{
		printf("  response:req_id=[%d]:[%s]:[%s]:[%s]:[%s]\n", req_id, pkg_type, pkgid, key, val);
	}

	if (strncmp(key, "end", strlen("end")) == 0)
	{
		if ((strncmp(val, "fail", strlen("fail")) == 0) && ret == 0)
		{
			ret = PKGCMD_ERR_FATAL_ERROR;
		}
		g_main_loop_quit(main_loop);
	}

	return ret;
}

int __do_uninstall(pkg_tool_args *args)
{
	int ret = -1;
	pkgmgr_client *pc = NULL;

	g_type_init();
	main_loop = g_main_loop_new(NULL, FALSE);

	pc = pkgmgr_client_new(PC_REQUEST);
	tryvm_if(pc == NULL, ret = PKGCMD_ERR_FATAL_ERROR, "__do_uninstall: pkgmgr client creation failed, ret=%d\n", ret);

	ret = pkgmgr_client_uninstall(pc, NULL/*data.pkg_type*/, args->pkgid, 0/*mode*/, __return_cb, NULL);
	tryvm_if(ret < 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_uninstall: fatal error, ret=%d\n", ret);

	g_main_loop_run(main_loop);

	ret = 0;
catch:
	return ret;
}

int __do_enable(pkg_tool_args *args)
{
	int ret = -1;
	pkgmgr_client *pc = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(args->pkgid, &handle);
	tryvm_if(ret == 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_enable: already enabled, pkgid=%s\n", args->pkgid);

	pc = pkgmgr_client_new(PC_REQUEST);
	tryvm_if(pc == NULL, ret = PKGCMD_ERR_FATAL_ERROR, "__do_enable: pkgmgr client creation failed, ret=%d\n", ret);

	ret = pkgmgr_client_activate(pc, NULL, args->pkgid);
	tryvm_if(ret < 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_enable: fatal error, ret=%d\n", ret);

	sleep(1);

	ret = pkgmgrinfo_pkginfo_get_pkginfo(args->pkgid, &handle);
	tryvm_if(ret < 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_enable: fail to enable, pkgid=%s\n", args->pkgid);

	printf("success\n");
	__pkgmgr_list_cb(handle, args);

	ret = 0;
catch:
	return ret;
}

int __do_disable(pkg_tool_args *args)
{
	int ret = -1;
	pkgmgr_client *pc = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(args->pkgid, &handle);
	tryvm_if(ret < 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_disable: not installed, pkgid=%s\n", args->pkgid);

	pc = pkgmgr_client_new(PC_REQUEST);
	tryvm_if(pc == NULL, ret = PKGCMD_ERR_FATAL_ERROR, "__do_disable: pkgmgr client creation failed, ret=%d\n", ret);

	ret = pkgmgr_client_deactivate(pc, NULL, args->pkgid);
	tryvm_if(ret < 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_disable: fatal error, ret=%d\n", ret);

	sleep(1);

	ret = pkgmgrinfo_pkginfo_get_pkginfo(args->pkgid, &handle);
	tryvm_if(ret == 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_disable: fail to disable, pkgid=%s\n", args->pkgid);
	printf("success\n");

	ret = 0;
catch:
	return ret;
}

int __do_move_to_internal(pkg_tool_args *args)
{
	printf("__do_move_to_internal\n");
	return 0;
}

int __do_move_to_external(pkg_tool_args *args)
{
	printf("__do_move_to_external\n");
	return 0;
}

int __do_launch(pkg_tool_args *args)
{
	printf("__do_launch\n");
	return 0;
}

int __do_info(pkg_tool_args *args)
{
	printf("__do_info\n");

	if (args->pkgid[0])
	{
		printf("__do_info_by_pkgid\n");
		__do_info_by_pkgid(args->pkgid);
	}
	else if (args->appid[0])
	{
		printf("__do_info_by_appid\n");
		__do_info_by_appid(args->appid);
	}

	return 0;
}

int __do_info_by_pkgid(const char* pkgid)
{
	int ret = -1;
	pkgmgrinfo_pkginfo_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	tryvm_if(ret < 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_info_by_pkgid: failed to get handle, pkgid=%s\n", pkgid);

	ret = pkgmgrinfo_appinfo_get_list(handle, PM_ALL_APP, __do_info_app_func, (void*)pkgid);
	tryvm_if(ret < 0, ret = PKGCMD_ERR_FATAL_ERROR, "__do_info_by_pkgid: pkgmgrinfo_appinfo_get_list() failed, pkgid=%s\n", pkgid);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	handle = NULL;

	ret = 0;
catch:
	if (handle)
	{
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}

	return ret;
}

int __do_info_app_func(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;
	char *data = NULL;
	if (user_data) {
		data = (char *)user_data;
	}
	int ret = -1;
	char *exec = NULL;
	char *icon = NULL;
	char *label = NULL;
	pkgmgrinfo_app_component component = 0;
	char *apptype = NULL;
	bool nodisplay = 0;
	bool multiple = 0;
	bool taskmanage = 0;
	pkgmgrinfo_app_hwacceleration hwacceleration;
	pkgmgrinfo_app_screenreader screenreader;
	bool support_disable = 0;
	bool onboot = 0;
	bool autorestart = 0;
	char *package = NULL;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		printf("Failed to get appid\n");
	}
	if (appid)
		printf("Appid: %s\n", appid);

	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &package);
	if (ret < 0) {
		printf("Failed to get package\n");
	}
	if (package)
		printf("Package: %s\n", package);

	ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	if (ret < 0) {
		printf("Failed to get exec\n");
	}
	if (exec)
		printf("Exec: %s\n", exec);

	ret = pkgmgrinfo_appinfo_get_icon(handle, &icon);
	if (ret < 0) {
		printf("Failed to get icon\n");
	}
	if (icon)
		printf("Icon: %s\n", icon);

	ret = pkgmgrinfo_appinfo_get_label(handle, &label);
	if (ret < 0) {
		printf("Failed to get label\n");
	}
	if (label)
		printf("Label: %s\n", label);

	ret = pkgmgrinfo_appinfo_get_component(handle, &component);
	if (ret < 0) {
		printf("Failed to get component\n");
	}

	ret = pkgmgrinfo_appinfo_get_apptype(handle, &apptype);
	if (ret < 0) {
		printf("Failed to get apptype\n");
	}
	if (apptype)
		printf("Apptype: %s\n", apptype);

	if (component == PMINFO_UI_APP) {
		printf("component: uiapp\n");
		ret = pkgmgrinfo_appinfo_is_multiple(handle, &multiple);
		if (ret < 0) {
			printf("Failed to get multiple\n");
		} else {
			printf("Multiple: %d\n", multiple);
		}

		ret = pkgmgrinfo_appinfo_is_nodisplay(handle, &nodisplay);
		if (ret < 0) {
			printf("Failed to get nodisplay\n");
		} else {
			printf("Nodisplay: %d \n", nodisplay);
		}

		ret = pkgmgrinfo_appinfo_is_taskmanage(handle, &taskmanage);
		if (ret < 0) {
			printf("Failed to get taskmanage\n");
		} else {
			printf("Taskmanage: %d\n", taskmanage);
		}

		ret = pkgmgrinfo_appinfo_get_hwacceleration(handle, &hwacceleration);
		if (ret < 0) {
			printf("Failed to get hwacceleration\n");
		} else {
			printf("hw-acceleration: %d\n", hwacceleration);
		}

		ret = pkgmgrinfo_appinfo_get_screenreader(handle, &screenreader);
		if (ret < 0) {
			printf("Failed to get screenreader\n");
		} else {
			printf("screenreader: %d\n", screenreader);
		}

		ret = pkgmgrinfo_appinfo_is_support_disable(handle, &support_disable);
		if (ret < 0) {
			printf("Failed to get support-disable\n");
		} else {
			printf("support-disable: %d\n", support_disable);
		}
	}
	if (component == PMINFO_SVC_APP) {
		printf("component: svcapp\n");
		ret = pkgmgrinfo_appinfo_is_onboot(handle, &onboot);
		if (ret < 0) {
			printf("Failed to get onboot\n");
		} else {
			printf("Onboot: %d\n", onboot);
		}

		ret = pkgmgrinfo_appinfo_is_autorestart(handle, &autorestart);
		if (ret < 0) {
			printf("Failed to get autorestart\n");
		} else {
			printf("Autorestart: %d \n", autorestart);
		}
	}
	if (data)
		printf("user_data : %s\n\n", data);

	return 0;
}

int __do_info_by_appid(const char* appid)
{
	return 0;
}

static void __run_query(sqlite3 *database, char *query, sqlite3_stmt *stmt, FILE *fp)
{
	int col = 0;
	int cols = 0;
	int ret = 0;
	char *colname = NULL;
	char *coltxt = NULL;

	ret = sqlite3_prepare_v2(database, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		printf("[%s]sqlite3_prepare_v2 error!!\n", query);
		return;
	}

	cols = sqlite3_column_count(stmt);
	while(1)
	{
		ret = sqlite3_step(stmt);
		if(ret == SQLITE_ROW) {
			for(col = 0; col < cols; col++)
			{
				colname = (char *)sqlite3_column_name(stmt, col);
				if (strcmp(colname, "installed_time")==0) {
					continue;
				}
				coltxt = (char *)sqlite3_column_text(stmt, col);
				fprintf(fp, "%s-%s\n", colname, coltxt);
//				printf("%s-%s\n", colname, coltxt);
			}
			ret = 0;
		} else {
			break;
		}
	}

}

static void __make_pkginfo_file(char *db_file, char *file_path, char *pkgid)
{
	int ret = 0;
	char *query = NULL;
	sqlite3 *info_db = NULL;
	sqlite3_stmt *stmt = NULL;
	FILE *fp;

	fp = fopen(file_path, "w");
	if (fp == NULL) {
		printf("[%s]fopen error!!\n", PKGID_LIST_FILE);
		return;
	}

	ret = db_util_open(db_file, &info_db, 0);
	if (ret != SQLITE_OK) {
		printf("[%s]db_util_open error!!\n", db_file);
		fclose(fp);
		return;
	}

	query = sqlite3_mprintf("select * from package_info "\
			"LEFT OUTER JOIN package_privilege_info ON package_info.package=package_privilege_info.package "\
			"LEFT OUTER JOIN package_plugin_info ON package_info.package=package_plugin_info.pkgid "\
			"where package_info.package=%Q", pkgid);

	__run_query(info_db, query, stmt, fp);

	fclose(fp);
	sqlite3_free(query);
	sqlite3_finalize(stmt);
	sqlite3_close(info_db);
}


static void __make_appinfo_file(char *db_file, char *file_path, char *appid)
{
	int ret = 0;
	char *query = NULL;
	sqlite3 *info_db = NULL;
	sqlite3_stmt *stmt = NULL;
	FILE *fp;

	fp = fopen(file_path, "w");
	if (fp == NULL) {
		printf("[%s]fopen error!!\n", PKGID_LIST_FILE);
		return;
	}

	ret = db_util_open(db_file, &info_db, 0);
	if (ret != SQLITE_OK) {
		printf("[%s]db_util_open error!!\n", db_file);
		fclose(fp);
		return;
	}

	query = sqlite3_mprintf("select * from package_app_info where app_id=%Q", appid);
	__run_query(info_db, query, stmt, fp);
	sqlite3_free(query);
	sqlite3_finalize(stmt);

	query = sqlite3_mprintf("select * from package_app_app_category where app_id=%Q", appid);
	__run_query(info_db, query, stmt, fp);
	sqlite3_free(query);
	sqlite3_finalize(stmt);

	query = sqlite3_mprintf("select * from package_app_app_metadata where app_id=%Q", appid);
	__run_query(info_db, query, stmt, fp);
	sqlite3_free(query);
	sqlite3_finalize(stmt);

	query = sqlite3_mprintf("select * from package_app_app_control where app_id=%Q", appid);
	__run_query(info_db, query, stmt, fp);
	sqlite3_free(query);
	sqlite3_finalize(stmt);

	query = sqlite3_mprintf("select * from package_app_localized_info where app_id=%Q", appid);
	__run_query(info_db, query, stmt, fp);

	fclose(fp);
	sqlite3_free(query);
	sqlite3_finalize(stmt);
	sqlite3_close(info_db);
}

static void __make_pkgid_list()
{
	int ret = 0;
	char *query = NULL;
	sqlite3 *info_db = NULL;
	sqlite3_stmt *stmt = NULL;
	FILE *fp;

	fp = fopen(PKGID_LIST_FILE, "w");
	if (fp == NULL) {
		printf("[%s]fopen error!!\n", PKGID_LIST_FILE);
		return;
	}

	ret = db_util_open(PKGMGR_DB, &info_db, 0);
	if (ret != SQLITE_OK) {
		printf("[%s]db_util_open error!!\n", PKGMGR_DB);
		fclose(fp);
		return;
	}
	query = sqlite3_mprintf("select package from package_info where package_system like 'true' order by package asc");

	ret = sqlite3_prepare_v2(info_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		printf("[%s]sqlite3_prepare_v2 error!!\n", query);
		goto end;
	}

	while(1) {
		ret = sqlite3_step(stmt);
		if(ret == SQLITE_ROW) {
			fprintf(fp, "%s\n", (const char *)sqlite3_column_text(stmt, 0));
//			printf("pkgid  == 	%s\n" ,(const char *)sqlite3_column_text(stmt, 0));
		} else {
			break;
		}
	}

end:

	fclose(fp);
	sqlite3_free(query);
	sqlite3_finalize(stmt);
	sqlite3_close(info_db);
}

static void __make_appid_list()
{
	int ret = 0;
	char *query = NULL;
	sqlite3 *info_db = NULL;
	sqlite3_stmt *stmt = NULL;
	FILE *fp;

	fp = fopen(APPID_LIST_FILE, "w");
	if (fp == NULL) {
		printf("[%s]fopen error!!\n", APPID_LIST_FILE);
		return;
	}

	ret = db_util_open(PKGMGR_DB, &info_db, 0);
	if (ret != SQLITE_OK) {
		printf("[%s]db_util_open error!!\n", PKGMGR_DB);
		fclose(fp);
		return;
	}
	query = sqlite3_mprintf("select app_id from package_app_info where app_preload like 'true' order by app_id asc");

	ret = sqlite3_prepare_v2(info_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		printf("[%s]sqlite3_prepare_v2 error!!\n", query);
		goto end;
	}

	while(1) {
		ret = sqlite3_step(stmt);
		if(ret == SQLITE_ROW) {
			fprintf(fp, "%s\n", (const char *)sqlite3_column_text(stmt, 0));
//			printf("pkgid  == 	%s\n" ,(const char *)sqlite3_column_text(stmt, 0));
		} else {
			break;
		}
	}

end:

	fclose(fp);
	sqlite3_free(query);
	sqlite3_finalize(stmt);
	sqlite3_close(info_db);
}

static int __compare_files(char *ori_file, char *zip_file)
{
	int ret = 0;
	FILE *ori_fp = NULL;
	FILE *zip_fp = NULL;
	char ori_buf[BUF_SIZE] = {0};
	char zip_buf[BUF_SIZE] = {0};

	ori_fp = fopen(ori_file, "r");
	if (ori_fp == NULL) {
		printf("Fail get : %s\n", PKGID_LIST_FILE);
		return -1;
	}

	zip_fp = fopen(zip_file, "r");
	if (zip_fp == NULL) {
		printf("Fail get : %s\n", PKGID_LIST_FILE);
		fclose(ori_fp);
		return -1;
	}

	while ((fgets(ori_buf, BUF_SIZE, ori_fp) != NULL) && (fgets(zip_buf, BUF_SIZE, zip_fp) != NULL)) {
		ori_buf[strlen(ori_buf) - 1] = '\0';
		zip_buf[strlen(zip_buf) - 1] = '\0';

		if(strcasecmp(ori_buf, zip_buf) != 0) {
			printf("-----------------------------------------------------------------------------\n");
			printf("different value ==  %s , %s\n", ori_buf, zip_buf);
			ret = -1;
			break;
		}

		memset(zip_buf, 0x00, BUF_SIZE);
		memset(ori_buf, 0x00, BUF_SIZE);
	}
	fclose(zip_fp);
	fclose(ori_fp);

	return ret;
}

static int __check_time(long privous_time)
{
	long current_time;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	current_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	return (int)(current_time - privous_time);
}

static void __check_fota_prepare()
{
	int ret = 0;

	__make_pkgid_list();
	__make_appid_list();

	const char *unzip_argv[] = { "/usr/bin/unzip", "-jo", FACTORYRESET_BACKUP_FILE, "opt/dbspace/.pkgmgr_parser.db", "-d", PKGMGR_FOTA_PATH, NULL };
	ret = __xsystem(unzip_argv);
	if (ret < 0) {
		printf("unzip pkgmgr db from factoryrest data fail.\n");
	}
}

static void __check_fota_process_pkg()
{
	int ret = 0;
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};
	char ori_file[BUF_SIZE] = {0};
	char zip_file[BUF_SIZE] = {0};

	fp = fopen(PKGID_LIST_FILE, "r");
	if (fp == NULL) {
		printf("Fail get : %s\n", PKGID_LIST_FILE);
		return;
	}
	printf("=============================================================================\n");
	printf("%-70s%-60s\n", "PKGID", "RESULT");
	printf("=============================================================================\n");

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		buf[strlen(buf) - 1] = '\0';

		snprintf(ori_file, sizeof(ori_file), "%s%s-ori", PKGMGR_FOTA_PATH, buf);
		__make_pkginfo_file(PKGMGR_DB, ori_file, buf);

		snprintf(zip_file, sizeof(zip_file), "%s%s-zip", PKGMGR_FOTA_PATH, buf);
		__make_pkginfo_file(ZIP_PKGMGR_DB, zip_file, buf);

		ret = __compare_files(ori_file, zip_file);
		if (ret < 0) {
			printf("%-70s%-60s\n", buf, "different");
			printf("-----------------------------------------------------------------------------\n");
		} else {
			printf("%-70s%-60s\n", buf, "same");

			const char *delete_argv[] = { "/bin/rm", ori_file, zip_file, NULL };
			ret = __xsystem(delete_argv);
			if (ret < 0) {
				printf("delete fail.\n");
			}
		}

		memset(ori_file, 0x00, BUF_SIZE);
		memset(zip_file, 0x00, BUF_SIZE);
	}

	if (fp != NULL)
		fclose(fp);
}

static void __check_fota_process_app()
{
	int ret = 0;
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};
	char ori_file[BUF_SIZE] = {0};
	char zip_file[BUF_SIZE] = {0};

	fp = fopen(APPID_LIST_FILE, "r");
	if (fp == NULL) {
		printf("Fail get : %s\n", APPID_LIST_FILE);
		return;
	}
	printf("=============================================================================\n");
	printf("%-70s%-60s\n", "APPID", "RESULT");
	printf("=============================================================================\n");

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		buf[strlen(buf) - 1] = '\0';

		snprintf(ori_file, sizeof(ori_file), "%s%s-appori", PKGMGR_FOTA_PATH, buf);
		__make_appinfo_file(PKGMGR_DB, ori_file, buf);

		snprintf(zip_file, sizeof(zip_file), "%s%s-appzip", PKGMGR_FOTA_PATH, buf);
		__make_appinfo_file(ZIP_PKGMGR_DB, zip_file, buf);

		ret = __compare_files(ori_file, zip_file);
		if (ret < 0) {
			printf("%-70s%-60s\n", buf, "different");
			printf("-----------------------------------------------------------------------------\n");
		} else {
			printf("%-70s%-60s\n", buf, "same");

			const char *delete_argv[] = { "/bin/rm", ori_file, zip_file, NULL };
			ret = __xsystem(delete_argv);
			if (ret < 0) {
				printf("delete fail.\n");
			}
		}

		memset(ori_file, 0x00, BUF_SIZE);
		memset(zip_file, 0x00, BUF_SIZE);
	}

	if (fp != NULL)
		fclose(fp);
}

static void __check_fota_post()
{
	const char *delete_argv[] = { "/bin/rm", ZIP_PKGMGR_DB, PKGID_LIST_FILE, APPID_LIST_FILE, NULL };
	if (__xsystem(delete_argv) < 0) {
		printf("delete fail.\n");
	}

	printf("==========================================================================\n");
	printf("\t\t\t\t finish\n");
	printf("==========================================================================\n");
}

static void __check_fota_result()
{
	__check_fota_prepare();
	__check_fota_process_pkg();
	__check_fota_process_app();
	__check_fota_post();
}

static void __clear_cache_dir()
{
	int ret = 0;
	printf("========================================================\n");
	printf("\t\t clear cache directory\n");

	ret = pkgmgr_client_clear_all_cache_dir();
	if (ret < 0)
		printf("pkgmgr_client_clear_all_cache_dir fail\n");
	printf("========================================================\n");
}

static void __send_event_make_exdir()
{
	DBusConnection *bus = NULL;
	DBusMessage *message = NULL;

	printf("========================================================\n");

	printf("\t\t send event to pkgmgr server\n");
	printf("\t\t Method = %s\n", COMM_PKG_MGR_METHOD_CREATE_EXTERNAL_DIRECTORY);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	retm_if(bus == NULL, "dbus_bus_get() failed.\n");

	message = dbus_message_new_method_call(COMM_PKG_MGR_DBUS_SERVICE,
            COMM_PKG_MGR_DBUS_PATH, COMM_PKG_MGR_DBUS_INTERFACE,
            COMM_PKG_MGR_METHOD_CREATE_EXTERNAL_DIRECTORY);
	retm_if(message == NULL, "dbus_message_new_method_call() failed.\n");

	if(dbus_connection_send_with_reply_and_block(bus, message, -1, NULL) == NULL){
		printf("DBUS msg send error!!\n");
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	printf("========================================================\n");
}

static int __pkg_list_cb(pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = 0;
	char *pkgid = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret != PMINFO_R_OK) {
		return -1;
	}

	if (pkgid != NULL) {
		if (strcmp(pkgid, TEST_PKGID) == 0) {
			printf("success - find matched pkgid!!\n");
		} else {
//			_LOG("test log : %s", pkgid);
		}
	}
	return 0;
}

static int __app_list_cb(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int ret = 0;
	char *appid = NULL;
	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret != PMINFO_R_OK) {
		return -1;
	}

	if (appid != NULL) {
		if (strcmp(appid, TEST_APPID) == 0) {
			printf("success - find matched appid!!\n");
		} else {
//			_LOG("test log : %s", appid);
		}
	}
	return 0;
}

static int __tc_01()
{
	int ret = 0;
	char *type = NULL;
	char *version = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;

	long check_time = 0;;
	int spend_time = 0;
	struct timeval tv;


	printf("--------------------------------------------------------\n");
	printf("TC 01 : pkgmgrinfo_pkginfo_get_pkginfo\n");
	printf("### Access DB table list ###\n");
	printf("package_info\n");
	printf("package_privilege_info\n");
	printf("package_localized_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(TEST_PKGID, &handle);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_get_pkginfo : fail\n");
		goto end;
	}

	printf("pkgid : %s\n", TEST_PKGID);

	ret = pkgmgrinfo_pkginfo_get_type(handle, &type);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_get_type : fail\n");
		goto end;
	}
	printf("type : %s\n", type);

	ret = pkgmgrinfo_pkginfo_get_version(handle, &version);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_get_version : fail\n");
		goto end;
	}
	printf("version : %s\n", version);

end:
	if(handle)
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	if (ret == PMINFO_R_OK) {
		printf("TC 01 result :: OK\n");
	} else {
		printf("TC 01 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_02()
{
	int ret = 0;

	long check_time = 0;
	int spend_time = 0;
	struct timeval tv;

	printf("--------------------------------------------------------\n");
	printf("TC 02 : pkgmgrinfo_pkginfo_get_list\n");
	printf("### Access DB table list ###\n");
	printf("package_info\n");
	printf("package_privilege_info\n");
	printf("package_localized_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_pkginfo_get_list(__pkg_list_cb, NULL);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_get_list : fail\n");
		goto end;
	}

end:

	if (ret == PMINFO_R_OK) {
		printf("TC 02 result :: OK\n");
	} else {
		printf("TC 02 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_03()
{
	int ret = 0;
	long check_time = 0;
	int spend_time = 0;
	struct timeval tv;

	pkgmgrinfo_pkginfo_filter_h handle ;

	printf("--------------------------------------------------------\n");
	printf("TC 03 : pkgmgrinfo_pkginfo_filter_foreach_pkginfo\n");
	printf("### Access DB table list ###\n");
	printf("package_info\n");
	printf("package_localized_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_filter_create : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_pkginfo_filter_add_string(handle, PMINFO_PKGINFO_PROP_PACKAGE_TYPE, "rpm\n");
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_filter_add_string : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __pkg_list_cb, NULL);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_filter_foreach_pkginfo : fail\n");
		goto end;
	}

end:
	if (ret == PMINFO_R_OK) {
		printf("TC 03 result :: OK\n");
	} else {
		printf("TC 03 result :: fail\n");
	}

	if(handle)
		pkgmgrinfo_pkginfo_filter_destroy(handle);

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_04()
{
	int ret = 0;
	long check_time = 0;
	int spend_time = 0;
	struct timeval tv;
	pkgmgrinfo_pkginfo_h handle;

	printf("--------------------------------------------------------\n");
	printf("TC 04 : pkgmgrinfo_appinfo_get_list\n");
	printf("### Access DB table list ###\n");
	printf("package_app_info\n");
	printf("package_app_localized_info\n");
	printf("package_app_icon_section_info\n");
	printf("package_app_image_info\n");
	printf("package_app_app_catogory\n");
	printf("package_app_app_metadata\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(TEST_PKGID, &handle);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_get_pkginfo : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __app_list_cb, NULL);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_get_list : fail\n");
		goto end;
	}

end:
	if(handle)
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	if (ret == PMINFO_R_OK) {
		printf("TC 04 result :: OK\n");
	} else {
		printf("TC 04 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_05()
{
	int ret = 0;
	char *label = NULL;
	char *icon = NULL;

	long check_time = 0;
	int spend_time = 0;
	struct timeval tv;

	pkgmgrinfo_appinfo_h handle = NULL;

	printf("--------------------------------------------------------\n");
	printf("TC 05 : pkgmgrinfo_appinfo_get_appinfo\n");
	printf("### Access DB table list ###\n");
	printf("package_app_info\n");
	printf("package_app_localized_info\n");
	printf("package_app_app_category\n");
	printf("package_app_app_metadata\n");
	printf("package_app_app_permission\n");
	printf("package_app_icon_section_info\n");
	printf("package_app_image_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_appinfo_get_appinfo(TEST_APPID, &handle);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_get_appinfo : fail\n");
		goto end;
	}

	printf("appid : %s\n", TEST_APPID);

	ret = pkgmgrinfo_appinfo_get_label(handle, &label);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_get_label : fail\n");
		goto end;
	}
	printf("label : %s\n", label);

	ret = pkgmgrinfo_appinfo_get_icon(handle, &icon);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_get_icon : fail\n");
		goto end;
	}
	printf("icon : %s\n", icon);

end:
	if(handle)
		pkgmgrinfo_appinfo_destroy_appinfo(handle);

	if (ret == PMINFO_R_OK) {
		printf("TC 05 result :: OK\n");
	} else {
		printf("TC 05 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_06()
{
	int ret = 0;
	long check_time = 0;;
	int spend_time = 0;
	struct timeval tv;

	printf("--------------------------------------------------------\n");
	printf("TC 06 : pkgmgrinfo_appinfo_get_install_list\n");
	printf("### Access DB table list ###\n");
	printf("package_app_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_appinfo_get_install_list(__app_list_cb, NULL);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_get_install_list : fail\n");
		goto end;
	}

end:
	if (ret == PMINFO_R_OK) {
		printf("TC 06 result :: OK\n");
	} else {
		printf("TC 06 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_07()
{
	int ret = 0;
	long check_time = 0;
	int spend_time = 0;
	struct timeval tv;

	printf("--------------------------------------------------------\n");
	printf("TC 07 : pkgmgrinfo_appinfo_get_installed_list\n");
	printf("### Access DB table list ###\n");
	printf("package_app_info\n");
	printf("package_app_localized_info\n");
	printf("package_app_icon_section_info\n");
	printf("package_app_image_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_appinfo_get_installed_list(__app_list_cb, NULL);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_get_install_list : fail\n");
		goto end;
	}

end:
	if (ret == PMINFO_R_OK) {
		printf("TC 07 result :: OK\n");
	} else {
		printf("TC 07 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_08()
{
	int ret = 0;

	long check_time = 0;
	int spend_time = 0;
	struct timeval tv;

	pkgmgrinfo_appinfo_filter_h handle = NULL;

	printf("--------------------------------------------------------\n");
	printf("TC 08 : pkgmgrinfo_appinfo_filter_foreach_appinfo\n");
	printf("### Access DB table list ###\n");
	printf("package_app_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_filter_create : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_appinfo_filter_add_bool(handle, PMINFO_APPINFO_PROP_APP_NODISPLAY, 1);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_filter_add_string : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(handle, __app_list_cb, NULL);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_filter_foreach_appinfo : fail\n");
		goto end;
	}

end:
	if(handle)
		pkgmgrinfo_appinfo_filter_destroy(handle);

	if (ret == PMINFO_R_OK) {
		printf("TC 08 result :: OK\n");
	} else {
		printf("TC 08 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_09()
{
	int ret = 0;

	long check_time;
	int spend_time = 0;
	struct timeval tv;

	pkgmgrinfo_appinfo_metadata_filter_h handle = NULL;

	printf("--------------------------------------------------------\n");
	printf("TC 09 : pkgmgrinfo_appinfo_metadata_filter_foreach\n");
	printf("### Access DB table list ###\n");
	printf("package_app_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_appinfo_metadata_filter_create(&handle);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_metadata_filter_create : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_appinfo_metadata_filter_add(handle, "http://developer.samsung.com/tizen/metadata/splash", NULL);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_metadata_filter_add : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_appinfo_metadata_filter_foreach(handle, __app_list_cb, NULL);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_filter_foreach : fail\n");
		goto end;
	}

end:
	if(handle)
		pkgmgrinfo_appinfo_metadata_filter_destroy(handle);

	if (ret == PMINFO_R_OK) {
		printf("TC 09 result :: OK\n");
	} else {
		printf("TC 09 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_10()
{
	int ret = 0;
	long check_time = 0;
	int spend_time = 0;
	struct timeval tv;
	int count = 0;

	pkgmgrinfo_pkginfo_filter_h handle = NULL;

	printf("--------------------------------------------------------\n");
	printf("TC 10 : pkgmgrinfo_pkginfo_filter_count\n");
	printf("### Access DB table list ###\n");
	printf("package_info\n");
	printf("package_localized_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_filter_create : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_pkginfo_filter_add_string(handle, PMINFO_PKGINFO_PROP_PACKAGE_TYPE, "rpm\n");
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_filter_add_string : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_pkginfo_filter_count(handle, &count);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_pkginfo_filter_count : fail\n");
		goto end;
	}
	printf("count : %d\n", count);

end:
	if(handle)
		pkgmgrinfo_pkginfo_filter_destroy(handle);

	if (ret == PMINFO_R_OK) {
		printf("TC 10 result :: OK\n");
	} else {
		printf("TC 10 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static int __tc_11()
{
	int ret = 0;
	long check_time = 0;
	int spend_time = 0;
	struct timeval tv;
	int count = 0;

	pkgmgrinfo_appinfo_filter_h handle = NULL;

	printf("--------------------------------------------------------\n");
	printf("TC 11 : pkgmgrinfo_appinfo_filter_count\n");
	printf("### Access DB table list ###\n");
	printf("package_app_info\n");

	gettimeofday(&tv, NULL);
	check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_filter_create : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_appinfo_filter_add_bool(handle, PMINFO_APPINFO_PROP_APP_NODISPLAY, 1);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_filter_add_bool : fail\n");
		goto end;
	}

	ret = pkgmgrinfo_appinfo_filter_count(handle, &count);
	if (ret != PMINFO_R_OK) {
		printf("pkgmgrinfo_appinfo_filter_count : fail\n");
		goto end;
	}
	printf("count : %d\n", count);

end:
	if(handle)
		pkgmgrinfo_appinfo_filter_destroy(handle);

	if (ret == PMINFO_R_OK) {
		printf("TC 11 result :: OK\n");
	} else {
		printf("TC 11 result :: fail\n");
	}

	spend_time = __check_time(check_time);
	return spend_time;
}

static void __api_performance_test()
{
	int spend_time_tc_01 = 0;
	int spend_time_tc_02 = 0;
	int spend_time_tc_03 = 0;
	int spend_time_tc_04 = 0;
	int spend_time_tc_05 = 0;
	int spend_time_tc_06 = 0;
	int spend_time_tc_07 = 0;
	int spend_time_tc_08 = 0;
	int spend_time_tc_09 = 0;
	int spend_time_tc_10 = 0;
	int spend_time_tc_11 = 0;

	printf("========================================================\n");
	printf("\t\t\t Start API perf\n");
	printf("========================================================\n");

	spend_time_tc_01 = __tc_01();
	spend_time_tc_02 = __tc_02();
	spend_time_tc_03 = __tc_03();
	spend_time_tc_04 = __tc_04();
	spend_time_tc_05 = __tc_05();
	spend_time_tc_06 = __tc_06();
	spend_time_tc_07 = __tc_07();
	spend_time_tc_08 = __tc_08();
	spend_time_tc_09 = __tc_09();
	spend_time_tc_10 = __tc_10();
	spend_time_tc_11 = __tc_11();


	printf("========================================================\n");
	printf("\t\t\t Test Result\n");
	printf("========================================================\n");
	if(spend_time_tc_01)
		printf("TC 01 - get pkginfo               : %d ms\n", spend_time_tc_01);
	if(spend_time_tc_02)
		printf("TC 02 - get installed pkg list    : %d ms\n", spend_time_tc_02);
	if(spend_time_tc_03)
		printf("TC 03 - pkg filter                : %d ms\n", spend_time_tc_03);
	if(spend_time_tc_04)
		printf("TC 04 - get appinfo from pkgid    : %d ms\n", spend_time_tc_04);
	if(spend_time_tc_05)
		printf("TC 05 - get appinfo               : %d ms\n", spend_time_tc_05);
	if(spend_time_tc_06)
		printf("TC 06 - get app list with basic   : %d ms\n", spend_time_tc_06);
	if(spend_time_tc_07)
		printf("TC 07 - get app list with full    : %d ms\n", spend_time_tc_07);
	if(spend_time_tc_08)
		printf("TC 08 - app filter                : %d ms\n", spend_time_tc_08);
	if(spend_time_tc_09)
		printf("TC 09 - app metadata filter       : %d ms\n", spend_time_tc_09);
	if(spend_time_tc_10)
		printf("TC 10 - pkg filter count          : %d ms\n", spend_time_tc_10);
	if(spend_time_tc_11)
		printf("TC 11 - app filter count          : %d ms\n", spend_time_tc_11);
	printf("========================================================\n");
	printf("\t\t\t Finish test perf\n");
	printf("========================================================\n");
}

int __do_api_test(pkg_tool_args *pkg_args)
{
	int ret = PMINFO_R_OK;
	int option = -1;

	option = atoi(pkg_args->pkgid);

	switch (option) {

	case 1:
		__check_fota_result();
		break;

	case 2:
		__send_event_make_exdir();
		break;

	case 3:
		__clear_cache_dir();
		break;

	case 4:
		__api_performance_test();
		break;

	default:
		__do_print_usage_api_test();
		ret = -1;
	}

	return ret;
}
