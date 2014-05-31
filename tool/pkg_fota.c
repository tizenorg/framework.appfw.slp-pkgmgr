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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <iniparser.h>

#include <pkgmgr_parser.h>
#include <pkgmgr-info.h>

#define PKGMGR_FOTA_PATH	 		"/opt/share/packages/.recovery/fota/"
#define FACTORYRESET_BACKUP_FILE	"/usr/system/RestoreDir/opt.zip"
#define CSC_APPLIST_INI_FILE		"/opt/system/csc-default/app/applist.ini"

#define DBSPACE_PATH			"/opt/dbspace/"
#define PKGMGR_DB				DBSPACE_PATH".pkgmgr_parser.db"
#define PKGMGR_DB_BACKUP		DBSPACE_PATH".pkgmgr_parser_b.db"

#define PKGMGR_DB_JOURNAL			DBSPACE_PATH".pkgmgr_parser.db-journal"
#define PKGMGR_DB_JOURNAL_BACKUP	DBSPACE_PATH".pkgmgr_parser_b.db-journal"

#define FOTA_PKGMGR_DB_FILE 	PKGMGR_FOTA_PATH".pkgmgr_parser.db"

#define CSC_PKGID_LIST_FILE 	PKGMGR_FOTA_PATH"csc_pkgid_list.txt"

#define RO_PKGID_LIST_FILE 		PKGMGR_FOTA_PATH"ro_pkgid_list.txt"
#define RW_PKGID_LIST_FILE 		PKGMGR_FOTA_PATH"rw_pkgid_list.txt"

#define RO_FOTA_PKGID_LIST_FILE 	PKGMGR_FOTA_PATH"ro_fota_pkgid_list.txt"
#define RW_FOTA_PKGID_LIST_FILE 	PKGMGR_FOTA_PATH"rw_fota_pkgid_list.txt"

#define FOTA_RESULT_FILE 		PKGMGR_FOTA_PATH"result.txt"
#define TPK_MANIFEST_FILE 		PKGMGR_FOTA_PATH"manifest.xml"

#define PKG_INFO_DB_LABEL "pkgmgr::db"
#define PKG_PARSER_DB_FILE "/opt/dbspace/.pkgmgr_parser.db"
#define PKG_PARSER_DB_FILE_JOURNAL "/opt/dbspace/.pkgmgr_parser.db-journal"

#define OPT_MANIFEST_DIRECTORY "/opt/share/packages"
#define USR_MANIFEST_DIRECTORY "/usr/share/packages"
#define BUFSZE 1024

#define TOKEN_MANEFEST_STR	"manifest"
#define TOKEN_PKGID_STR		"package="
#define TOKEN_VERSION_STR	"version="
#define TOKEN_TYPE_STR		"type="
#define TOKEN_PATH_STR		"path"
#define TOKEN_TPK_PKGID_STR	"<Id>"

#define SEPERATOR_START		'"'
#define SEPERATOR_END		'"'
#define SEPERATOR_MID		':'

#define _LOG(fmt, arg...) do { \
	int fd = 0;\
	FILE* file = NULL;\
	file = fopen(FOTA_RESULT_FILE, "a");\
	if (file == NULL) break;\
	fprintf(file, "[PKG_FOTA] "fmt"", ##arg); \
	fflush(file);\
	fd = fileno(file);\
	fsync(fd);\
	fclose(file);\
	fprintf(stderr, "[PKG_FOTA] "fmt"", ##arg);\
} while (0)

typedef enum {
	PKG_IS_NOT_EXIST = 0,
	PKG_IS_SAME,
	PKG_IS_UPDATED,
	PKG_IS_INSERTED,
	PKG_IS_REMOVED
} COMPARE_RESULT;

static int initdb_xsystem(const char *argv[])
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

static void __remove_pkgid_list()
{
	if (access(FOTA_RESULT_FILE, R_OK) == 0){
		(void)remove(FOTA_RESULT_FILE);
	}

	if (access(RO_PKGID_LIST_FILE, R_OK) == 0){
		(void)remove(RO_PKGID_LIST_FILE);
	}

	if (access(RO_FOTA_PKGID_LIST_FILE, R_OK) == 0){
		(void)remove(RO_FOTA_PKGID_LIST_FILE);
	}

	if (access(CSC_PKGID_LIST_FILE, R_OK) == 0){
		(void)remove(CSC_PKGID_LIST_FILE);
	}

	if (access(TPK_MANIFEST_FILE, R_OK) == 0){
		(void)remove(TPK_MANIFEST_FILE);
	}

	if (access(RW_PKGID_LIST_FILE, R_OK) == 0){
		(void)remove(RW_PKGID_LIST_FILE);
	}

	if (access(RW_FOTA_PKGID_LIST_FILE, R_OK) == 0){
		(void)remove(RW_FOTA_PKGID_LIST_FILE);
	}
}

static int __make_pkgid_list(char *file_path, char *pkgid, char *version, char *type)
{
	FILE *fp;\

	if (NULL == pkgid)
		return 0;

	fp = fopen(file_path, "a+");\
	if (NULL == fp)
		return -1;

	fprintf(fp, "%s\"%s\"   %s\"%s\"   %s\"%s\":\n", TOKEN_PKGID_STR, pkgid, TOKEN_VERSION_STR, version, TOKEN_TYPE_STR, type); \
	fclose(fp);\

	return 0;
}

static int __pkgid_list_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid = NULL;
	char *version = NULL;
	char *type = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if(ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_get_pkgid() failed\n");
	}

	ret = pkgmgrinfo_pkginfo_get_version(handle, &version);
	if(ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_get_pkgid() failed\n");
	}

	ret = pkgmgrinfo_pkginfo_get_type(handle, &type);
	if(ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_get_pkgid() failed\n");
	}

	ret = __make_pkgid_list((char *)user_data, pkgid, version, type);

	return ret;
}

static void __str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!isspace(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

static char * __getvalue(const char* pBuf, const char* pKey)
{
	const char* p = NULL;
	const char* pStart = NULL;
	const char* pEnd = NULL;

	p = strstr(pBuf, pKey);
	if (p == NULL)
		return NULL;

	pStart = p + strlen(pKey) + 1;
	pEnd = strchr(pStart, SEPERATOR_END);
	if (pEnd == NULL) {
		pEnd = strchr(pStart, SEPERATOR_MID);
		if (pEnd == NULL)
			return NULL;
	}

	size_t len = pEnd - pStart;
	if (len <= 0)
		return NULL;

	char *pRes = (char*)malloc(len + 1);
	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	return pRes;
}

static char * __find_str(const char* manifest, const char *str)
{
	FILE *fp = NULL;
	char buf[BUFSZE] = {0};
	char *get_str = NULL;

	fp = fopen(manifest, "r");
	if (fp == NULL) {
		_LOG("Fail get : %s\n", manifest);
		return NULL;
	}

	while (fgets(buf, BUFSZE, fp) != NULL) {
		__str_trim(buf);

		if (strstr(buf, TOKEN_MANEFEST_STR) != NULL) {
			get_str = __getvalue(buf, str);
			if (get_str !=  NULL) {
				fclose(fp);
				return get_str;
			}
		}
		memset(buf, 0x00, BUFSZE);
	}

	if (fp != NULL)
		fclose(fp);

	return NULL;
}

static int __compare_version(char *orig_version, char *fota_version)
{
	int i = 1;
	char* orig_str[4]= {0, };
	char* fota_str[4]= {0, };

	char orig_ver[BUFSZE] = {0};
	char fota_ver[BUFSZE] = {0};

	if ((orig_version == NULL) || (fota_version == NULL)) {
		_LOG("Version is null \n");
		return PKG_IS_SAME;
	}

	snprintf(orig_ver, BUFSZE-1, "%s", orig_version);
	snprintf(fota_ver, BUFSZE-1, "%s", fota_version);

	orig_str[0] = strtok(orig_ver,".");
	while(1)
	{
		orig_str[i] = strtok(NULL,".");
		if(orig_str[i] == NULL)
			break;
		i++;
	}

	i = 1;
	fota_str[0] = strtok(fota_ver,".");
	while(1)
	{
		fota_str[i] = strtok(NULL,".");
		if(fota_str[i] == NULL)
			break;
		i++;
	}

	if((orig_str[0] == NULL) || (orig_str[1] == NULL) || (orig_str[2] == NULL))
		return PKG_IS_SAME;

	/*check first number*/
	if (atoi(orig_str[0]) < atoi(fota_str[0])) {
		return PKG_IS_UPDATED;
	} else if (atoi(orig_str[0]) == atoi(fota_str[0])) {
		/*check 2nd number*/
		if (atoi(orig_str[1]) < atoi(fota_str[1])) {
			return PKG_IS_UPDATED;
		} else if (atoi(orig_str[1]) == atoi(fota_str[1])) {
			/*check 3rd number*/
			if (atoi(orig_str[2]) < atoi(fota_str[2])) {
				return PKG_IS_UPDATED;
			}
		}
	}

	/*other case is same*/
	return PKG_IS_SAME;
}

static int __compare_pkgid(char *file_path, char *fota_pkgid, char *fota_version)
{
	int ret = PKG_IS_NOT_EXIST;
	FILE *fp = NULL;
	char buf[BUFSZE] = {0};
	char *pkgid = NULL;
	char *version = NULL;

	if((file_path == NULL) || (fota_pkgid == NULL) || (fota_version == NULL)){
		_LOG("input is null\n");
		return -1;
	}

	fp = fopen(file_path, "r");
	if (fp == NULL) {
		_LOG("Fail get : %s\n", file_path);
		return -1;
	}

	while (fgets(buf, BUFSZE, fp) != NULL) {
		__str_trim(buf);

		pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		if(pkgid == NULL) {
			_LOG("pkgid is null\n");
			continue;
		}
		version = __getvalue(buf, TOKEN_VERSION_STR);
		if(version == NULL) {
			free(pkgid);
			_LOG("version is null\n");
			continue;
		}

		if(strcmp(pkgid, fota_pkgid) == 0) {
			if(__compare_version(version, fota_version) == PKG_IS_UPDATED) {
				ret = PKG_IS_UPDATED;
				_LOG("Pkg[%s] is updated[orig ver=%s, fota ver=%s]\n", fota_pkgid, version, fota_version);
				free(pkgid);
				free(version);
				break;
			}

			free(pkgid);
			free(version);
			ret =  PKG_IS_SAME;
			break;
		}

		free(pkgid);
		free(version);
		memset(buf, 0x00, BUFSZE);
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
}

static int __compare_csc_pkgid(const char *pkgid)
{
	int ret = 0;
	FILE *fp = NULL;
	char buf[BUFSZE] = {0};
	char *csc_pkgid = NULL;

	if(pkgid == NULL) {
		_LOG("pkgid is null\n");
		return ret;
	}

	fp = fopen(CSC_PKGID_LIST_FILE, "r");
	if (fp == NULL) {
//		_LOG("Fail get : %s\n", CSC_PKGID_LIST_FILE);
		return ret;
	}

	while (fgets(buf, BUFSZE, fp) != NULL) {
		__str_trim(buf);

		csc_pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		if(csc_pkgid == NULL) {
			_LOG("pkgid is null\n");
			memset(buf, 0x00, BUFSZE);
			continue;
		}

		if(strcmp(csc_pkgid, pkgid) == 0) {
			_LOG("pkgid[%s] is already processed by csc \n", pkgid);
			free(csc_pkgid);
			ret = -1;
			break;
		}

		free(csc_pkgid);
		memset(buf, 0x00, BUFSZE);
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
}

static char *__get_pkgid_from_tpk_manifest(const char* manifest)
{
	FILE *fp = NULL;
	char buf[BUFSZE] = {0};

	fp = fopen(manifest, "r");
	if (fp == NULL)	{
		_LOG("Fail get : %s \n", manifest);
		return NULL;
	}

	while (fgets(buf, BUFSZE, fp) != NULL) {
		__str_trim(buf);

		const char* p = NULL;
		const char* pStart = NULL;

		p = strstr(buf, TOKEN_TPK_PKGID_STR);
		if (p != NULL) {
			pStart = p + strlen(TOKEN_TPK_PKGID_STR);
			char *pRes = (char*)malloc(11);
			strncpy(pRes, pStart, 10);
			pRes[10] = 0;
			fclose(fp);
			return pRes;
		}
		memset(buf, 0x00, BUFSZE);
	}

	if (fp != NULL)
		fclose(fp);

	return NULL;
}

char* __manifest_to_package(const char* manifest)
{
	char *package;

	if(manifest == NULL)
		return NULL;

	package = strdup(manifest);
	if(package == NULL)
		return NULL;

	if (!strstr(package, ".xml")) {
		_LOG("%s is not a manifest file \n", manifest);
		free(package);
		return NULL;
	}

	return package;
}

static void __send_args_to_backend(char *pkgid, char *type, int compare_result)
{
	int ret = 0;
	char *op = NULL;
	char buf[BUFSZE] = {0};

	if (compare_result == PKG_IS_SAME) {
//		_LOG("Pkgid[%s] - [%s] is same\n", pkgid, type);
		return;
	}

	if (__compare_csc_pkgid(pkgid) < 0) {
		return;
	}

	switch (compare_result) {
		case 2:
			op  = "update";
//			_LOG("pkgid[%s] is update, it is already exist\n", pkgid);
			break;

		case 3:
			op  = "install";
			_LOG("pkgid[%s] is install, it is new\n", pkgid);
			break;

		case 4:
			op  = "uninstall";
			_LOG("pkgid[%s] is uninstall, it is deleted\n", pkgid);
			break;

		default:
			break;
	}

	snprintf(buf, sizeof(buf), "path=%s:op=%s", pkgid, op);

	if (strcmp(type,"rpm") == 0) {
		const char *rpm_argv[] = { "/usr/bin/rpm-backend", "-k", "rpm-fota", "-s", buf, NULL };
		ret = initdb_xsystem(rpm_argv);
	} else if(strcmp(type,"tpk") == 0) {
		const char *osp_argv[] = { "/usr/bin/osp-installer", "-f", buf, NULL };
		ret = initdb_xsystem(osp_argv);
	} else if(strcmp(type,"wgt") == 0) {
		const char *wrt_argv[] = { "/usr/bin/wrt-installer", "-f", buf, NULL };
		ret = initdb_xsystem(wrt_argv);
	} else {
		_LOG("Pkgid[%s] - [%s] is not supported\n", pkgid, type);
		return;
	}

	_LOG("Pkgid[%s] -- send args done -- type[%s], operation[%s], result[%d]\n", pkgid, type, op, ret);
}


static void __send_args_to_backend_for_rw_fota(char *pkgid, char *type, int compare_result)
{
	int ret = 0;
	char *op = NULL;
	char buf[BUFSZE] = {0};

	if (compare_result == PKG_IS_SAME) {
//		_LOG("Pkgid[%s] - [%s] is same\n", pkgid, type);
		return;
	}

	if (__compare_csc_pkgid(pkgid) < 0) {
		return;
	}

	switch (compare_result) {
		case 2:
			op  = "update";
			_LOG("pkgid[%s] is update, it is already exist\n", pkgid);
			break;
		case 3:
			op  = "install";
			_LOG("pkgid[%s] is install, it is new\n", pkgid);
			break;
		case 4:
			op  = "uninstall";
			_LOG("pkgid[%s] is uninstall, it is deleted\n", pkgid);
			break;
		default:
			break;
	}

	snprintf(buf, sizeof(buf), "path=%s:op=%s", pkgid, op);

	if (strcmp(type,"rpm") == 0) {
		const char *rpm_argv[] = { "/usr/bin/rpm-backend", "-k", "rpm-rw-fota", "-s", buf, NULL };
		ret = initdb_xsystem(rpm_argv);
	} else if(strcmp(type,"tpk") == 0) {
		const char *osp_argv[] = { "/usr/bin/osp-installer", "-F", buf, NULL };
		ret = initdb_xsystem(osp_argv);
	} else if(strcmp(type,"wgt") == 0) {
		const char *wrt_argv[] = { "/usr/bin/wrt-installer", "-F", buf, NULL };
		ret = initdb_xsystem(wrt_argv);
	} else {
		_LOG("Pkgid[%s] - [%s] is not supported\n", pkgid, type);
		return;
	}

	_LOG("Result :: Pkgid[%s], type[%s], operation[%s], result[%d]\n", pkgid, type, op, ret);
}

static int __find_preload_pkgid_from_xml(const char *file_path)
{
	int ret = 0;
	char buf[BUFSZE] = {0};
	DIR *dir;
	struct dirent entry, *result;

	dir = opendir(USR_MANIFEST_DIRECTORY);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			_LOG("Failed to access the [%s] because %s\n", USR_MANIFEST_DIRECTORY, buf);
		return -1;
	}

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {
		char *manifest;
		char *pkgid;
		char *version;
		char *type;

		if (entry.d_name[0] == '.') continue;

		manifest = __manifest_to_package(entry.d_name);
		if (!manifest) {
			_LOG("Failed to convert file to xml[%s]\n", entry.d_name);
			continue;
		}

		snprintf(buf, sizeof(buf), "%s/%s", USR_MANIFEST_DIRECTORY, manifest);

		ret = pkgmgr_parser_check_manifest_validation(buf);
		if (ret < 0) {
//			_LOG("manifest validation failed : %s \n", buf);
			free(manifest);
			continue;
		}

		pkgid = __find_str(buf, TOKEN_PKGID_STR);
		if(pkgid == NULL) {
			free(manifest);
			continue;
		}
		version = __find_str(buf, TOKEN_VERSION_STR);
		if(version == NULL)
			version = strdup("0.0.1");
		type = __find_str(buf, TOKEN_TYPE_STR);
		if(type == NULL)
			type = strdup("rpm");

		ret = __make_pkgid_list(file_path, pkgid, version, type);
		if (ret < 0)
			_LOG("Make file Fail : %s => %s, %s\n", buf, pkgid, version);

		free(pkgid);
		free(version);
		free(type);
		free(manifest);
	}

	closedir(dir);

	return 0;
}

static int __find_preload_pkgid_from_db(const char *file_path, int is_readonly)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_filter_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	if (ret > 0) {
		_LOG("pkginfo filter handle create failed\n");
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD, 1);
	if (ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
		ret = -1;
	}

	if (is_readonly == 1) {
		ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE, 0);
		if (ret < 0) {
			_LOG("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
			ret = -1;
		}

		ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_READONLY, 1);
		if (ret < 0) {
			_LOG("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
			ret = -1;
		}
	} else {
		ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_READONLY, 0);
		if (ret < 0) {
			_LOG("pkgmgrinfo_pkginfo_filter_add_string() failed\n");
		}
	}

	ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __pkgid_list_cb, (void *)file_path);
	if (ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_filter_foreach_pkginfo() failed\n");
		ret = -1;
	}

	pkgmgrinfo_pkginfo_filter_destroy(handle);
	return ret;
}

static int __find_matched_pkgid_from_list(const char *source_file, const char *target_file, int rw_fota_enabled)
{
	FILE *fp = NULL;
	char buf[BUFSZE] = {0};
	char *pkgid = NULL;
	char *version = NULL;
	char *type = NULL;

	int same_pkg_cnt = 0;
	int update_pkg_cnt = 0;
	int insert_pkg_cnt = 0;
	int total_pkg_cnt = 0;

	int compare_result = 0;

	fp = fopen(source_file, "r");
	if (fp == NULL) {
		_LOG("Fail get : %s\n", source_file);
		return -1;
	}

	_LOG("Searching...... inserted  or  Updated package \n");

	while (fgets(buf, BUFSZE, fp) != NULL) {
		__str_trim(buf);

		pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		version = __getvalue(buf, TOKEN_VERSION_STR);
		type = __getvalue(buf, TOKEN_TYPE_STR);

		if(pkgid == NULL) {
			if(version) {
				free(version);
				version = NULL;
			}
			if(type) {
				free(type);
				type = NULL;
			}
			continue;
		}

		compare_result = __compare_pkgid(target_file, pkgid, version);
		if(compare_result == PKG_IS_NOT_EXIST) {
			compare_result = PKG_IS_INSERTED;
			insert_pkg_cnt++;
		} else if (compare_result == PKG_IS_SAME) {
			same_pkg_cnt++;
		} else if (compare_result == PKG_IS_UPDATED) {
			update_pkg_cnt++;
		}

		total_pkg_cnt++;

		if (rw_fota_enabled == 1)
			__send_args_to_backend_for_rw_fota(pkgid, type, compare_result);
		else
			__send_args_to_backend(pkgid, type, compare_result);

		memset(buf, 0x00, BUFSZE);
		if(pkgid) {
			free(pkgid);
			pkgid = NULL;
		}
		if(version) {
			free(version);
			version = NULL;
		}
		if(type) {
			free(type);
			type = NULL;
		}
	}

	_LOG("Finish Searching ::: [Total pkg=%d, same pkg=%d, updated pkg=%d, inserted package=%d]\n\n", total_pkg_cnt, same_pkg_cnt, update_pkg_cnt, insert_pkg_cnt);

	if (fp != NULL)
		fclose(fp);

	return 0;
}

static int __find_deleted_pkgid_from_list(const char *source_file, const char *target_file, int rw_fota_enabled)
{
	FILE *fp = NULL;
	char buf[BUFSZE] = {0};
	char *pkgid = NULL;
	char *version = NULL;
	char *type = NULL;

	int deleted_pkg_cnt = 0;
	int total_pkg_cnt = 0;

	int compare_result = 0;

	fp = fopen(source_file, "r");
	if (fp == NULL) {
		_LOG("Fail get : %s\n", source_file);
		return -1;
	}

	_LOG("Searching...... deleted package \n");

	while (fgets(buf, BUFSZE, fp) != NULL) {
		__str_trim(buf);

		pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		version = __getvalue(buf, TOKEN_VERSION_STR);
		type = __getvalue(buf, TOKEN_TYPE_STR);

		if(pkgid == NULL) {
			if(version) {
				free(version);
				version = NULL;
			}
			if(type) {
				free(type);
				type = NULL;
			}
			continue;
		}

		compare_result = __compare_pkgid(target_file, pkgid, version);
		if(compare_result == PKG_IS_NOT_EXIST) {
			compare_result = PKG_IS_REMOVED;

			if (rw_fota_enabled == 1)
				__send_args_to_backend_for_rw_fota(pkgid, type, compare_result);
			else
				__send_args_to_backend(pkgid, type, compare_result);

			deleted_pkg_cnt++;
		}
		total_pkg_cnt++;

		memset(buf, 0x00, BUFSZE);
		if(pkgid) {
			free(pkgid);
			pkgid = NULL;
		}
		if(version) {
			free(version);
			version = NULL;
		}
		if(type) {
			free(type);
			type = NULL;
		}
	}

	_LOG("Finish Searching ::: [Total pkg=%d, deleted package=%d]\n\n", total_pkg_cnt, deleted_pkg_cnt);

	if (fp != NULL)
		fclose(fp);

	return 0;

}

static void __find_tpk_pkgid_from_csc(const char *tpk_path, char *result_path)
{
	int ret = 0;
	char *pkgid = NULL;

	/*check : input param is pkgid or tpk file*/
	if (strstr(tpk_path, ".tpk") == NULL) {
		__make_pkgid_list(result_path, tpk_path, NULL, NULL);
		return;
	}

	/*unzip manifest from tpk*/
	const char *unzip_argv[] = { "/usr/bin/unzip", "-j", tpk_path, "info/manifest.xml", "-d", PKGMGR_FOTA_PATH, NULL };
	ret = initdb_xsystem(unzip_argv);
	if (ret < 0) {
		_LOG("unzip_argv fail[%s]", tpk_path);
		return;
	}

	/*open manifest and get pkgid*/
	pkgid = __get_pkgid_from_tpk_manifest(TPK_MANIFEST_FILE);
	if (pkgid == NULL) {
		_LOG("pkgid is null[%s]", tpk_path);
		return;
	}

	/*make csc pkgid list*/
	__make_pkgid_list(result_path, pkgid, NULL, NULL);

	/*free variable*/
	free(pkgid);

	(void)remove(TPK_MANIFEST_FILE);
}

static void __find_xml_pkgid_from_csc(const char *xml_path, char *result_path)
{
	char *pkgid = NULL;
	FILE *fp = NULL;
	char buf[BUFSZE] = {0,};

	if (strstr(xml_path, ".xml") == NULL) {
		__make_pkgid_list(result_path, xml_path, NULL, NULL);
		return;
	}

	fp = fopen(xml_path, "r");
	if (fp == NULL) {
		return;
	}

	while (fgets(buf, BUFSZE, fp) != NULL) {
		__str_trim(buf);
		pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		if (pkgid !=  NULL) {
			/*make csc pkgid list*/
			__make_pkgid_list(result_path, pkgid, NULL, NULL);
			free(pkgid);
			fclose(fp);
			return;
		}
		memset(buf, 0x00, BUFSZE);
	}

	if (fp != NULL)
		fclose(fp);
}

static void __get_pkgid_list_from_db_and_xml()
{
	int ret = 0;
	int is_readonly = 1;

	/*get pkgid of old version */
	ret = __find_preload_pkgid_from_db(RO_PKGID_LIST_FILE, is_readonly);
	if (ret < 0) {
		_LOG("__find_preload_pkgid_from_db fail.\n");
	} else {
		_LOG("Make original pkgid success!! \n");
	}

	/*get pkgid of updated version by fota*/
	ret = __find_preload_pkgid_from_xml(RO_FOTA_PKGID_LIST_FILE);
	if (ret < 0) {
		_LOG("__find_preload_pkgid_from_xml fail.\n");
	} else {
		_LOG("Make fota pkgid success!! \n\n");
	}
}

static void __get_pkgid_list_from_db_and_zip()
{
	int ret = 0;
	int is_readonly = 0;

	/*get pkgid from orginal pkgmgr db*/
	ret = __find_preload_pkgid_from_db(RW_PKGID_LIST_FILE, is_readonly);
	if (ret < 0) {
		_LOG("__find_preload_pkgid_from_db fail.\n");
	} else {
		_LOG("Make original pkgid success!! \n");
	}

	/*move orginal pkgmgr db to backup*/
	const char *db_mv_argv[] = { "/bin/mv", PKGMGR_DB, PKGMGR_DB_BACKUP, NULL };
	ret = initdb_xsystem(db_mv_argv);
	if (ret < 0) {
		_LOG("move orginal pkgmgr db to backup fail.\n");
	}
	const char *jn_mv_argv[] = { "/bin/mv", PKGMGR_DB_JOURNAL, PKGMGR_DB_JOURNAL_BACKUP, NULL };
	ret = initdb_xsystem(jn_mv_argv);
	if (ret < 0) {
		_LOG("move orginal pkgmgr db to backup fail.\n");
	}

	/*unzip pkgmgr db from factoryrest data*/
	const char *unzip_argv[] = { "/usr/bin/unzip", "-j", FACTORYRESET_BACKUP_FILE, "opt/dbspace/.pkgmgr_parser.db", "-d", PKGMGR_FOTA_PATH, NULL };
	ret = initdb_xsystem(unzip_argv);
	if (ret < 0) {
		_LOG("unzip pkgmgr db from factoryrest data fail.\n");
	}

	/*move fota pkgmgr db to dbspace*/
	const char *fota__mv_argv[] = { "/bin/mv", FOTA_PKGMGR_DB_FILE, DBSPACE_PATH, NULL };
	ret = initdb_xsystem(fota__mv_argv);
	if (ret < 0) {
		_LOG("move fota pkgmgr db to dbspace fail.\n");
	}

	/*get pkgid from fota pkgmgr db*/
	ret = __find_preload_pkgid_from_db(RW_FOTA_PKGID_LIST_FILE, is_readonly);
	if (ret < 0) {
		_LOG("__find_preload_pkgid_from_db fail.\n");
	} else {
		_LOG("Make fota pkgid success!! \n\n");
	}

	/*del pkgmgr db and recover orginal pkgmgr db from backup*/
	const char *db_rm_argv[] = { "/bin/rm", "-f", PKGMGR_DB, NULL };
	ret = initdb_xsystem(db_rm_argv);
	if (ret < 0) {
		_LOG("del pkgmgr db fail.\n");
	}
	const char *jn_rm_argv[] = { "/bin/rm", "-f", PKGMGR_DB_JOURNAL, NULL };
	ret = initdb_xsystem(jn_rm_argv);
	if (ret < 0) {
		_LOG("del pkgmgr db fail.\n");
	}

	const char *db_recover_argv[] = { "/bin/mv", PKGMGR_DB_BACKUP, PKGMGR_DB, NULL };
	ret = initdb_xsystem(db_recover_argv);
	if (ret < 0) {
		_LOG("recover orginal pkgmgr db fail.\n");
	}
	const char *jn_recover_argv[] = { "/bin/mv", PKGMGR_DB_JOURNAL_BACKUP, PKGMGR_DB_JOURNAL, NULL };
	ret = initdb_xsystem(jn_recover_argv);
	if (ret < 0) {
		_LOG("recover orginal pkgmgr db fail.\n");
	}

	const char *argv_parser[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_PARSER_DB_FILE, NULL };
	initdb_xsystem(argv_parser);
	const char *argv_parserjn[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_PARSER_DB_FILE_JOURNAL, NULL };
	initdb_xsystem(argv_parserjn);
}

static void __get_pkgid_list_from_csc()
{
	int cnt = 0;
	int count = 0;

	char *pkgtype = NULL;
	char *des = NULL;
	char *path = NULL;

	char type_buf[BUFSZE] = { 0 };
	char des_buf[BUFSZE] = { 0 };
	dictionary *csc = NULL;

	csc = iniparser_load(CSC_APPLIST_INI_FILE);
	if (csc == NULL) {
		_LOG("Dont have csc applist file\n\n");
		return;
	}

	count = iniparser_getint(csc, "csc packages:count", -1);
	if (count == 0) {
		_LOG("csc [%s] dont have packages \n", CSC_APPLIST_INI_FILE);
		goto end;
	}

	for(cnt = 1 ; cnt <= count ; cnt++)
	{
		snprintf(type_buf, BUFSZE - 1, "csc packages:type_%03d", cnt);
		snprintf(des_buf, BUFSZE - 1, "csc packages:description_%03d", cnt);

		/*parse csc description and type*/
		pkgtype = iniparser_getstr(csc, type_buf);
		des = iniparser_getstr(csc, des_buf);

		if ((pkgtype == NULL) || (des == NULL)) {
			continue;
		}

		/*get tpk path from csc description*/
		path = __getvalue(des, TOKEN_PATH_STR);
		if (path == NULL) {
			_LOG("description[%s] has error", des);
			continue;
		}

		if (strcmp(pkgtype, "tpk") == 0) {
			__find_tpk_pkgid_from_csc(path, CSC_PKGID_LIST_FILE);
		} else if (strcmp(pkgtype, "wgt")== 0) {
//			__find_wgt_pkgid_from_csc(path, CSC_PKGID_LIST_FILE);
		} else if (strcmp(pkgtype, "xml")== 0) {
			__find_xml_pkgid_from_csc(path, CSC_PKGID_LIST_FILE);
		}

		free(path);
	}

end:
	iniparser_freedict(csc);
}

int main(int argc, char *argv[])
{
	int ret;
	int rw_fota_enabled = 0;

	/*clean pkgid list file, if it is exit*/
	__remove_pkgid_list();

	_LOG("=======================================================\n");
	_LOG("	               RO preload package fota\n");
	_LOG("=======================================================\n");

	/*get pkgid from orginal pkgmgr db*/
	__get_pkgid_list_from_db_and_xml();

	/*get pkgid from csc applist*/
	__get_pkgid_list_from_csc();

	_LOG("Ready RO pkgid list for compare\n\n");

	/*find deleted pkgid*/
	ret = __find_deleted_pkgid_from_list(RO_PKGID_LIST_FILE, RO_FOTA_PKGID_LIST_FILE, rw_fota_enabled);
	if (ret < 0) {
		_LOG("__find_deleted_pkgid_from_list fail.\n");
	}

	/*find updated, inserted pkgid*/
	ret = __find_matched_pkgid_from_list(RO_FOTA_PKGID_LIST_FILE, RO_PKGID_LIST_FILE, rw_fota_enabled);
	if (ret < 0) {
		_LOG("__find_matched_pkgid_from_list fail.\n");
	}

	_LOG("End RO pkgid list for compare\n\n");

	if (access(FACTORYRESET_BACKUP_FILE, R_OK) == 0) {
		_LOG("=======================================================\n");
		_LOG("	               RW preload package fota\n");
		_LOG("=======================================================\n");

		rw_fota_enabled = 1;

		/*get pkgid from orginal pkgmgr db*/
		__get_pkgid_list_from_db_and_zip();

		if (access(RW_FOTA_PKGID_LIST_FILE, R_OK) != 0){
			_LOG(" !!! Dont have preload downloaded package in /opt/usr/apps !!!\n\n");
			goto end;
		}

		_LOG("Ready RW pkgid list for compare\n\n");

		/*find updated, inserted pkgid*/
		ret = __find_matched_pkgid_from_list(RW_FOTA_PKGID_LIST_FILE, RW_PKGID_LIST_FILE, rw_fota_enabled);
		if (ret < 0) {
			_LOG("__find_matched_pkgid_from_list fail.\n");
		}

		_LOG("End RW pkgid list for compare\n\n");
	}

	/*clean pkgid list file, if it is exit*/
	//	__remove_pkgid_list();

end:
	_LOG("=======================================================\n");
	_LOG("	               End fota process\n");
	_LOG("=======================================================\n");

	return 0;
}


