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
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <pkgmgr_parser.h>
#include <pkgmgr-info.h>

#include "pkg.h"

#define CSC_APPLIST_INI_FILE		"/opt/system/csc-default/app/applist.ini"

#define FOTA_PKGMGR_DB_FILE 		PKGMGR_FOTA_PATH".pkgmgr_parser.db"
#define CSC_PKGID_LIST_FILE 		PKGMGR_FOTA_PATH"csc_pkgid_list.txt"
#define RO_PKGID_LIST_FILE 			PKGMGR_FOTA_PATH"ro_pkgid_list.txt"
#define RW_PKGID_LIST_FILE 			PKGMGR_FOTA_PATH"rw_pkgid_list.txt"
#define RO_FOTA_PKGID_LIST_FILE 	PKGMGR_FOTA_PATH"ro_fota_pkgid_list.txt"
#define RW_FOTA_PKGID_LIST_FILE 	PKGMGR_FOTA_PATH"rw_fota_pkgid_list.txt"
#define FOTA_RESULT_FILE 			PKGMGR_FOTA_PATH"result.txt"
#define TPK_MANIFEST_FILE 			PKGMGR_FOTA_PATH"manifest.xml"
#define PKG_DISABLED_LIST_FILE 		PKGMGR_FOTA_PATH"pkg_disabled_list.txt"

#define PKG_INFO_DB_LABEL "pkgmgr::db"

#define OPT_MANIFEST_DIRECTORY "/opt/share/packages"
#define USR_MANIFEST_DIRECTORY "/usr/share/packages"

#define TOKEN_MANEFEST_STR	"manifest"
#define TOKEN_PKGID_STR		"package="
#define TOKEN_VERSION_STR	"version="
#define TOKEN_TYPE_STR		"type="
#define TOKEN_HASH_STR		"hash="
#define TOKEN_PATH_STR		"path"
#define TOKEN_TPK_PKGID_STR	"<Id>"

#define SEPERATOR_START		'"'
#define SEPERATOR_END		'"'
#define SEPERATOR_MID		':'

#define ASCII(s) (const char *)s
#define XMLCHAR(s) (const xmlChar *)s

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

static int _child_element(xmlTextReaderPtr reader, int depth)
{
	int ret = xmlTextReaderRead(reader);
	int cur = xmlTextReaderDepth(reader);
	while (ret == 1) {

		switch (xmlTextReaderNodeType(reader)) {
			case XML_READER_TYPE_ELEMENT:
				if (cur == depth + 1)
					return 1;
				break;
			case XML_READER_TYPE_TEXT:
				/*text is handled by each function separately*/
				if (cur == depth + 1)
					return 0;
				break;
			case XML_READER_TYPE_END_ELEMENT:
				if (cur == depth)
					return 0;
				break;
			default:
				if (cur <= depth)
					return 0;
				break;
			}

		ret = xmlTextReaderRead(reader);
		cur = xmlTextReaderDepth(reader);
	}
	return ret;
}
static char *__find_info_from_xml(const char *manifest, const char *find_info)
{
	const xmlChar *node;
	xmlTextReaderPtr reader;
	char *info_val = NULL;
	xmlChar *tmp = NULL;

	if(manifest == NULL) {
		_LOG("Input argument is NULL\n");
		return NULL;
	}

	if(find_info == NULL) {
		_LOG("find_info is NULL\n");
		return NULL;
	}

	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader) {
		if (_child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_LOG("xmlTextReaderConstName value is NULL\n");
				goto end;
			}

			if (!strcmp(ASCII(node), "manifest")) {
				tmp = xmlTextReaderGetAttribute(reader, XMLCHAR(find_info));
				if (tmp) {
					FREE_AND_STRDUP(ASCII(tmp),info_val);
					if(info_val == NULL)
						_LOG("Malloc Failed");
					FREE_AND_NULL(tmp);
				}
			} else {
				_LOG("Manifest Node is not found\n");
			}
		}
	} else {
		_LOG("xmlReaderForFile value is NULL\n");
	}

end:
	if (reader) {
		xmlFreeTextReader(reader);
	}

	return info_val;
}

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

	if (access(PKG_DISABLED_LIST_FILE, R_OK) == 0){
		(void)remove(PKG_DISABLED_LIST_FILE);
	}
}

static int __make_pkgid_list(char *file_path, char *pkgid, char *compare_data, char *type)
{
	FILE *fp;\

	if (NULL == pkgid)
		return 0;

	fp = fopen(file_path, "a+");
	if (NULL == fp)
		return -1;
	/* compare_data variable hold hash value if Hash comparsion is enabled, otherwise it holds version */
	fprintf(fp, "%s\"%s\"   %s\"%s\"   %s\"%s\":\n", TOKEN_PKGID_STR, pkgid, TOKEN_HASH_STR, compare_data, TOKEN_TYPE_STR, type);

	fclose(fp);\

	return 0;
}

static int __pkgid_list_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid = NULL;
	char *compare_data = NULL;
	char *type = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if(ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_get_pkgid() failed\n");
	}

	ret = pkgmgrinfo_pkginfo_get_type(handle, &type);
	if(ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_get_type() failed\n");
	}

	ret = pkgmgrinfo_pkginfo_get_hash(handle, &compare_data);
	if(ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_get_hash() failed\n");
	}

	ret = __make_pkgid_list((char *)user_data, pkgid, compare_data, type);

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
	if (pRes == NULL) {
		_LOG("out of memory");
		return NULL;
	}

	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	return pRes;
}

#ifdef _FOTA_INIT_DB

static char * __find_str(const char* manifest, const char *str)
{
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};
	char *get_str = NULL;

	fp = fopen(manifest, "r");
	if (fp == NULL) {
		_LOG("Fail get : %s\n", manifest);
		return NULL;
	}

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		if (strstr(buf, TOKEN_MANEFEST_STR) != NULL) {
			get_str = __getvalue(buf, str);
			if (get_str !=  NULL) {
				fclose(fp);
				return get_str;
			}
		}
		memset(buf, 0x00, BUF_SIZE);
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

	char orig_ver[BUF_SIZE] = {0};
	char fota_ver[BUF_SIZE] = {0};

	if ((orig_version == NULL) || (fota_version == NULL)) {
		_LOG("Version is null \n");
		return PKG_IS_SAME;
	}

	snprintf(orig_ver, BUF_SIZE-1, "%s", orig_version);
	snprintf(fota_ver, BUF_SIZE-1, "%s", fota_version);

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

#endif

static int __compare_hash(char *orig_hash, char* fota_hash)
{
	int ret = PKG_IS_SAME;
	if(strcmp(orig_hash,"(null)") && strcmp(fota_hash,"(null)")){
		if(strcmp(orig_hash,fota_hash))
			ret = PKG_IS_UPDATED;
	}

	return ret;
}
static int __compare_pkgid(char *file_path, char *fota_pkgid, char *fota_compare_data)
{
	int ret = PKG_IS_NOT_EXIST;
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};
	char *pkgid = NULL;
	char *compare_data = NULL;

	if((file_path == NULL) || (fota_pkgid == NULL) || (fota_compare_data == NULL)){
		_LOG("input is null\n");
		return -1;
	}

	fp = fopen(file_path, "r");
	if (fp == NULL) {
		_LOG("Fail get : %s\n", file_path);
		return -1;
	}

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		if(pkgid == NULL) {
			_LOG("pkgid is null\n");
			continue;
		}

		compare_data = __getvalue(buf,TOKEN_HASH_STR);

		if(compare_data == NULL) {
			free(pkgid);
			_LOG("compare_data is null\n");
			continue;
		}

		if(strcmp(pkgid, fota_pkgid) == 0) {
			if(__compare_hash(compare_data,fota_compare_data) == PKG_IS_UPDATED){
				ret = PKG_IS_UPDATED;
				free(pkgid);
				free(compare_data);
				break;
			}

			free(pkgid);
			free(compare_data);
			ret =  PKG_IS_SAME;
			break;
		}

		free(pkgid);
		free(compare_data);
		memset(buf, 0x00, BUF_SIZE);
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
}

static int __compare_csc_pkgid(const char *pkgid)
{
	int ret = 0;
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};
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

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		csc_pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		if(csc_pkgid == NULL) {
			_LOG("pkgid is null\n");
			memset(buf, 0x00, BUF_SIZE);
			continue;
		}

		if(strcmp(csc_pkgid, pkgid) == 0) {
			_LOG("pkgid[%s] is already processed by csc \n", pkgid);
			free(csc_pkgid);
			ret = -1;
			break;
		}

		free(csc_pkgid);
		memset(buf, 0x00, BUF_SIZE);
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
}

static char *__get_pkgid_from_tpk_manifest(const char* manifest)
{
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};

	fp = fopen(manifest, "r");
	if (fp == NULL)	{
		_LOG("Fail get : %s \n", manifest);
		return NULL;
	}

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		const char* p = NULL;
		const char* pStart = NULL;

		p = strstr(buf, TOKEN_TPK_PKGID_STR);
		if (p != NULL) {
			pStart = p + strlen(TOKEN_TPK_PKGID_STR);
			char *pRes = (char*)malloc(11);
			if (pRes == NULL) {
				_LOG("out of memory");
				fclose(fp);
				return NULL;
			}

			strncpy(pRes, pStart, 10);
			pRes[10] = 0;
			fclose(fp);
			return pRes;
		}
		memset(buf, 0x00, BUF_SIZE);
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
	char buf[BUF_SIZE] = {0};

	long starttime;
	long endtime;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	starttime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

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
//			_LOG("pkgid[%s] is install, it is new\n", pkgid);
			break;

		case 4:
			op  = "uninstall";
//			_LOG("pkgid[%s] is uninstall, it is deleted\n", pkgid);
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

	gettimeofday(&tv, NULL);
	endtime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	_LOG("operation[%s - %s] \t result[%d ms, %d] \t Pkgid[%s]  \n", op, type, (int)(endtime - starttime), ret, pkgid);
}


static void __send_args_to_backend_for_rw_fota(char *pkgid, char *type, int compare_result)
{
	int ret = 0;
	char *op = NULL;
	char buf[BUF_SIZE] = {0};

	long starttime;
	long endtime;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	starttime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	if(pkgid == NULL || type == NULL){
		_LOG("input is null\n");
		return;
	}

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
//			_LOG("pkgid[%s] is install, it is new\n", pkgid);
			break;
		case 4:
			op  = "uninstall";
//			_LOG("pkgid[%s] is uninstall, it is deleted\n", pkgid);
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

	gettimeofday(&tv, NULL);
	endtime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	_LOG("operation[%s - %s] \t result[%d ms, %d] \t Pkgid[%s]  \n", op, type, (int)(endtime - starttime), ret, pkgid);
}

static int __find_preload_pkgid_from_xml(const char *file_path)
{
	int ret = 0;
	char buf[BUF_SIZE] = {0};
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
		// compare_data variable holds hash value if hash comparsion is enabled, otherwise it holds version.
		char *compare_data;
		char *type;

		if (entry.d_name[0] == '.') continue;

		manifest = __manifest_to_package(entry.d_name);
		if (!manifest) {
			_LOG("Failed to convert file to xml[%s]\n", entry.d_name);
			continue;
		}

		snprintf(buf, sizeof(buf), "%s/%s", USR_MANIFEST_DIRECTORY, manifest);

		/*Get the package name from manifest file*/
		pkgid = __find_info_from_xml(buf,"package");
		if(pkgid == NULL) {
			free(manifest);
			continue;
		}

		/*Get the type of the package from manifest file*/
		type = __find_info_from_xml(buf,"type");
		if(type == NULL)
			type = strdup("rpm");

		compare_data = pkgmgrinfo_basic_generate_hash_for_file(buf);

		ret = __make_pkgid_list((char*)file_path, pkgid, compare_data, type);
		if (ret < 0)
			_LOG("Make file Fail : %s => %s, %s\n", buf, pkgid, compare_data);

		FREE_AND_NULL(pkgid);
		FREE_AND_NULL(compare_data);
		FREE_AND_NULL(type);
		FREE_AND_NULL(manifest);
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
		_LOG("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
		ret = -1;
	}

	if (is_readonly == 1) {
		ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE, 0);
		if (ret < 0) {
			_LOG("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
			ret = -1;
		}

		ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_READONLY, 1);
		if (ret < 0) {
			_LOG("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
			ret = -1;
		}
	} else {
		ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_READONLY, 0);
		if (ret < 0) {
			_LOG("pkgmgrinfo_pkginfo_filter_add_bool() failed\n");
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
	char buf[BUF_SIZE] = {0};
	char *pkgid = NULL;
	char *compare_data = NULL;
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

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		if(pkgid == NULL) {
			continue;
		}

		compare_data = __getvalue(buf,TOKEN_HASH_STR);

		type = __getvalue(buf, TOKEN_TYPE_STR);

		compare_result = __compare_pkgid((char*)target_file, pkgid, compare_data);
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

		memset(buf, 0x00, BUF_SIZE);
		FREE_AND_NULL(pkgid);
		FREE_AND_NULL(type);
		FREE_AND_NULL(compare_data);
	}

	_LOG("-------------------------------------------------------\n");
	_LOG("[Total pkg=%d, same pkg=%d, updated pkg=%d, inserted package=%d]\n", total_pkg_cnt, same_pkg_cnt, update_pkg_cnt, insert_pkg_cnt);
	_LOG("-------------------------------------------------------\n");

	if (fp != NULL)
		fclose(fp);

	return 0;
}

static int __find_deleted_pkgid_from_list(const char *source_file, const char *target_file, int rw_fota_enabled)
{
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};
	char *pkgid = NULL;
	char *compare_data = NULL;
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

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		if(pkgid == NULL) {
			continue;
		}

		type = __getvalue(buf, TOKEN_TYPE_STR);

		compare_data = __getvalue(buf,TOKEN_HASH_STR);

		compare_result = __compare_pkgid((char*)target_file, pkgid, compare_data);
		if(compare_result == PKG_IS_NOT_EXIST) {
			compare_result = PKG_IS_REMOVED;

			if (rw_fota_enabled == 1)
				__send_args_to_backend_for_rw_fota(pkgid, type, compare_result);
			else
				__send_args_to_backend(pkgid, type, compare_result);

			deleted_pkg_cnt++;
		}
		total_pkg_cnt++;

		memset(buf, 0x00, BUF_SIZE);
		FREE_AND_NULL(pkgid);
		FREE_AND_NULL(compare_data);
		FREE_AND_NULL(type);
	}

	_LOG("-------------------------------------------------------\n");
	_LOG("[Total pkg=%d, deleted package=%d]\n", total_pkg_cnt, deleted_pkg_cnt);
	_LOG("-------------------------------------------------------\n");

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
		__make_pkgid_list(result_path, (char*)tpk_path, NULL, NULL);
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
	char buf[BUF_SIZE] = {0,};

	if (strstr(xml_path, ".xml") == NULL) {
		__make_pkgid_list(result_path, (char*)xml_path, NULL, NULL);
		return;
	}

	pkgid = __find_info_from_xml(xml_path,"package");
	if (pkgid !=  NULL) {
		/*make csc pkgid list*/
		__make_pkgid_list(result_path, pkgid, NULL, NULL);
		free(pkgid);
		return;
	}
	memset(buf, 0x00, BUF_SIZE);

}

static int __find_uninstalled_pkg(const char *xml_name)
{
	int ret = 0;
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};
	char *csc_pkgid = NULL;

	if(xml_name == NULL) {
		_LOG("xml_name is null\n");
		return ret;
	}

	fp = fopen(CSC_PKGID_LIST_FILE, "r");
	if (fp == NULL) {
//		_LOG("Fail get : %s\n", CSC_PKGID_LIST_FILE);
		return ret;
	}

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		csc_pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		if(csc_pkgid == NULL) {
			_LOG("pkgid is null\n");
			memset(buf, 0x00, BUF_SIZE);
			continue;
		}

		if(strstr(xml_name, csc_pkgid) != NULL) {
			_LOG("xml_name[%s] is already processed by csc \n", xml_name);
			free(csc_pkgid);
			ret = -1;
			break;
		}

		free(csc_pkgid);
		memset(buf, 0x00, BUF_SIZE);
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
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
		_LOG("Make fota pkgid success!! \n");
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
	const char *fota__mv_argv[] = { "/bin/mv", FOTA_PKGMGR_DB_FILE, OPT_DBSPACE_PATH, NULL };
	ret = initdb_xsystem(fota__mv_argv);
	if (ret < 0) {
		_LOG("move fota pkgmgr db to dbspace fail.\n");
	}

	/*get pkgid from fota pkgmgr db*/
	ret = __find_preload_pkgid_from_db(RW_FOTA_PKGID_LIST_FILE, is_readonly);
	if (ret < 0) {
		_LOG("__find_preload_pkgid_from_db fail.\n");
	} else {
		_LOG("Make fota pkgid success!! \n");
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

	const char *argv_parser[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKGMGR_DB, NULL };
	initdb_xsystem(argv_parser);
	const char *argv_parserjn[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKGMGR_DB_JOURNAL, NULL };
	initdb_xsystem(argv_parserjn);
}

static void __get_pkgid_list_from_csc()
{
	int cnt = 0;
	int count = 0;

	char *pkgtype = NULL;
	char *des = NULL;
	char *path = NULL;

	char type_buf[BUF_SIZE] = { 0 };
	char des_buf[BUF_SIZE] = { 0 };
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
		snprintf(type_buf, BUF_SIZE - 1, "csc packages:type_%03d", cnt);
		snprintf(des_buf, BUF_SIZE - 1, "csc packages:description_%03d", cnt);

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

#ifdef _FOTA_INIT_DB

static void __get_uninstalled_pkgid_list_from_csc()
{
	int cnt = 0;
	int count = 0;

	char *pkgtype = NULL;
	char *des = NULL;
	char *path = NULL;

	char type_buf[BUF_SIZE] = { 0 };
	char des_buf[BUF_SIZE] = { 0 };
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
		snprintf(type_buf, BUF_SIZE - 1, "csc packages:type_%03d", cnt);
		snprintf(des_buf, BUF_SIZE - 1, "csc packages:description_%03d", cnt);

		/*parse csc description and type*/
		pkgtype = iniparser_getstr(csc, type_buf);
		des = iniparser_getstr(csc, des_buf);

		if ((pkgtype == NULL) || (des == NULL)) {
			continue;
		}

		if (strstr(des, "op=uninstall") != NULL) {
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
	}
	__make_pkgid_list(CSC_PKGID_LIST_FILE, "org.tizen.joyn", NULL, NULL);

end:
	iniparser_freedict(csc);
}

static void __initdb_load_directory(const char *directory)
{
	DIR *dir;
	struct dirent entry, *result;
	int ret;
	char buf[BUF_SIZE];

	dir = opendir(directory);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			_LOG("Failed to access the [%s] because %s \n", directory, buf);
		return;
	}

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {

		if (!strcmp(entry.d_name, ".") || !strcmp(entry.d_name, "..")) {
			continue;
		}

		if (!strstr(entry.d_name, ".xml")) {
			continue;
		}

		if (__find_uninstalled_pkg(entry.d_name) < 0) {
			continue;
		}

		snprintf(buf, sizeof(buf), "%s/%s", directory, entry.d_name);

		const char *pkginfo_argv[] = { "/usr/bin/pkginfo", "--imd", buf, NULL };
		initdb_xsystem(pkginfo_argv);
	}

	closedir(dir);
}

static void __change_preload_attribute(const char *file_path)
{
	int ret = 0;
	FILE *fp = NULL;
	char buf[BUF_SIZE] = {0};
	char *pkgid = NULL;

	fp = fopen(file_path, "r");
	if (fp == NULL) {
		return;
	}

	while (fgets(buf, BUF_SIZE, fp) != NULL) {
		__str_trim(buf);

		pkgid = __getvalue(buf, TOKEN_PKGID_STR);
		if(pkgid == NULL) {
			_LOG("pkgid is null\n");
			memset(buf, 0x00, BUF_SIZE);
			continue;
		}

		ret = pkgmgrinfo_pkginfo_set_preload(pkgid, 1);
		if (ret < 0) {
			_LOG("pkgmgrinfo_pkginfo_set_preload[%s] fail.. \n", pkgid);
		} else {
			_LOG("pkgid[%s] set db as preload\n", pkgid);
		}

		free(pkgid);
		memset(buf, 0x00, BUF_SIZE);
	}

	if (fp != NULL)
		fclose(fp);

	return;

}

#endif

static int __make_disabled_list(char *file_path, char *pkgid)
{
	FILE *fp = NULL;

	if ((file_path == NULL) || (pkgid == NULL)) {
		_LOG("invalid argument.\n");
		return -1;
	}

	fp = fopen(file_path, "a+");
	if (fp == NULL) {
		_LOG("fopen is failed.\n");
		return -1;
	}

	fprintf(fp, "%s\n", pkgid);
	fclose(fp);

	return 0;
}

static int __pkg_disabled_list_cb(const pkgmgrinfo_pkginfo_h handle, void *file_path)
{
	int ret = 0;
	char *pkgid = NULL;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_get_pkgid is failed. pkgid is [%s].\n", pkgid);
		return -1;
	}

	ret = __make_disabled_list((char *)file_path, pkgid);
	if (ret < 0) {
		_LOG("__make_disabled_list is failed. pkgid is [%s].\n", pkgid);
		return -1;
	}

	ret = pkgmgr_parser_enable_pkg(pkgid, NULL);
	if (ret < 0) {
		_LOG("pkgmgr_parser_enable_pkg is failed. pkgid is [%s].\n", pkgid);
		return -1;
	}

	_LOG("pkgid [%s] is enabled.\n", pkgid);

	return ret;
}

static int __get_disabled_list_and_enable()
{
	int ret = 0;
	char *file_path = PKG_DISABLED_LIST_FILE;
	pkgmgrinfo_pkginfo_filter_h handle = NULL;

	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	if (ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_filter_create is failed.\n");
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_filter_add_bool(handle, PMINFO_PKGINFO_PROP_PACKAGE_DISABLE, 1);
	if (ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_filter_add_bool is failed.\n");
		free(handle);
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, __pkg_disabled_list_cb, (void*)file_path);
	if (ret < 0) {
		_LOG("pkgmgrinfo_pkginfo_filter_foreach_pkginfo is failed.\n");
	}

	free(handle);

	return ret;
}

static int __disable_pkg()
{
	int ret = 0;
	FILE *fp = NULL;
	char *file_path = PKG_DISABLED_LIST_FILE;
	char pkgid[BUF_SIZE] = {'\0',};

	fp = fopen(file_path, "r");
	if (fp == NULL) {
		_LOG("fopen is failed.\n");
		return -1;
	}

	while (fscanf(fp, "%s", pkgid) != EOF) {
		ret = pkgmgr_parser_disable_pkg(pkgid, NULL);
		if (ret < 0) {
			_LOG("pkgmgr_parser_disable_pkg is failed. pkgid is [%s].\n", pkgid);
			continue;
		}
		_LOG("pkgid [%s] is disabled.\n", pkgid);
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;
	int rw_fota_enabled = 0;

	long starttime;
	long endtime;
	struct timeval tv;

	xmlInitParser();

	gettimeofday(&tv, NULL);
	starttime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

#ifdef _FOTA_INIT_DB
	int is_readonly = 0;

	/*clean pkgid list file, if it is exit*/
	__remove_pkgid_list();

	_LOG("=======================================================\n");
	_LOG("	               package manager fota\n");
	_LOG("=======================================================\n");

	__find_preload_pkgid_from_db(RW_PKGID_LIST_FILE, is_readonly);

	(void)remove(PKGMGR_DB);

	__get_uninstalled_pkgid_list_from_csc();

	__initdb_load_directory(USR_MANIFEST_DIRECTORY);
	__initdb_load_directory(OPT_MANIFEST_DIRECTORY);

	__change_preload_attribute(RW_PKGID_LIST_FILE);

	const char *argv_parser[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKGMGR_DB, NULL };
	initdb_xsystem(argv_parser);
	const char *argv_parserjn[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKGMGR_DB_JOURNAL, NULL };
	initdb_xsystem(argv_parserjn);

#else
	/*clean pkgid list file, if it is exit*/
	__remove_pkgid_list();

	_LOG("=======================================================\n");
	_LOG("	            Get disabled list and enable\n");
	_LOG("=======================================================\n");

	ret = __get_disabled_list_and_enable();
	if (ret < 0) {
		_LOG("__get_disabled_list_and_enable is failed.\n");
	}

	_LOG("=======================================================\n");
	_LOG("	               RO preload package fota\n");
	_LOG("=======================================================\n");

	/*get pkgid from orginal pkgmgr db*/
	__get_pkgid_list_from_db_and_xml();

	/*get pkgid from csc applist*/
	__get_pkgid_list_from_csc();

	_LOG("Ready RO pkgid list for compare\n");

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

	_LOG("End RO pkgid list for compare\n");

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

		_LOG("Ready RW pkgid list for compare\n");

		/*find updated, inserted pkgid*/
		ret = __find_matched_pkgid_from_list(RW_FOTA_PKGID_LIST_FILE, RW_PKGID_LIST_FILE, rw_fota_enabled);
		if (ret < 0) {
			_LOG("__find_matched_pkgid_from_list fail.\n");
		}

		_LOG("End RW pkgid list for compare\n");
	}

	/*clean pkgid list file, if it is exit*/
	//	__remove_pkgid_list();

	ret = pkgmgr_parser_insert_app_aliasid();
	if(ret == -1){
		_LOG("Insert for app-aliasID DB failed");
	}

end:
#endif

	_LOG("=======================================================\n");
	_LOG("	              disabled pkg list\n");
	_LOG("=======================================================\n");

	if (access(PKG_DISABLED_LIST_FILE, R_OK) == 0) {
		ret = __disable_pkg();
		if (ret < 0) {
			_LOG("__disable_pkg is failed.\n");
		}
	} else {
		_LOG("no package to disable.\n");
	}

	gettimeofday(&tv, NULL);
	endtime = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	_LOG("=======================================================\n");
	_LOG("\t\t End fota process[time : %d ms]\n", (int)(endtime - starttime));
	_LOG("=======================================================\n");

	xmlCleanupParser();
	return 0;
}


