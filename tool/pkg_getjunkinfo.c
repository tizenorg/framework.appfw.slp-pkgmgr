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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkgmgr-info.h>
#include <vconf.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>
#include <dbus/dbus.h>

#include "package-manager.h"
#include "package-manager-debug.h"
#include "pkgmgr_installer.h"
#include "comm_config.h"
#include "junk-manager.h"
#include <sys/xattr.h>

#include <sqlite3.h>
#include <time.h>
#include "pkg_magic.h"

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR_JUNKINFO"
#endif				/* LOG_TAG */

#define MAX_PATH_LENGTH		1024
#define MAX_PROCESS_NAME	512
#define MAX_QUERY_LEN		4096
#define DB_UTIL_REGISTER_HOOK_METHOD 0x00000001


#define QUERY_CREATE_TABLE_JUNK_ROOT "CREATE TABLE junk_root " \
						"(root_name text, "\
						"category integer, "\
						"root_file_type integer, "\
						"storage_type integer, "\
						"junk_total_size integer, "\
						"root_path text)"

#define QUERY_CREATE_TABLE_JUNK_FILES "CREATE TABLE junk_file "\
						"(root_name text, "\
						"file_name text, "\
						"file_type integer, "\
						"storage_type integer, "\
						"junk_file_size integer, "\
						"file_path text)"

const char *category_list[12] = {
	"Images", "Sounds", "Videos", "Camera", "Downloads",
	"Music", "Documents", "Others", "System", "DCIM", "MISC", NULL
};

const char INTERNAL_STORAGE_PATH[256] = "/opt/usr/media";
const char EXTERNAL_STORAGE_PATH[256] = "/opt/storage/sdcard";

typedef struct __junk_root_info_t{
	char *root_name;
	char *root_path;
	int category;
	int root_file_type;
	int storage_type;
	long long junk_total_size;
} junk_root_info_t;

typedef struct __junk_file_info_t{
	char *file_path;
	char *root_name;
	char *file_name;
	int file_type;
	int storage_type;
	long long junk_file_size;
} junk_file_info_t;


int storage_path_length;

static void __print_usage()
{
	// TODO: print usage
	exit(0);
}

static void __send_signal(int argc, char *argv[], const char *pid_str, const char *key, const char *value)
{
	LOGD("Enter");
	pkgmgr_installer *pi = pkgmgr_installer_new();
	if (pi == NULL) {
		_LOGE("Failed to create the pkgmgr_installer instance.");
		return;
	}
	pkgmgr_installer_receive_request(pi, argc, argv);
	pkgmgr_installer_send_signal(pi, PKGMGR_INSTALLER_GET_JUNK_INFO_KEY_STR, pid_str, key, value);
	pkgmgr_installer_free(pi);
}

static int __db_open(const char *db_file_path, sqlite3 **ppDB, int option)
{
	if ((db_file_path == NULL) || (ppDB == NULL))
	{
		LOGE("%s Invalid input param error", __func__);
		return -1;
	}

	if ((geteuid() != 0) && (access(db_file_path, R_OK)))
	{
		if (errno == EACCES)
		{
			LOGE("%s file access permission error", __func__);
			return -1;
		}
	}

	int res = sqlite3_open(db_file_path, ppDB);
	if (SQLITE_OK != res)
	{
		LOGE("%s sqlite3_open() failed.(%d)", __func__, res);
		return res;
	}

	return res;
}

static int __exec_query(const sqlite3 *db, char *query)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
		sqlite3_exec((sqlite3 *)db, query, NULL, NULL, &error_message))
	{
		LOGE("Don't execute query = %s error message = %s", query, error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __category_name_to_category_number(const char *category)
{
	int i = 0;
	for (i=0; category_list[i]; i++)
	{
		if (strncmp(category, category_list[i], 3) == 0)
		{
			return i;
		}
	}
	return 10;
}

static int __insert_junk_to_junk_root_info_db(const sqlite3 *db, junk_root_info_t *junk_root_info)
{
	int res = 0;
	char *query = NULL;
	sqlite3_stmt *db_stmt = NULL;

	query = sqlite3_mprintf("SELECT junk_total_size, root_path FROM junk_root WHERE root_path='%q'", junk_root_info->root_path);
	if (query == NULL)
	{
		LOGE("unable to allocate enough memory to hold the resulting string");
		return -1;
	}

	res = sqlite3_prepare_v2((sqlite3 *)db, query, strlen(query), &db_stmt, NULL);
	if (SQLITE_OK != res)
	{
		LOGE("sqlite prepare error, res: %d (%s)", res, sqlite3_errmsg((sqlite3 *)db));
		return -1;
	}
	sqlite3_free(query);

	res = sqlite3_step(db_stmt);
	if (SQLITE_ROW == res)
	{
		// update junk_info in junk_root table.
		long long junk_total_size = 0;

		junk_total_size = sqlite3_column_int64(db_stmt, 0);
		junk_total_size += junk_root_info->junk_total_size;

		query = sqlite3_mprintf("UPDATE junk_root SET junk_total_size = %lld WHERE root_path='%s'", junk_total_size, junk_root_info->root_path);
		if (query == NULL)
		{
			LOGE("unable to allocate enough memory to hold the resulting string");
			return -1;
		}
	}
	else if (SQLITE_DONE == res)
	{
		// insert junk_info to junk_root table.
		query = sqlite3_mprintf("INSERT INTO junk_root VALUES('%q', %d, %d, %d, %lld, '%q')",
				junk_root_info->root_name,
				junk_root_info->category,
				junk_root_info->root_file_type,
				junk_root_info->storage_type,
				junk_root_info->junk_total_size,
				junk_root_info->root_path
		);
		if (query == NULL)
		{
			LOGE("unable to allocate enough memory to hold the resulting string");
			return -1;
		}
	}
	else
	{
		LOGE("sqlite step error, res: %d (%s)", res, sqlite3_errmsg((sqlite3 *)db));
		return -1;
	}

	res = __exec_query(db, query);
	if (res < 0)
	{
		LOGE("%s __exec_query() failed.(%d)", __func__, res);
		return -1;
	}

	if (query)
		sqlite3_free(query);

	if (db_stmt)
		sqlite3_finalize(db_stmt);

	return 0;
}

static int __insert_junk_to_junk_files_info_db(const sqlite3 *db, junk_file_info_t *junk_file_info)
{
	int res = 0;
	char query[MAX_QUERY_LEN] = {0,};
	snprintf(query, MAX_QUERY_LEN,
			"insert into junk_file " \
			"values('%s', '%s', %d, %d, %lld, '%s')",
			junk_file_info->root_name,
			junk_file_info->file_name,
			junk_file_info->file_type,
			junk_file_info->storage_type,
			junk_file_info->junk_file_size,
			junk_file_info->file_path
		);

	res = __exec_query(db, query);
	if (res < 0)
	{
		LOGE("%s __exec_query() failed.(%d)", __func__, res);
		return -1;
	}

	return 0;
}


static long long __stat_size(struct stat *s)
{
	long long blksize = s->st_blksize;
	long long size = s->st_blocks * 512;

	if (blksize)
	{
		size = (size + blksize - 1) & (~(blksize - 1));
	}

	return size;
}

static int __get_category_number(const char *file_path)
{
	char *category_name = NULL;
	category_name = (char*)file_path + storage_path_length + 1;

	return __category_name_to_category_number(category_name);
}

static bool __is_junk_file(const char *file_path)
{
	int category_number = 0;
	int mime_number = 0;
	bool ret = false;

	category_number = __get_category_number(file_path);
	mime_number = get_mime_type(file_path);


	switch(category_number)
	{
	case JUNKMGR_CATEGORY_IMAGES:
		if (mime_number != _MIME_IMAGE)
		{
			ret = true;
		}
		break;

	case JUNKMGR_CATEGORY_SOUNDS:
		if (mime_number != _MIME_AUDIO)
		{
			ret = true;
		}
		break;

	case JUNKMGR_CATEGORY_VIDEOS:
		if (mime_number != _MIME_VIDEO)
		{
			ret = true;
		}
		break;

	case JUNKMGR_CATEGORY_CAMERA:
		if ((mime_number != _MIME_IMAGE) && (mime_number != _MIME_VIDEO))
		{
			ret = true;
		}
		break;

	case JUNKMGR_CATEGORY_DOWNLOADS:
		if ((mime_number != _MIME_AUDIO) && (mime_number != _MIME_IMAGE) && (mime_number != _MIME_VIDEO))
		{
			ret = true;
		}
		break;

	case JUNKMGR_CATEGORY_MUSIC:
		if (mime_number != _MIME_AUDIO)
		{
			ret = true;
		}
		break;

	case JUNKMGR_CATEGORY_DOCUMENTS:
		if ((mime_number != _MIME_APPLICATION) && (mime_number != _MIME_TEXT))
		{
			ret = true;
		}
		break;

	case JUNKMGR_CATEGORY_OTHERS:
		ret = true;
		break;

	case JUNKMGR_CATEGORY_SYSTEM_RINGTONES:
		if (mime_number != _MIME_AUDIO)
		{
			ret = true;
		}
		break;

	case JUNKMGR_CATEGORY_DCIM:
		if ((mime_number != _MIME_IMAGE) && (mime_number != _MIME_VIDEO))
		{
			ret = true;
		}
		break;

	case JUNKMGR_CATEGORY_MISC:
		ret = false;
		break;
	}
	if (ret)
		SECURE_LOGI("file_path:%s category_number:%d mime_number:%d", file_path, category_number, mime_number);

	return ret;
}

static char * __get_root_path(junkmgr_storage_type_e storage_type, const char *file_path)
{
	char *temp = NULL;
	char *root_name = NULL;
	char *category_name = NULL;
	char *ptr = NULL;
	int i = 0;

	temp = strdup(file_path + storage_path_length + 1);
	if (temp == NULL) {
		LOGE("temp is NULL");
		return NULL;
	}

	ptr = strtok(temp, "/");

	while (ptr != NULL)
	{
		if (i == 0)
		{
			category_name = strdup(temp);
		}
		else if (i == 1)
		{
			root_name = strdup(ptr);
		}
		else
		{
			break;
		}
		i++;
		ptr = strtok(NULL, "/");
	}

	if (category_name == NULL)
	{
		LOGI("category is null. file_path is %s", file_path);
		free(temp);
		return NULL;
	}

	char root_path[MAX_PATH_LENGTH] = {0,};
	if (root_name == NULL)
	{
		if (storage_type == JUNKMGR_STORAGE_TYPE_INTERNAL)
		{
			sprintf(root_path, "%s/%s", INTERNAL_STORAGE_PATH, category_name);
		}
		else
		{
			sprintf(root_path, "%s/%s", EXTERNAL_STORAGE_PATH, category_name);
		}
	}
	else
	{
		if (storage_type == JUNKMGR_STORAGE_TYPE_INTERNAL)
		{
			sprintf(root_path, "%s/%s/%s", INTERNAL_STORAGE_PATH, category_name, root_name);
		}
		else
		{
			sprintf(root_path, "%s/%s/%s", EXTERNAL_STORAGE_PATH, category_name, root_name);
		}
	}

	free(temp);
	free(root_name);
	free(category_name);

	return strdup(root_path);
}

static char * __search_root_name(const char *file_path)
{
	char *temp = NULL;
	char *root_name = NULL;
	char *category_name = NULL;
	char *ptr = NULL;
	int i = 0;

	temp = strdup(file_path + storage_path_length + 1);
	if (temp == NULL)
	{
		LOGE("temp is NULL");
		return NULL;
	}

	ptr = strtok(temp, "/");

	while (ptr != NULL)
	{
		if (i == 0)
		{
			category_name = strdup(temp);
		}
		else if (i == 1)
		{
			root_name = strdup(ptr);
		}
		else
		{
			break;
		}
		i++;
		ptr = strtok(NULL, "/");
	}

	if (category_name == NULL)
	{
		LOGI("category is null. file_path is %s", file_path);
		free(temp);
		return NULL;
	}
	if (root_name == NULL)
	{
		root_name = strdup(category_name);
	}

	LOGI("category: %s, root_name: %s", category_name, root_name);

	free(category_name);
	free(temp);

	return root_name;
}

static int __search_junk_file(const sqlite3 *db, const char *path, int depth, junkmgr_storage_type_e storage_type)
{
	bool exist_junk = false;
	long long junk_size = 0;

	depth++;

	if (depth == 1)
	{
		storage_path_length = strlen(path);
	}

	DIR *dir = opendir(path);
	if (dir == NULL)
	{
		LOGE("opendir() failed. path: %s, errno: %d (%s)", dir, errno, strerror(errno));
		return -1;
	}

	int dfd = dirfd(dir);

	struct stat st;
	int res = fstat(dfd, &st);
	if (res < 0)
	{
		LOGE("fstat() failed. path: %s, errno: %d (%s)", dir, errno, strerror(errno));
		if (dir)
			closedir(dir);
		return -1;
	}

	struct dirent *dent = NULL;
	while ((dent = readdir(dir)))
	{
		const char *entry = dent->d_name;
		if (entry[0] == '.')
		{
			continue;
		}

		if (dent->d_type == DT_DIR)
		{
			char sub_dir_path[MAX_PATH_LENGTH];
			long long junk_dir_size = 0;
			snprintf(sub_dir_path, MAX_PATH_LENGTH, "%s/%s", path, entry);
			junk_dir_size = __search_junk_file(db, sub_dir_path, depth, storage_type);
			if (junk_dir_size > 0)
			{
				int category_number = 0;
				char *category_name = NULL;
				char *temp = NULL;
				char *root_path = NULL;
				char *root_name = NULL;

				root_path = __get_root_path(storage_type, sub_dir_path);
				if (root_path == NULL)
					continue;

				root_name = __search_root_name(sub_dir_path);
				if (root_name == NULL) {
					free(root_path);
					continue;
				}

				temp = sub_dir_path + storage_path_length + 1;
				category_name = strdup(temp);
				if (category_name == NULL) {
					free(root_name);
					free(root_path);
					continue;
				}

				category_number = __category_name_to_category_number(category_name);

				if (category_number == 10)
				{
					free(category_name);
					free(root_name);
					free(root_path);
					continue;
				}

				junk_root_info_t junk_root_info;
				junk_root_info.root_name = strdup(root_name);
				junk_root_info.root_path = strdup(root_path);
				junk_root_info.category = category_number;
				junk_root_info.root_file_type = 1;
				junk_root_info.storage_type = storage_type;
				junk_root_info.junk_total_size = junk_dir_size;

				SECURE_LOGD("junk_root root_name(%s) root_path(%s) category(%d) root_file_type(%d) storage_type(%d) total_size(%lld)",
						junk_root_info.root_name, junk_root_info.root_path, junk_root_info.category,
						junk_root_info.root_file_type, junk_root_info.storage_type, junk_root_info.junk_total_size);

				__insert_junk_to_junk_root_info_db(db, &junk_root_info);

				exist_junk = true;

				free(category_name);
				free(root_name);
				free(root_path);
				free(junk_root_info.root_name);
				free(junk_root_info.root_path);
			}
		}
		else
		{
			int res = fstatat(dfd, entry, &st, AT_SYMLINK_NOFOLLOW);
			if (res < 0)
			{
				LOGE("fstatat() failed. path: %s, errno: %d (%s)", dir, errno, strerror(errno));
				if (dir)
				{
					closedir(dir);
				}
				return -1;
			}

			char junk_file_path[MAX_PATH_LENGTH];
			char *root_name = NULL;
			snprintf(junk_file_path, MAX_PATH_LENGTH, "%s/%s", path, entry);

			long long size = 0;
			size = __stat_size(&st);

			if ((size < 8192) || (__is_junk_file(junk_file_path)))
			{
				if (depth == 1)
				{
					root_name = strdup(entry);
					if (root_name == NULL)
						continue;;

					junk_root_info_t junk_root_info = {0,};
					junk_root_info.root_name = strdup(root_name);
					junk_root_info.root_path = strdup(junk_file_path);
					junk_root_info.category = 10;
					junk_root_info.root_file_type = 0;
					junk_root_info.storage_type = storage_type;
					junk_root_info.junk_total_size = size;

					SECURE_LOGD("junk_root root_name(%s) root_path(%s) category(%d) root_file_type(%d) storage_type(%d) total_size(%lld)",
							junk_root_info.root_name, junk_root_info.root_path, junk_root_info.category,
							junk_root_info.root_file_type, junk_root_info.storage_type, junk_root_info.junk_total_size);

					__insert_junk_to_junk_root_info_db(db, &junk_root_info);

					free(junk_root_info.root_name);
					free(junk_root_info.root_path);
				}
				else
				{
					root_name = __search_root_name(path);
					if (root_name == NULL)
						continue;
				}

				junk_file_info_t junk_file = {0,};
				junk_file.root_name = strdup(root_name);
				junk_file.file_name = strdup(entry);
				junk_file.file_type = 0;
				junk_file.storage_type = storage_type;
				junk_file.junk_file_size = size;
				junk_file.file_path = strdup(junk_file_path);

				SECURE_LOGD("junk_file root_name(%s) file_name(%s) file_type(%d) storage_type(%d) total_size(%lld) file_path(%s)",
						junk_file.root_name, junk_file.file_name, junk_file.file_type,
						junk_file.storage_type, junk_file.junk_file_size, junk_file.file_path);

				junk_size += size;
				__insert_junk_to_junk_files_info_db(db, &junk_file);

				exist_junk = true;

				free(root_name);
				free(junk_file.root_name);
				free(junk_file.file_name);
				free(junk_file.file_path);
			}
		}
	}
	closedir(dir);

	if (exist_junk)
		return junk_size;
	return 0;
}


static bool __is_exist_process_at_process_list(int pid)
{
	char name[MAX_PROCESS_NAME] = {0,};

	sprintf(name, "/proc/%d/cmdline", pid);
	FILE* fp = fopen(name, "r");
	if (!fp)
	{
		LOGE("%s fopen() failed. ENOPROC", __func__);
		return false;
	}

	fclose(fp);
	return true;
}

static bool __is_exist_junk_cache_file(const char *file_path)
{
	int res = access(file_path, F_OK);
	if (res < 0)
	{
		switch (errno)
		{
			case ENOENT:
				SECURE_LOGI("%s access() failed. file is not existed.(%s)", __func__, file_path);
				return false;

			default:
				LOGE("%s access() failed. path: %s, errno: %d (%s)",__func__, file_path, errno, strerror(errno));
				break;
		}
	}
	return true;
}

static bool __is_valid_junk_cache_file(const char *file_path)
{
	struct stat st = {0,};
	int res = stat(file_path, &st);
	if (res < 0)
	{
		LOGI("stat() failed. path: %s, errno: %d (%s)", file_path, errno, strerror(errno));
		return -1;
	}

	time_t current_time = time(NULL);
	if (current_time == ((time_t)-1))
	{
		LOGD("time() failed. path: %s, errno: %d (%s)", file_path, errno, strerror(errno));
	}

	double diff = difftime(current_time, st.st_mtime);
	LOGD("st_mtime: %d, current_time: %d, diff: %lf", st.st_mtime, current_time, diff);
	if (diff > (60 * 5))
	{
		LOGI("OLD FILE!! DELETE!!");
		return false;
	}

	LOGI("GOOD FILE!! PASS!!");
	return true;
}

static int __set_smack_label_access(const char *file_path, const char *label)
{
	int res = smack_lsetlabel(file_path, label, SMACK_LABEL_ACCESS);
	if (res != 0)
	{
		LOGE("smack set label(%s) failed[%d] (path:[%s]))", label, res, file_path);
	}
	return res;
}

static bool is_need_junk_cache_file(const char *file_path)
{
	int res = 0;
	bool ret = false;

	if (__is_exist_junk_cache_file(file_path))
	{
		if (__is_exist_process_at_process_list(atoi(file_path)))
		{
			if (!__is_valid_junk_cache_file(file_path))
			{
				res = remove(file_path);
				if (res < 0)
				{
					LOGE("%s remove() failed. path: %s, errno: %d (%s)", file_path, errno, strerror(errno));
					return -1;
				}
				ret = true;
			}
		}
		else
		{
			res = remove(file_path);
			if (res < 0)
			{
				LOGE("%s remove() failed. path: %s, errno: %d (%s)", file_path, errno, strerror(errno));
				return -1;
			}
			ret = true;
		}
	}
	else
	{
		ret = true;
	}

	return ret;
}

int create_junk_cache_file(const sqlite3 *db)
{
	int res = __search_junk_file(db, INTERNAL_STORAGE_PATH, 0, JUNKMGR_STORAGE_TYPE_INTERNAL);
	if (res < 0)
	{
		LOGE("%s __serch_junk_file() failed.(%d)", __func__, res);
		return -1;
	}

	res = __search_junk_file(db, EXTERNAL_STORAGE_PATH, 0, JUNKMGR_STORAGE_TYPE_EXTERNAL);
	if (res < 0)
	{
		LOGE("%s __serch_junk_file() failed.(%d)", __func__, res);
		return -1;
	}

	return 0;
}

int clear_all_junk_files(const sqlite3 *db, const char *junk_db_path)
{
	int res = 0;
	int ret = 0;
	char query[512] = "SELECT file_path FROM junk_file";
	sqlite3_stmt *db_stmt = NULL;

	res = sqlite3_prepare_v2((sqlite3 *)db, query, strlen(query), &db_stmt, NULL);
	if (SQLITE_OK != res)
	{
		LOGE("sqlite prepare error, res: %d (%s)", res, sqlite3_errmsg((sqlite3 *)db));
		return -1;
	}

	res = sqlite3_step(db_stmt);
	if (SQLITE_DONE == res)
	{
		LOGI("Not exist junk file");
		if (db_stmt)
			sqlite3_finalize(db_stmt);
	}
	else if (SQLITE_ROW == res)
	{
		// delete junk file.
		char *junk_path = NULL;
		while(SQLITE_ROW == res)
		{
			junk_path = (char*)sqlite3_column_text(db_stmt, 0);
			ret = remove(junk_path);
			if (ret < 0)
			{
				LOGE("remove() failed. path: %s, errno %d (%s)", junk_path, errno, strerror(errno));
				free(junk_path);
				if (db_stmt)
					sqlite3_finalize(db_stmt);

				return ret;
			}
			SECURE_LOGI("Delete junk file :%s", junk_path);
			res = sqlite3_step(db_stmt);
		}

		if (db_stmt)
			sqlite3_finalize(db_stmt);

		// delete junk db file.
		ret = remove(junk_db_path);
		if (ret < 0)
		{
			LOGE("remove() failed. path: %s, errno %d (%s)", junk_db_path, errno, strerror(errno));
			return ret;
		}
	}
	else
	{
		LOGE("sqlite3_step() error, res: %d (%s)", res, sqlite3_errmsg((sqlite3 *)db));
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	LOGD("Enter");

	int c = 0;
	char req_str[256] = {0,};
	char pid_str[7] = {0,};
    char junk_req_type[4] = { 0, };
    char junk_storage[4] = { 0, };
    char junk_path[PATH_MAX] = { 0, };

	while (1) {
		c = getopt(argc, argv, "p:k:t:w:j:");
		if (c == -1)
			break;	/* Parse end */
		switch (c) {
		case 'p':
			if (optarg) strncpy(pid_str, optarg, sizeof(pid_str));
			break;
		case 'k':
			if (optarg) strncpy(req_str, optarg, sizeof(req_str));
			break;
		case 't':
			if (optarg) strncpy(junk_req_type, optarg, sizeof(junk_req_type));
			break;
		case 'w':
			if (optarg) strncpy(junk_storage, optarg, sizeof(junk_storage));
			break;
		case 'j':
			if (optarg) strncpy(junk_path, optarg, sizeof(junk_path));
			break;
		case '?':
			__print_usage();
			break;
		default:
			break;
		}
	}

	int res = 0;

	char *junk_db_path = (char *)calloc(1, MAX_PATH_LENGTH);
	if (junk_db_path == NULL)
	{
		LOGE("out of memory");
		return -1;
	}

	sprintf(junk_db_path, "/tmp/.cache%s.db", pid_str);

	char *junk_db_journal_path = (char *)malloc(PATH_MAX);
	if (junk_db_journal_path == NULL)
	{
		LOGE("out of memory");
		free(junk_db_path);
		return -1;
	}

	strncpy(junk_db_journal_path, junk_db_path, PATH_MAX - 1);
	strcat(junk_db_journal_path , "-journal");

	if (atoi(junk_req_type) == 2)
	{
		sqlite3 *junk_db;

		res = __db_open(junk_db_path, &junk_db, DB_UTIL_REGISTER_HOOK_METHOD);
		if (res < 0)
		{
			LOGE("%s __db_open() failed.(%d)", __func__, res);
			return -1;
		}

		res = clear_all_junk_files(junk_db, junk_db_path);
		if (res < 0)
		{
			LOGE("%s clear_all_junk_files() failed.(%d)", __func__, res);
			free(junk_db_journal_path);
			sqlite3_close(junk_db);
			return -1;
		}

		if (junk_db)
		{
			sqlite3_close(junk_db);
		}
		free(junk_db_journal_path);

		SECURE_LOGI("return db path: %s", junk_db_path);
		__send_signal(argc, argv, pid_str, "dbpath", junk_db_path);
		return 0;
	}

	if (is_need_junk_cache_file(junk_db_path))
	{
		sqlite3 *junk_db;

		res = __db_open(junk_db_path, &junk_db, DB_UTIL_REGISTER_HOOK_METHOD);
		if (res < 0)
		{
			LOGE("%s __db_open() failed.(%d)", __func__, res);
			return -1;
		}

		res = __exec_query(junk_db, QUERY_CREATE_TABLE_JUNK_ROOT);
		if (res < 0)
		{
			LOGE("%s __exec_query() failed.(%d)", __func__, res);
			sqlite3_close(junk_db);
			return -1;
		}
		__exec_query(junk_db, QUERY_CREATE_TABLE_JUNK_FILES);
		if (res < 0)
		{
			LOGE("%s __exec_query() failed.(%d)", __func__, res);
			sqlite3_close(junk_db);
			return -1;
		}

		res = create_junk_cache_file(junk_db);
		if (res < 0)
		{
			LOGE("%s create_junk_cache_file() failed.(%d)", __func__, res);
			sqlite3_close(junk_db);
			return -1;
		}
		if (junk_db)
		{
			sqlite3_close(junk_db);
		}

		res = chmod(junk_db_path, 0644);
		if (res < 0)
		{
			LOGE("chmod() failed. path: %s, errno: %d (%s)", junk_db_path, errno, strerror(errno));
			return -1;
		}

		res = chmod(junk_db_journal_path, 0644);
		if (res < 0)
		{
			LOGE("chmod() failed. path: %s, errno: %d (%s)", junk_db_journal_path, errno, strerror(errno));
			return -1;
		}

		res = chown(junk_db_path, 5000, 5000);
		if (res < 0)
		{
			LOGE("chown() failed. path: %s, errno: %d (%s)", junk_db_path, errno, strerror(errno));
			return -1;
		}

		res = chown(junk_db_journal_path, 5000, 5000);
		if (res < 0)
		{
			LOGE("chown() failed. path: %s, errno: %d (%s)", junk_db_journal_path, errno, strerror(errno));
			return -1;
		}

		res = __set_smack_label_access(junk_db_path, "junkmgr::db");
		if (res < 0)
		{
			LOGE("%s __set_smack_label_access() failed.(%d)", __func__, res);
			return -1;
		}

		res = __set_smack_label_access(junk_db_journal_path, "junkmgr::db");
		if (res < 0)
		{
			LOGE("%s __set_smack_label_access() failed.(%d)", __func__, res);
			return -1;
		}
	}

	free(junk_db_journal_path);

	SECURE_LOGI("return db path: %s", junk_db_path);
	__send_signal(argc, argv, pid_str, "dbpath", junk_db_path);
	return 0;
}
