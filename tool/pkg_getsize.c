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
#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>
#include <dbus/dbus.h>

#include "package-manager.h"
#include "package-manager-debug.h"
#include "pkgmgr_installer.h"
#include "comm_config.h"


#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR_GETSIZE"
#endif				/* LOG_TAG */

#define MAX_PKG_INFO_LEN	10
#define MAX_PKG_BUF_LEN	1024
#define BLOCK_SIZE      4096 /*in bytes*/

#define PKG_RW_PATH "/opt/usr/apps/"
#define MAX_PATH_LENGTH 512
#define MAX_LONGLONG_LENGTH 32
#define MAX_SIZE_INFO_SIZE 128

const char* directory_list[4][10] = {
	{ "bin", "info", "res", "info", "data", "shared", "setting", "lib", NULL },
	{ "bin", "info", "res", "info", "shared", "setting", "lib", NULL },
	{ "data", NULL },
	{NULL},
};

void __getsize_send_signal(const char *req_id, const char *pkg_type, const char *pkgid, const char *key, const char *val);

long long __stat_size(struct stat *s)
{
	long long blksize = s->st_blksize;
	long long size = s->st_blocks * 512;

	if (blksize) {
		size = (size + blksize - 1) & (~(blksize - 1));
	}

	return size;
}

long long __calculate_dir_size(int dfd, int depth, int type)
{
	long long size = 0;
	struct stat s;
	DIR *d = NULL;
	struct dirent *de = NULL;
	int i = 0;

	++depth;

	d = fdopendir(dfd);
	if (d == NULL) {
		close(dfd);
		return 0;
	}

	while ((de = readdir(d))) {
		int skip = 0;
		const char *name = de->d_name;
		if (name[0] == '.') {
			if (name[1] == 0)
				continue;
			if ((name[1] == '.') && (name[2] == 0))
				continue;
		}

		if (depth == 1 && de->d_type == DT_DIR) {
			for (i = 0; directory_list[type][i]; i++) {
				if (strcmp(name, directory_list[type][i]) == 0) {
					skip = -1;
					break;
				}
			}

			if (skip == 0)
				continue;
		}

		if (fstatat(dfd, name, &s, AT_SYMLINK_NOFOLLOW) == 0) {
			size += __stat_size(&s);
		}

		if (de->d_type == DT_DIR) {
			int subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0) {
				size += __calculate_dir_size(subfd, depth, type);
			}
			close(subfd);
		}
	}

	closedir(d);
	return size;
}

int __set_attr_info_file()
{
	const char* app_info_label = "*";

	if(lsetxattr(PKG_SIZE_INFO_FILE, "security.SMACK64", app_info_label, strlen(app_info_label), 0)) {
		_LOGE("error(%d) in setting smack label",errno);
		return -1;
	}

	return 0;
}

void __make_sizeinfo_file(char *package_size_info)
{
	FILE* file = NULL;
	int fd = 0;

	if(package_size_info == NULL)
		return;

	file = fopen(PKG_SIZE_INFO_FILE, "w");
	if (file == NULL) {
		_LOGE("Couldn't open the file %s \n", PKG_SIZE_INFO_FILE);
		return;
	}

	fwrite(package_size_info, 1, strlen(package_size_info), file);
	fflush(file);
	fd = fileno(file);
	fsync(fd);
	fclose(file);

	if (__set_attr_info_file() < 0)
		_LOGE("Fail set label file %s \n", PKG_SIZE_INFO_FILE);
}

int __get_size_info(char *pkgid, int *pkg_data_size, int *pkg_total_size)
{
	DIR *dir = NULL;
	int dfd = 0;
	struct stat f_stat;
	struct dirent *de = NULL;

	dir = opendir(PKG_RW_PATH);
	if (dir == NULL) {
		_LOGE("Couldn't open the directory %s \n", PKG_RW_PATH);
		return -1;
	}

	while ((de = readdir(dir)))
	{
		int total_size = 0;
		int others_size = 0;
		int data_size = 0;

		const char *name = de->d_name;
		if (name[0] == '.') {
			if (name[1] == 0)
				continue;
			if ((name[1] == '.') && (name[2] == 0))
				continue;
		}

		if (strcmp(name, pkgid) != 0){
			continue;
		}

		dfd = dirfd(dir);
		if (de->d_type == DT_DIR) {
			int subfd = 0;

			subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0) {
				if (fstat(subfd, &f_stat) == 0)	// pkgid
				{
					others_size += __stat_size(&f_stat);
				}
				others_size += __calculate_dir_size(subfd, 0, 1);
			}
			subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0) {
				int datafd = 0;
				datafd = openat(subfd, "data", O_RDONLY | O_DIRECTORY);
				if (datafd >= 0) {
					if (fstat(datafd, &f_stat) == 0)	// data
					{
						others_size += __stat_size(&f_stat);
					}
					data_size = __calculate_dir_size(datafd, 1, 2);
				}
			}
		}

		total_size = others_size + data_size;
		*pkg_total_size = total_size;
		*pkg_data_size = data_size;
	}
	closedir(dir);
	return 0;
}

typedef enum
{
	STORAGE_TYPE_INTERNAL,
	STORAGE_TYPE_EXTERNAL,
	STORAGE_TYPE_MAX = 255,
} STORAGE_TYPE;

#define APP_BASE_INTERNAL_PATH "/opt/usr/apps/"
#define APP_BASE_EXTERNAL_PATH "/opt/storage/sdcard/apps/"

static long long __calculate_directory_size(int dfd, bool include_itself)
{
	long long size = 0;
	struct stat st;
	int subfd = -1;
	int res = 0;

	if (include_itself)
	{
		res = fstat(dfd, &st);
		if (res < 0)
		{
			_LOGE("fstat() failed, entry: ., errno: %d (%s)", errno, strerror(errno));
			return -1;
		}
		size += __stat_size(&st);
	}

	DIR *dir = fdopendir(dfd);
	if (dir == NULL) {
		_LOGE("fdopendir() failed, errno: %d (%s)", errno, strerror(errno));
		return -1;
	}

	struct dirent *dent = NULL;
	while ((dent = readdir(dir)))
	{
		const char *entry = dent->d_name;
		if (entry[0] == '.')
		{
			if (entry[1] == '\0')
			{
				continue;
			}
			if ((entry[1] == '.') && (entry[2] == '\0'))
			{
				continue;
			}
		}

		if (dent->d_type == DT_DIR)
		{
			subfd = openat(dfd, entry, O_RDONLY | O_DIRECTORY);
			if (subfd < 0)
			{
				_LOGE("openat() failed, entry: %s, errno: %d (%s)", entry, errno, strerror(errno));
				goto error;
			}

			_LOGS("traverse entry: %s", entry);
			size += __calculate_directory_size(subfd, true);
			close(subfd);
		}
		else
		{
			res = fstatat(dfd, entry, &st, AT_SYMLINK_NOFOLLOW);
			if (res < 0)
			{
				_LOGE("fstatat() failed, entry: %s, errno: %d (%s)",entry, errno, strerror(errno));
				goto error;
			}
			size += __stat_size(&st);
		}
	}

	return size;

error:

	return -1;
}

static long long __calculate_shared_dir_size(int dfd, const char *app_root_dir, long long *data_size, long long *app_size)
{
	int fd = -1;
	int subfd = -1;
	long long size = 0;

	_LOGS("traverse path: %sshared", app_root_dir);

	fd = openat(dfd, "shared", O_RDONLY | O_DIRECTORY);
	if (fd < 0)
	{
		_LOGE("openat() failed, path: %sshared, errno: %d (%s)", app_root_dir, errno, strerror(errno));
		return -1;
	}

	struct stat st;
	int res = fstat(fd, &st);
	if (res < 0)
	{
		_LOGE("fstat() failed, path: %sshared, errno: %d (%s)", app_root_dir, errno, strerror(errno));
		goto error;
	}
	*app_size += __stat_size(&st); // shared directory
	_LOGS("app_size: %lld", *app_size);

	_LOGS("traverse path: %sshared/data", app_root_dir);

	subfd = openat(fd, "data", O_RDONLY | O_DIRECTORY);
	if (subfd >= 0)
	{
		size = __calculate_directory_size(subfd, true);
		if (size < 0)
		{
			_LOGE("Calculating shared/data directory failed.");
			goto error;
		}
		*data_size += size;
		_LOGS("data_size: %lld", *data_size);
		close(subfd);
	}
	else if (subfd < 0 && errno != ENOENT)
	{
		_LOGE("openat() failed, entry: data, errno: %d (%s)", errno, strerror(errno));
		goto error;
	}

	_LOGS("traverse path: %sshared/trusted", app_root_dir);

	subfd = openat(fd, "trusted", O_RDONLY | O_DIRECTORY);
	if (subfd >= 0)
	{
		size = __calculate_directory_size(subfd, true);
		if (size < 0)
		{
			_LOGE("Calculating shared/trusted directory failed.");
			goto error;
		}
		*data_size += size;
		_LOGS("data_size: %lld", *data_size);
		close(subfd);
	}
	else if (subfd < 0 && errno != ENOENT)
	{
		_LOGE("openat() failed, entry: trusted, errno: %d (%s)", errno, strerror(errno));
		goto error;
	}

	_LOGS("traverse path: %sshared/res", app_root_dir);

	subfd = openat(fd, "res", O_RDONLY | O_DIRECTORY);
	if (subfd >= 0)
	{
		size = __calculate_directory_size(subfd, true);
		if (size < 0)
		{
			_LOGE("Calculating shared/res directory failed.");
			goto error;
		}
		*app_size += size;
		_LOGS("app_size: %lld", *app_size);
		close(subfd);
	}
	else if (subfd < 0 && errno != ENOENT)
	{
		_LOGE("openat() failed, entry: res, errno: %d (%s)", errno, strerror(errno));
		goto error;
	}

	close(fd);
	return 0;

error:
	if (fd != -1)
	{
		close(fd);
	}
	if (subfd != -1)
	{
		close(subfd);
	}

	return -1;
}

static int __calculate_pkg_size_info(STORAGE_TYPE type, const char *pkgid, long long *data_size, long long *cache_size, long long *app_size)
{
	char app_root_dir[MAX_PATH_LENGTH] = { 0, };
	if (type == STORAGE_TYPE_INTERNAL)
	{
		snprintf(app_root_dir, MAX_PATH_LENGTH, "%s%s/", APP_BASE_INTERNAL_PATH, pkgid);
	}
	else if (type == STORAGE_TYPE_EXTERNAL)
	{
		snprintf(app_root_dir, MAX_PATH_LENGTH, "%s%s/", APP_BASE_EXTERNAL_PATH, pkgid);
	}
	else
	{
		_LOGE("Invalid STORAGE_TYPE");
		return -1;
	}

	DIR *dir = opendir(app_root_dir);
	if (dir == NULL)
	{
		_LOGE("opendir() failed, path: %s, errno: %d (%s)", app_root_dir, errno, strerror(errno));
		return -1;
	}

	int dfd = dirfd(dir);
	int subfd = -1;
	struct stat st;
	int res = fstat(dfd, &st);
	if (res < 0)
	{
		_LOGE("fstat() failed, path: %s, errno: %d (%s)", app_root_dir, errno, strerror(errno));
		goto error;
	}
	*app_size += __stat_size(&st);

	struct dirent *ent = NULL;
	long long size = 0;
	while ((ent = readdir(dir)))
	{
		const char *name = ent->d_name;
		if (name[0] == '.')
		{
			if (name[1] == '\0')
			{
				continue;
			}
			if ((name[1] == '.') && (name[2] == '\0'))
			{
				continue;
			}
		}

		if (ent->d_type == DT_DIR)
		{
			subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0)
			{
				if (strncmp(name, "data", strlen("data")) == 0)
				{
					_LOGS("traverse path: %s%s", app_root_dir, name);
					size = __calculate_directory_size(subfd, false);
					if (size < 0)
					{
						_LOGE("Calculating data directory failed.");
						goto error;
					}
					*data_size += size;
					_LOGS("data_size: %lld", *data_size);
				}
				else if (strncmp(name, "cache", strlen("cache")) == 0)
				{
					_LOGS("traverse path: %s%s", app_root_dir, name);
					size = __calculate_directory_size(subfd, false);
					if (size < 0)
					{
						_LOGE("Calculating cache directory failed.");
						goto error;
					}
					*cache_size += size;
					_LOGS("cache_size: %lld", *cache_size);
				}
				else if (strncmp(name, "shared", strlen("shared")) == 0)
				{
					size = __calculate_shared_dir_size(dfd, app_root_dir, data_size, app_size);
					if (size < 0)
					{
						_LOGE("Calculating shared directory failed.");
						goto error;
					}
					*app_size += size;
					_LOGS("app_size: %lld", *app_size);
				}
				else
				{
					_LOGS("traverse path: %s%s", app_root_dir, name);
					size = __calculate_directory_size(subfd, true);
					if (size < 0)
					{
						_LOGE("Calculating %s directory failed.", name);
						goto error;
					}
					*app_size += size;
					_LOGS("app_size: %lld", *app_size);
				}
			}
			else if (subfd < 0 && errno != ENOENT)
			{
				_LOGE("openat() failed, entry: res, errno: %d (%s)", errno, strerror(errno));
				goto error;
			}
			close(subfd);
		}
	}
	closedir(dir);
	return 0;

error:
	if (dir)
	{
		closedir(dir);
	}
	if (subfd != -1)
	{
		close(subfd);
	}

	return -1;
}

static char *__get_pkg_size_info_str(const pkg_size_info_t* pkg_size_info)
{
	char *size_info_str = (char *)malloc(MAX_SIZE_INFO_SIZE);
	if (size_info_str == NULL)
	{
		_LOGE("Out of memory.");
		return NULL;
	}

	snprintf(size_info_str, MAX_LONGLONG_LENGTH, "%lld", pkg_size_info->data_size);
	strcat(size_info_str, ":");
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH, "%lld", pkg_size_info->cache_size);
	strcat(size_info_str, ":");
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH, "%lld", pkg_size_info->app_size);
	strcat(size_info_str, ":");
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH, "%lld", pkg_size_info->ext_data_size);
	strcat(size_info_str, ":");
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH, "%lld", pkg_size_info->ext_cache_size);
	strcat(size_info_str, ":");
	snprintf(size_info_str + strlen(size_info_str), MAX_LONGLONG_LENGTH, "%lld", pkg_size_info->ext_app_size);
	strcat(size_info_str, ":");

	_LOGS("size_info_str: %s", size_info_str);

	return size_info_str;
}

static void __get_pkg_size_info(const char *pkgid, pkg_size_info_t* pkg_size_info)
{
	int res = __calculate_pkg_size_info(STORAGE_TYPE_INTERNAL, pkgid, &pkg_size_info->data_size, &pkg_size_info->cache_size, &pkg_size_info->app_size);
	if (res < 0)
	{
		_LOGD("Calculating internal package size info failed. res: %d", res);
	}
	_LOGS("size_info: %lld %lld %lld", pkg_size_info->data_size, pkg_size_info->cache_size, pkg_size_info->app_size);

	res = __calculate_pkg_size_info(STORAGE_TYPE_EXTERNAL, pkgid, &pkg_size_info->ext_data_size, &pkg_size_info->ext_cache_size, &pkg_size_info->ext_app_size);
	if (res < 0)
	{
		_LOGD("Calculating external package size info failed. res: %d", res);
	}
	_LOGS("size_info(external): %lld %lld %lld", pkg_size_info->ext_data_size, pkg_size_info->ext_cache_size, pkg_size_info->ext_app_size);
}

static int __get_total_pkg_size_info_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = 0;
	char *pkgid;
	pkg_size_info_t temp_pkg_size_info = {0,};
	pkg_size_info_t *pkg_size_info = (void *)user_data;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if(ret != PMINFO_R_OK) {
		_LOGE("pkgmgr_pkginfo_get_pkgid() failed");
		return -1;
	}

	__get_pkg_size_info(pkgid, &temp_pkg_size_info);

	pkg_size_info->app_size += temp_pkg_size_info.app_size;
	pkg_size_info->data_size += temp_pkg_size_info.data_size;
	pkg_size_info->cache_size += temp_pkg_size_info.cache_size;
	pkg_size_info->ext_app_size += temp_pkg_size_info.ext_app_size;
	pkg_size_info->ext_data_size += temp_pkg_size_info.ext_data_size;
	pkg_size_info->ext_cache_size += temp_pkg_size_info.ext_cache_size;

	return 0;
}

static int __get_total_pkg_size_info(pkg_size_info_t* pkg_size_info)
{
	int res = pkgmgrinfo_pkginfo_get_list(__get_total_pkg_size_info_cb, pkg_size_info);
	if (res != PMINFO_R_OK)
	{
		return -1;
	}
	return 0;
}

static void __send_signal(const char *pkgid, int argc, char *argv[], char *size_info)
{
	pkgmgr_installer *pi = pkgmgr_installer_new();
	if (pi == NULL)
	{
		_LOGD("Creating the pkgmgr_installer instance failed.");
	}
	else
	{
		pkgmgr_installer_receive_request(pi, argc, argv);
		pkgmgr_installer_send_signal(pi, PKGMGR_INSTALLER_GET_SIZE_KEY_STR, pkgid, "-1", size_info);
		pkgmgr_installer_free(pi);
	}
}

static int __send_signal_for_pkg_size_info(const char *pkgid, int argc, char *argv[])
{
	pkg_size_info_t pkg_size_info = {0,};
	__get_pkg_size_info(pkgid, &pkg_size_info);
	char *size_info = __get_pkg_size_info_str(&pkg_size_info);
	if (size_info == NULL)
	{
		return -1;
	}
	__send_signal(pkgid, argc, argv, size_info);
	free(size_info);
	return 0;
}

static int __send_signal_for_total_pkg_size_info(int argc, char *argv[])
{
	pkg_size_info_t pkg_size_info = {0,};
	__get_total_pkg_size_info(&pkg_size_info);
	char *size_info = __get_pkg_size_info_str(&pkg_size_info);
	if (size_info == NULL)
	{
		return -1;
	}
	__send_signal(PKG_SIZE_INFO_TOTAL, argc, argv, size_info);
	free(size_info);
	return 0;
}

int __create_size_info(int argc, char *argv[])
{
	char *package_size_info = NULL;
	int info_len = MAX_PKG_BUF_LEN * MAX_PKG_INFO_LEN;
	pkgmgr_installer *pi;
	char total_buf[MAX_PKG_BUF_LEN] = {'\0'};
	char data_buf[MAX_PKG_BUF_LEN] = {'\0'};

	DIR *dir = NULL;
	int dfd = 0;
	struct stat f_stat;
	struct dirent *de = NULL;

	dir = opendir(PKG_RW_PATH);
	if (dir == NULL)
	{
		_LOGE("Couldn't open the directory %s \n", PKG_RW_PATH);
		return -1;
	}

	package_size_info = (char*)malloc(info_len);
	memset(package_size_info, 0, info_len);

	pi = pkgmgr_installer_new();
	if (!pi) {
		_LOGD("Failure in creating the pkgmgr_installer object");
		return -1;
	}

	while ((de = readdir(dir)))
	{
		int total_size = 0;
		int others_size = 0;
		int data_size = 0;

		char size_string[128] = {0};
		const char *name = de->d_name;
		if (name[0] == '.') {
			if (name[1] == 0)
				continue;
			if ((name[1] == '.') && (name[2] == 0))
				continue;
		}

		dfd = dirfd(dir);
		if (de->d_type == DT_DIR) {
			int subfd = 0;

			subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0) {
				if (fstat(subfd, &f_stat) == 0)	// root
				{
					others_size += __stat_size(&f_stat);
				}
				others_size += __calculate_dir_size(subfd, 0, 1);
			}
			subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
			if (subfd >= 0) {
				int datafd = 0;
				datafd = openat(subfd, "data", O_RDONLY | O_DIRECTORY);
				if (datafd >= 0) {
					if (fstat(datafd, &f_stat) == 0)	// data
					{
						others_size += __stat_size(&f_stat);
					}
					data_size = __calculate_dir_size(datafd, 1, 2);
				}
			}
		}

		total_size = others_size + data_size;

		/*send size info to client*/
		snprintf(total_buf, MAX_PKG_BUF_LEN - 1, "%d", total_size);
		snprintf(data_buf, MAX_PKG_BUF_LEN - 1, "%d", data_size);

		pkgmgr_installer_receive_request(pi, argc, argv);
		pkgmgr_installer_send_signal(pi, PKGMGR_INSTALLER_GET_SIZE_KEY_STR, name, data_buf, total_buf);

		sprintf(size_string, "%s=%d/%d:", name, total_size, data_size);
		strncat(package_size_info, size_string, info_len);
	}
	closedir(dir);

	pkgmgr_installer_send_signal(pi, PKGMGR_INSTALLER_GET_SIZE_KEY_STR, "get_size", "get_size", "end");
	pkgmgr_installer_free(pi);

	__make_sizeinfo_file(package_size_info);
	if(package_size_info)
		free(package_size_info);

	return 0;
}

static int __pkg_list_cb (const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid;
	int data_size = 0;
	int total_size = 0;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if(ret < 0) {
		_LOGE("pkgmgr_pkginfo_get_pkgid() failed\n");
	}

	ret = __get_size_info(pkgid, &data_size, &total_size);
	if ((ret < 0) || (total_size < 0))
		return -1;

	* (int *) user_data += total_size;
	return 0;
}

void __make_size_info_file(char *req_key, int size)
{
	int ret = 0;
	FILE* file = NULL;
	int fd = 0;
	char buf[MAX_PKG_BUF_LEN] = {0};
	const char* app_info_label = "*";
	char info_file[MAX_PKG_BUF_LEN] = {'\0', };

	if(req_key == NULL)
		return;

	snprintf(info_file, MAX_PKG_BUF_LEN, "%s/%s", PKG_SIZE_INFO_PATH, req_key);
	_LOGE("File path = %s\n", info_file);

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

void __getsize_send_signal(const char *req_id, const char *pkg_type, const char *pkgid, const char *key, const char *val)
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
	}
	if (NULL == conn) {
		_LOGE("conn is NULL");
		return;
	}

	msg = dbus_message_new_signal(COMM_STATUS_BROADCAST_DBUS_GET_SIZE_PATH, COMM_STATUS_BROADCAST_DBUS_GET_SIZE_INTERFACE, COMM_STATUS_BROADCAST_EVENT_GET_SIZE);
	if (NULL == msg) {
		_LOGE("msg is NULL");
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

static int __send_sizeinfo_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	int ret = -1;
	char *pkgid;
	int data_size = 0;
	int total_size = 0;

	char total_buf[MAX_PKG_BUF_LEN] = {'\0'};
	char data_buf[MAX_PKG_BUF_LEN] = {'\0'};

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if(ret < 0) {
		_LOGE("pkgmgr_pkginfo_get_pkgid() failed\n");
	}

	ret = __get_size_info(pkgid, &data_size, &total_size);

	/*send size info to client*/
	snprintf(total_buf, MAX_PKG_BUF_LEN - 1, "%d", total_size);
	snprintf(data_buf, MAX_PKG_BUF_LEN - 1, "%d", data_size);

	__getsize_send_signal(PKGMGR_INSTALLER_GET_SIZE_KEY_STR, PKGMGR_INSTALLER_GET_SIZE_KEY_STR, pkgid, data_buf, total_buf);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = -1;
	int data_size = 0;
	int total_size = 0;
	int get_type = 0;
	char *pkgid = NULL;
	char *req_key = NULL;

	char data_buf[MAX_PKG_BUF_LEN] = {'\0'};
	char total_buf[MAX_PKG_BUF_LEN] = {'\0'};
	pkgmgr_installer *pi = NULL;

	// argv has bellowed meaning
	// argv[0] = pkgid
	// argv[1] = get type
	// argv[2] = req_key

	if(argv[0] == NULL) {
		_LOGE("pkgid is NULL\n");
		return -1;
	}

	pkgid = argv[0];
	get_type = atoi(argv[1]);

	_LOGD("start get size : [pkgid = %s, request type = %d] \n", pkgid, get_type);

	if (get_type == PM_GET_SIZE_INFO) {
		ret = pkgmgrinfo_pkginfo_get_list(__send_sizeinfo_cb, NULL);
		__getsize_send_signal(PKGMGR_INSTALLER_GET_SIZE_KEY_STR, PKGMGR_INSTALLER_GET_SIZE_KEY_STR, "get_size", "get_size", "end");
	} else if (get_type == PM_GET_ALL_PKGS) {
		ret = pkgmgrinfo_pkginfo_get_list(__pkg_list_cb, &total_size);
	} else if (get_type == PM_GET_SIZE_FILE) {
		ret = __create_size_info(argc, argv);
	} else if (get_type == PM_GET_PKG_SIZE_INFO) {
		int res = __send_signal_for_pkg_size_info(pkgid, argc, argv);
		if (res < 0) {
			_LOGE("Sending signal for package size info failed.");
			return -1;
		}
	} else if (get_type == PM_GET_TOTAL_PKG_SIZE_INFO) {
		int res = __send_signal_for_total_pkg_size_info(argc, argv);
		if (res < 0) {
			_LOGE("Failed to get the total size information of all the pacakges.");
			return -1;
		}
	} else {
		ret = __get_size_info(pkgid, &data_size, &total_size);
	}

	if (get_type != PM_GET_SIZE_INFO && get_type != PM_GET_PKG_SIZE_INFO) {
		pi = pkgmgr_installer_new();
		if (!pi) {
			_LOGD("Failure in creating the pkgmgr_installer object");
		} else {
			snprintf(data_buf, MAX_PKG_BUF_LEN - 1, "%d", data_size);
			snprintf(total_buf, MAX_PKG_BUF_LEN - 1, "%d", total_size);
			pkgmgr_installer_receive_request(pi, argc, argv);
			pkgmgr_installer_send_signal(pi, PKGMGR_INSTALLER_GET_SIZE_KEY_STR, pkgid, data_buf, total_buf);
			pkgmgr_installer_free(pi);
		}
//		__getsize_send_signal(PKGMGR_INSTALLER_GET_SIZE_KEY_STR, PKGMGR_INSTALLER_GET_SIZE_KEY_STR, pkgid, data_buf, total_buf);
	}

	req_key = (char *)calloc(strlen(argv[2])+1, sizeof(char));
	if(req_key == NULL)
		return -1;
	strncpy(req_key, argv[2], strlen(argv[2]));

	if (strncmp(req_key, pkgid, strlen(pkgid)) == 0) {
		_LOGD("make a file for sync request [pkgid = %s] \n", pkgid);
		__make_size_info_file(req_key , total_size);
	}

	_LOGD("finish get size : [result = %d] \n", ret);

	free(req_key);
	return 0;
}
