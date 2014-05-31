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

#include "pkgmgr-debug.h"
#include "package-manager.h"
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

char* directory_list[4][10] = { {"bin", "info", "res", "info", "data", "shared", "setting", "lib", NULL},
								{"bin", "info", "res", "info", "shared", "setting", "lib", NULL},
								{"data", NULL},
								NULL };

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

    depth++;

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
            int subfd;

            subfd = openat(dfd, name, O_RDONLY | O_DIRECTORY);
            if (subfd >= 0) {
                size += __calculate_dir_size(subfd, depth, type);
            }
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
			*pkg_total_size = total_size;
			*pkg_data_size = data_size;
    }
    closedir(dir);
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

	if(get_type == PM_GET_SIZE_INFO) {
		ret = pkgmgrinfo_pkginfo_get_list(__send_sizeinfo_cb, NULL);
		__getsize_send_signal(PKGMGR_INSTALLER_GET_SIZE_KEY_STR, PKGMGR_INSTALLER_GET_SIZE_KEY_STR, "get_size", "get_size", "end");
	} else if(get_type == PM_GET_ALL_PKGS) {
		ret = pkgmgrinfo_pkginfo_get_list(__pkg_list_cb, &total_size);
	} else if(get_type == PM_GET_SIZE_FILE) {
		ret = __create_size_info(argc, argv);
	} else {
		ret = __get_size_info(pkgid, &data_size, &total_size);
	}

	if(get_type != PM_GET_SIZE_INFO) {
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
