#include <string.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include "pkgmgr_external_storage.h"
#include "comm_config.h"

static const char _PRIVILEGE_NAME[] = "http://tizen.org/privilege/externalstorage.appdata";

static int __package_list_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data);
static int __create_external_directory(const char *pkgid);
static int __set_smack_label_access(const char *path, const char *label);
static int __get_smack_label_access(const char *path, char **label);
static int __set_smack_label_transmute(const char *path, const char *flag);

int _create_external_directory(void)
{
	char ext_base_path[MAX_PATH_LENGTH] = {0, };
	int res = 0;

	strcpy(ext_base_path, EXTERNAL_STORAGE_APP_SPECIFIC_PATH);
	res = mkdir(ext_base_path, 0500);
	if (res == -1 && errno != EEXIST)
	{
		ERR("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
		return -1;
	}

	res = __set_smack_label_access(ext_base_path, "_");
	if (res != 0)
	{
		ERR("__set_smack_label_access() is failed.");
		return -1;
	}

	res = pkgmgrinfo_pkginfo_privilege_filter_foreach(_PRIVILEGE_NAME, __package_list_cb, NULL);
	if (res != PMINFO_R_OK)
	{
		ERR("pkgmgrinfo_pkginfo_privilege_filter_foreach() is failed. error = [%d]", res);
		return -1;
	}

	return 0;
}

static int __package_list_cb(const pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	char *pkgid = NULL;
	int res = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);

	if (res != PMINFO_R_OK)
	{
		ERR("pkgmgrinfo_pkginfo_get_pkgid() is failed. error = [%d]", res);
		return -1;
	}

	dbg("Create external directory. package_id = [%s] privilge_name = [%s]", pkgid, _PRIVILEGE_NAME);
	res = __create_external_directory(pkgid);
	if (res != 0)
	{
		ERR("__create_external_directory() is failed. error = [%d]", res);
		return -1;
	}

	return 0;
}

static int __create_external_directory(const char *pkgid)
{
	char ext_pkg_base_path[MAX_PATH_LENGTH] = {0, };
	char temp_path[MAX_PATH_LENGTH] = {0, };
	char pkg_shared_data_path[MAX_PATH_LENGTH] = {0, };
	char *shared_data_label = NULL;
	int res = 0;

	/* Create directories */
	snprintf(ext_pkg_base_path, MAX_PATH_LENGTH, "%s/%s", EXTERNAL_STORAGE_APP_SPECIFIC_PATH, pkgid);
	res = mkdir(ext_pkg_base_path, 0500);
	if (res == -1 && errno != EEXIST)
	{
		ERR("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
		return -1;
	}

	res = __set_smack_label_access(ext_pkg_base_path, "_");
	if (res != 0)
	{
		ERR("__set_smack_label_access() is failed.");
		return -1;
	}

	memset(temp_path, 0, MAX_PATH_LENGTH);
	strcpy(temp_path, ext_pkg_base_path);
	strncat(temp_path, "/data", strlen("/data"));
	res = mkdir(temp_path, 0700);
	if (res == -1 && errno != EEXIST)
	{
		ERR("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
		return -1;
	}

	res = __set_smack_label_access(temp_path, pkgid);
	if (res != 0)
	{
		ERR("__set_smack_label_access() is failed.");
		return -1;
	}

	memset(temp_path, 0, MAX_PATH_LENGTH);
	strcpy(temp_path, ext_pkg_base_path);
	strncat(temp_path, "/cache", strlen("/cache"));
	res = mkdir(temp_path, 0700);
	if (res == -1 && errno != EEXIST)
	{
		ERR("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
		return -1;
	}

	res = __set_smack_label_access(temp_path, pkgid);
	if (res != 0)
	{
		ERR("__set_smack_label_access() is failed.");
		return -1;
	}

	memset(temp_path, 0, MAX_PATH_LENGTH);
	strcpy(temp_path, ext_pkg_base_path);
	strncat(temp_path, "/shared", strlen("/shared"));
	res = mkdir(temp_path, 0500);
	if (res == -1 && errno != EEXIST)
	{
		ERR("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
		return -1;
	}

	res = __set_smack_label_access(temp_path, "_");
	if (res != 0)
	{
		ERR("__set_smack_label_access() is failed.");
		return -1;
	}

	snprintf(pkg_shared_data_path, MAX_PATH_LENGTH, "%s/%s/%s", APP_ROOT_RW_PATH, pkgid , "shared/data");

	res = access(pkg_shared_data_path, F_OK);
	if (res == 0)
	{
		dbg("Exist shared/data folder (path:[%s])", pkg_shared_data_path);
		res = __get_smack_label_access(pkg_shared_data_path, &shared_data_label);
		if (res != 0)
		{
			ERR("__get_smack_label_access() is failed.");
			return -1;
		}

		strncat(temp_path, "/data", strlen("/data"));
		res = mkdir(temp_path, 0705);
		if (res == -1 && errno != EEXIST)
		{
			ERR("mkdir() is failed. error = [%d] strerror = [%s]", errno, strerror(errno));
			return -1;
		}

		res = __set_smack_label_access(temp_path, shared_data_label);
		if (res != 0)
		{
			ERR("__set_smack_label_access() is failed.");
			return -1;
		}

		res = __set_smack_label_transmute(temp_path, "1");
		if (res != 0)
		{
			ERR("__set_smack_label_transmute() is failed.");
			return -1;
		}
	}
	else if (res == -1 && errno == ENOENT)
	{
		dbg("Directory dose not exist. path: %s, errno: %d (%s)",
				pkg_shared_data_path, errno, strerror(errno));
		return 0;
	}
	else
	{
		ERR("access() failed. path: %s, errno: %d (%s)",
				pkg_shared_data_path, errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int __set_smack_label_access(const char *path, const char *label)
{
	int res = smack_lsetlabel(path, label, SMACK_LABEL_ACCESS);
	if (res != 0)
	{
		ERR("smack set label(%s) failed[%d] (path:[%s]))", label, res, path);
		return -1;
	}
	return 0;
}

static int __get_smack_label_access(const char *path, char **label)
{
	int res = smack_lgetlabel(path, label, SMACK_LABEL_ACCESS);
	if (res != 0)
	{
		ERR("smack get label(%s) failed[%d] (path:[%s]))", label, res, path);
		return -1;
	}
	return 0;
}

static int __set_smack_label_transmute(const char *path, const char *flag)
{
	int res = smack_lsetlabel(path, flag, SMACK_LABEL_TRANSMUTE);
	if (res != 0)
	{
		ERR("smack set label(%s) failed[%d] (path:[%s]))", flag, res, path);
		return -1;
	}
	return 0;
}
