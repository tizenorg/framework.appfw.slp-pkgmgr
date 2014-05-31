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

#include <pkgmgr_parser.h>
#include <pkgmgr-info.h>

#define OWNER_ROOT 0
#define GROUP_MENU 6010
#define BUFSZE 1024
#define OPT_MANIFEST_DIRECTORY "/opt/share/packages"
#define USR_MANIFEST_DIRECTORY "/usr/share/packages"
#define PACKAGE_INFO_DB_FILE "/opt/dbspace/.pkgmgr_parser.db"

#define PKG_PARSER_DB_FILE "/opt/dbspace/.pkgmgr_parser.db"
#define PKG_PARSER_DB_FILE_JOURNAL "/opt/dbspace/.pkgmgr_parser.db-journal"
#define PKG_CERT_DB_FILE "/opt/dbspace/.pkgmgr_cert.db"
#define PKG_CERT_DB_FILE_JOURNAL "/opt/dbspace/.pkgmgr_cert.db-journal"
#define PKG_INFO_DB_LABEL "pkgmgr::db"

#define TOKEN_TYPE_STR	"type="
#define TOKEN_PKGID_STR	"package="

#define SEPERATOR_START		'"'
#define SEPERATOR_END		'"'

#ifdef _E
#undef _E
#endif
#define _E(fmt, arg...) fprintf(stderr, "[PKG_INITDB][E] "fmt"\n", ##arg);

#ifdef _D
#undef _D
#endif
#define _D(fmt, arg...) fprintf(stderr, "[PKG_INITDB][D] "fmt"\n", ##arg);

static int initdb_count_package(void)
{
	int total = 0;

	return total;
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


char* _manifest_to_package(const char* manifest)
{
	char *package;

	if(manifest == NULL)
		return NULL;

	package = strdup(manifest);
	if(package == NULL)
		return NULL;


	if (!strstr(package, ".xml")) {
		_E("%s is not a manifest file", manifest);
		free(package);
		return NULL;
	}

	return package;
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

static char * getvalue(const char* pBuf, const char* pKey)
{
	const char* p = NULL;
	const char* pStart = NULL;
	const char* pEnd = NULL;

	p = strstr(pBuf, pKey);
	if (p == NULL)
		return NULL;

	pStart = p + strlen(pKey) + 1;
	pEnd = strchr(pStart, SEPERATOR_END);
	if (pEnd == NULL)
		return false;

	size_t len = pEnd - pStart;
	if (len <= 0)
		return false;

	char *pRes = (char*)malloc(len + 1);
	strncpy(pRes, pStart, len);
	pRes[len] = 0;

	return pRes;
}

static int __find_rpm_manifest(const char* manifest)
{
	FILE *fp = NULL;
	char buf[BUFSZE] = {0};
	char *pkgtype = NULL;

	fp = fopen(manifest, "r");
	if (fp == NULL)	{
		_D("Fail get : %s", manifest);
		return -1;
	}

	while (fgets(buf, BUFSZE, fp) != NULL) {
		__str_trim(buf);

		pkgtype = getvalue(buf, TOKEN_TYPE_STR);
		if (pkgtype != NULL) {
			if ((strcmp(pkgtype,"tpk") == 0) || (strcmp(pkgtype,"wgt") == 0)) {
				fclose(fp);
				free(pkgtype);
				return -1;
			}
			free(pkgtype);
		}
		memset(buf, 0x00, BUFSZE);
	}

	if (fp != NULL)
		fclose(fp);

	return 0;
}

static char *__find_rpm_pkgid(const char* manifest)
{
	FILE *fp = NULL;
	char buf[BUFSZE] = {0};
	char *pkgid = NULL;

	fp = fopen(manifest, "r");
	if (fp == NULL)	{
		_D("Fail get : %s", manifest);
		return NULL;
	}

	while (fgets(buf, BUFSZE, fp) != NULL) {
		__str_trim(buf);

		pkgid = getvalue(buf, TOKEN_PKGID_STR);
		if (pkgid !=  NULL) {
			fclose(fp);
			return pkgid;
		}
		memset(buf, 0x00, BUFSZE);
	}

	if (fp != NULL)
		fclose(fp);

	return NULL;
}

static int __check_time(long privous_time)
{
	long current_time;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	current_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

	return (int)(current_time - privous_time);
}

int initdb_install_corexml(const char *directory)
{
	DIR *dir;
	struct dirent entry, *result;
	int ret;
	char buf[BUFSZE];

	int spend_time = 0;
	int corexml_time = 0;
	int smack_time = 0;
	int prlivielge_time = 0;
	int pkg_cnt = 0;

	long check_time;
	struct timeval tv;

	dir = opendir(directory);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			_E("Failed to access the [%s] because %s", directory, buf);
		return -1;
	}

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {
		char *manifest;
		char *pkgid;

		if (entry.d_name[0] == '.') continue;

		manifest = _manifest_to_package(entry.d_name);
		if (!manifest) {
			_E("Failed to convert file to xml[%s]", entry.d_name);
			continue;
		}

		snprintf(buf, sizeof(buf), "%s/%s", directory, manifest);

		ret = pkgmgr_parser_check_manifest_validation(buf);
		if (ret < 0) {
			_E("manifest validation failed : %s", buf);
			free(manifest);
			continue;
		}

		ret = __find_rpm_manifest(buf);
		if (ret < 0) {
			free(manifest);
			continue;
		}

		pkg_cnt++;

		gettimeofday(&tv, NULL);
		check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

		const char *corexml_argv[] = { "/usr/bin/rpm-backend", "-k", "core-xml", "-s", buf, NULL };
		initdb_xsystem(corexml_argv);

		spend_time = __check_time(check_time);
		_D("Install corexml : %s done[time:%d ms]", manifest, spend_time);
		corexml_time += spend_time;

		free(manifest);

		pkgid = __find_rpm_pkgid(buf);
		if(pkgid == NULL) {
			_D("pkgid is NULL in %s", buf);
			continue;
		}

		gettimeofday(&tv, NULL);
		check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

		const char *rpmsmack_argv[] = { "/usr/bin/rpm-backend", "-k", "rpm-smack", "-s", pkgid, NULL };
		initdb_xsystem(rpmsmack_argv);

		spend_time = __check_time(check_time);
		_D("Smack pkgid : %s done[time:%d ms]", pkgid, spend_time);
		smack_time += spend_time;

		gettimeofday(&tv, NULL);
		check_time = tv.tv_sec * 1000l + tv.tv_usec / 1000l;

		const char *rpmperm_argv[] = { "/usr/bin/rpm-backend", "-k", "rpm-perm", "-s", pkgid, NULL };
		initdb_xsystem(rpmperm_argv);

		spend_time = __check_time(check_time);

		_D("Privilege pkgid : %s done[time:%d ms]", pkgid, spend_time);
		prlivielge_time += spend_time;

		free(pkgid);
	}

	closedir(dir);

	_D("================================================================");
	_D("Package-Manager DB initialize for Core xml[%s]", directory);
	_D("RPM package cnt       : %d", pkg_cnt);
	_D("Time for DB Init      : %d  sec", corexml_time / 1000);
	_D("Time for SMACK        : %d  sec", smack_time / 1000);
	_D("Time for Privilele    : %d  sec", prlivielge_time / 1000);
	_D("Time for Toal process : %d  sec", (corexml_time+smack_time+prlivielge_time) / 1000);
	_D("================================================================");

	return 0;
}

int initdb_load_directory(const char *directory)
{
	DIR *dir;
	struct dirent entry, *result;
	int ret;
	char buf[BUFSZE];
	int total_cnt = 0;
	int ok_cnt = 0;

	// desktop file
	dir = opendir(directory);
	if (!dir) {
		if (strerror_r(errno, buf, sizeof(buf)) == 0)
			_E("Failed to access the [%s] because %s", directory, buf);
		return -1;
	}

	_D("Loading manifest files from %s", directory);

	for (ret = readdir_r(dir, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dir, &entry, &result)) {
		char *manifest;

		if (entry.d_name[0] == '.') continue;
		total_cnt++;

		manifest = _manifest_to_package(entry.d_name);
		if (!manifest) {
			_E("Failed to convert file to xml[%s]", entry.d_name);
			continue;
		}

		snprintf(buf, sizeof(buf), "%s/%s", directory, manifest);

		ret = pkgmgr_parser_check_manifest_validation(buf);
		if (ret < 0) {
			_E("manifest validation failed : %s", buf);
			free(manifest);
			continue;
		}

		/*temporarily fixed due to glib abort */
		const char *pkginfo_argv[] = { "/usr/bin/pkginfo", "--imd", buf, NULL };
		initdb_xsystem(pkginfo_argv);

#if 0
		ret = pkgmgr_parser_parse_manifest_for_installation(buf, NULL);
		if (ret < 0) {
			_E("Failed to add a xml[%s]", buf);
		} else {
			ok_cnt++;
		}
#endif
		free(manifest);
	}

//	_D("Package-XML process : Success [%d], fail[%d], total[%d] \n", ok_cnt, total_cnt-ok_cnt, total_cnt);
	closedir(dir);

	return 0;
}



static int initdb_change_perm(const char *db_file)
{
	char buf[BUFSZE];
	char journal_file[BUFSZE];
	char *files[3];
	int ret, i;

	files[0] = (char *)db_file;
	files[1] = journal_file;
	files[2] = NULL;

	if(db_file == NULL)
		return -1;

	snprintf(journal_file, sizeof(journal_file), "%s%s", db_file, "-journal");

	for (i = 0; files[i]; i++) {
		ret = chown(files[i], OWNER_ROOT, OWNER_ROOT);
		if (ret == -1) {
			strerror_r(errno, buf, sizeof(buf));
			_E("FAIL : chown %s %d.%d, because %s", db_file, OWNER_ROOT, OWNER_ROOT, buf);
			return -1;
		}

		ret = chmod(files[i], S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		if (ret == -1) {
			strerror_r(errno, buf, sizeof(buf));
			_E("FAIL : chmod %s 0664, because %s", db_file, buf);
			return -1;
		}
	}

	return 0;
}

static int initdb_update_preload_info()
{
	if (pkgmgr_parser_parse_manifest_for_preload() == -1) {
		_E("pkgmgr_parser_parse_manifest_for_preload fail.");
		return -1;
	}
	return 0;
}
static int __is_authorized()
{
	/* pkg_init db should be called by as root privilege. */

	uid_t uid = getuid();
	if ((uid_t) 0 == uid)
		return 1;
	else
		return 0;
}


int main(int argc, char *argv[])
{
	int ret;
	time_t start_time;
	time_t end_time;

	if (!__is_authorized()) {
		_E("You are not an authorized user!\n");
		return -1;
	}

	time(&start_time);

	ret = initdb_count_package();
	if (ret > 0) {
		_D("Some Packages in the Package Info DB.");
		return 0;
	}

	if (argv[1] == NULL) {
		ret = initdb_install_corexml(USR_MANIFEST_DIRECTORY);
		if (ret == -1) {
			_E("cannot load usr manifest directory.");
		}
		ret = initdb_install_corexml(OPT_MANIFEST_DIRECTORY);
		if (ret == -1) {
			_E("cannot load opt manifest directory.");
		}
	} else if (strcmp(argv[1],"all") == 0) {
		ret = initdb_load_directory(USR_MANIFEST_DIRECTORY);
		if (ret == -1) {
			_E("cannot load usr manifest directory for all ");
		}

		ret = initdb_load_directory(OPT_MANIFEST_DIRECTORY);
		if (ret == -1) {
			_E("cannot load opt manifest directory for all ");
		}
	} else {
		_E("Wrong pkg_initdb cmd args");
		return 0;
	}

	ret = initdb_change_perm(PACKAGE_INFO_DB_FILE);
	if (ret == -1) {
		_E("cannot chown.");
	}

	ret = initdb_update_preload_info();
	if (ret == -1) {
		_E("cannot update preload info.");
	}

	const char *argv_parser[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_PARSER_DB_FILE, NULL };
	initdb_xsystem(argv_parser);
	const char *argv_parserjn[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_PARSER_DB_FILE_JOURNAL, NULL };
	initdb_xsystem(argv_parserjn);
	const char *argv_cert[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_CERT_DB_FILE, NULL };
	initdb_xsystem(argv_cert);
	const char *argv_certjn[] = { "/usr/bin/chsmack", "-a", PKG_INFO_DB_LABEL, PKG_CERT_DB_FILE_JOURNAL, NULL };
	initdb_xsystem(argv_certjn);

	time(&end_time);

	_D("================================================================");
	fprintf(stderr, "[PKG_INITDB][D] Package-Manager initializing start : %s", ctime(&start_time));
	fprintf(stderr, "[PKG_INITDB][D] Package-Manager initializing end   : %s", ctime(&end_time));
	_D("================================================================");

	return 0;
}


