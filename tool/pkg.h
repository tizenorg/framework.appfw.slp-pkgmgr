#ifndef _PKG_H_
#define _PKG_H_

#include <stdio.h>
#include <stdlib.h>
#include "package-manager-types.h"

#define PKG_TOOL_VERSION	"1.0.0"

#define BUF_SIZE 1024

#define OPT_DBSPACE_PATH			"/opt/dbspace/"
#define PKGMGR_DB					OPT_DBSPACE_PATH".pkgmgr_parser.db"
#define PKGMGR_DB_BACKUP			OPT_DBSPACE_PATH".pkgmgr_parser_b.db"
#define PKGMGR_DB_JOURNAL			OPT_DBSPACE_PATH".pkgmgr_parser.db-journal"
#define PKGMGR_DB_JOURNAL_BACKUP	OPT_DBSPACE_PATH".pkgmgr_parser_b.db-journal"

#define PKGMGR_FOTA_PATH	 		"/opt/usr/data/pkgmgr/fota/"
#define FACTORYRESET_BACKUP_FILE	"/usr/system/RestoreDir/opt.zip"

typedef enum
{
	LIST_REQ,
	INSTALL_REQ,
	UNINSTALL_REQ,
	ENABLE_REQ,
	DISABLE_REQ,
	MOVE_TO_INTERNAL_REQ,
	MOVE_TO_EXTERNAL_REQ,
	LAUNCH_REQ,
	INFO_REQ,
	API_TEST_REQ,
	NONE_REQ,
} pkg_operation_req;

typedef struct pkg_tool_args_t
{
	pkg_operation_req req;

	char path[PKG_NAME_STRING_LEN_MAX];
	char pkgid[PKG_NAME_STRING_LEN_MAX];
	char appid[PKG_NAME_STRING_LEN_MAX];
	char des_path[PKG_NAME_STRING_LEN_MAX];
	char label[PKG_NAME_STRING_LEN_MAX];
	int result;
	bool isListAll;

} pkg_tool_args;

typedef struct {
    int (*func)(pkg_tool_args *args);
} cmdinfo;

#endif // _PKG_H_
