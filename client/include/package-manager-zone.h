#ifndef __PACKAGE_MANAGER_ZONE_H__
#define __PACKAGE_MANAGER_ZONE_H__

#include <package-manager.h>

#ifdef __cplusplus
extern "C" {
#endif

/* APIs for zone-feature */

int pkgmgr_client_listen_status_with_zone(pkgmgr_client *pc,
		pkgmgr_handler_with_zone event_cb, void *data);

char *_zone_get_type_from_zip(const char *filename, const char *zone);

#ifdef __cplusplus
}
#endif
#endif /* __PACKAGE_MANAGER_ZONE_H__ */
