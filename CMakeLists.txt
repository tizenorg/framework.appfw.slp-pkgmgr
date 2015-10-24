#
# Copyright (c) 2008 ~ 2010 Samsung Electronics Co., Ltd.
# All rights reserved
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

PROJECT(package-manager C)

SET(VERSION 0.1.68)
SET(VERSION_MAJOR 0)

IF(_APPFW_FEATURE_EXPANSION_PKG_INSTALL)
        ADD_DEFINITIONS("-D_APPFW_FEATURE_EXPANSION_PKG_INSTALL")
ENDIF(_APPFW_FEATURE_EXPANSION_PKG_INSTALL)
IF(_APPFW_FEATURE_DELTA_UPDATE)
        ADD_DEFINITIONS("-D_APPFW_FEATURE_DELTA_UPDATE")
ENDIF(_APPFW_FEATURE_DELTA_UPDATE)

IF(_APPFW_FEATURE_MOUNT_INSTALL)
        ADD_DEFINITIONS("-D_APPFW_FEATURE_MOUNT_INSTALL")
ENDIF(_APPFW_FEATURE_MOUNT_INSTALL)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")


set(CMAKE_SKIP_BUILD_RPATH true)

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/comm )

INCLUDE(FindPkgConfig)
IF(_APPFW_FEATURE_DRM_ENABLE)
pkg_check_modules(pkgs REQUIRED security-server dlog pkgmgr-info pkgmgr-parser iniparser vconf minizip xdgmime drm-service-core-tizen)
ELSE(_APPFW_FEATURE_DRM_ENABLE)
pkg_check_modules(pkgs REQUIRED security-server dlog pkgmgr-info pkgmgr-parser iniparser vconf minizip xdgmime)
ENDIF(_APPFW_FEATURE_DRM_ENABLE)


FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)
IF(_APPFW_FEATURE_DRM_ENABLE)
pkg_check_modules(libpkgs REQUIRED dbus-glib-1 dlog pkgmgr-info pkgmgr-parser iniparser security-server vconf minizip xdgmime vasum db-util drm-service-core-tizen)
ELSE(_APPFW_FEATURE_DRM_ENABLE)
pkg_check_modules(libpkgs REQUIRED dbus-glib-1 dlog pkgmgr-info pkgmgr-parser iniparser security-server vconf minizip xdgmime vasum db-util)
ENDIF(_APPFW_FEATURE_DRM_ENABLE)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(pm_dir "${CMAKE_SOURCE_DIR}")
SET(pm_inc_dir "${pm_dir}/include")
SET(pm_c_src_dir "${pm_dir}/client/src")
SET(pm_c_inc_dir "${pm_dir}/client/include")
SET(pm_t_inc_dir "${pm_dir}/types/include")

## About debug
SET(debug_type "-DPM_CONSOLE_USE") 		# for debug - use console window

## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

IF(_APPFW_FEATURE_DRM_ENABLE)
	ADD_DEFINITIONS("-D_APPFW_FEATURE_DRM_ENABLE")
ENDIF(_APPFW_FEATURE_DRM_ENABLE)

##################
## build comm libraries
add_subdirectory(comm)
add_subdirectory(types)

###################################################################################################
## for libpkgmgr-client.so (library)
SET(PKGMGR_CLIENT "pkgmgr-client")
SET(libpkgmgr-client_SOURCES ${pm_c_src_dir}/pkgmgr-internal.c ${pm_c_src_dir}/pkgmgr.c)
SET(libpkgmgr-client_LDFLAGS " -module -avoid-version ")
SET(libpkgmgr-client_CFLAGS  " ${CFLAGS} -fPIC -I${pm_c_inc_dir} -I${pm_inc_dir} -I${pm_t_inc_dir} ${debug_type}")

ADD_LIBRARY(${PKGMGR_CLIENT} SHARED ${libpkgmgr-client_SOURCES})
SET_TARGET_PROPERTIES(${PKGMGR_CLIENT} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${PKGMGR_CLIENT} PROPERTIES VERSION ${VERSION})
SET_TARGET_PROPERTIES(${PKGMGR_CLIENT} PROPERTIES COMPILE_FLAGS "${libpkgmgr-client_CFLAGS}")
TARGET_LINK_LIBRARIES(${PKGMGR_CLIENT} pkgmgr_installer_client pkgmgr_installer_status_broadcast_server pkgmgr-info ${libpkgs_LDFLAGS})
###################################################################################################

CONFIGURE_FILE(pkgmgr.pc.in pkgmgr.pc @ONLY)
configure_file(pkg_path.conf.in pkg_path.conf @ONLY)

#INSTALL(FILES ${CMAKE_BINARY_DIR}/libpkgmgr-client.so DESTINATION lib)
INSTALL(TARGETS ${PKGMGR_CLIENT} DESTINATION lib COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr.pc DESTINATION lib/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/client/include/package-manager.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/client/include/package-manager-zone.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkg_path.conf DESTINATION ${PREFIX}/etc/package-manager/)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/package-manager-debug.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/package-manager-internal.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/types/include/package-manager-plugin.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/types/include/package-manager-types.h DESTINATION include)

####################################################################################################
# i18n
