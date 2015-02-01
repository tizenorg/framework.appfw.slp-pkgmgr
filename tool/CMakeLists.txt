# Test executables
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS}")

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/client/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs_test REQUIRED ecore dbus-1 dlog libxml-2.0 bundle pkgmgr-info pkgmgr-parser vconf iniparser sqlite3 db-util libsmack)
FOREACH(flag ${pkgs_test_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(toolpkgs REQUIRED appcore-efl dlog bundle glib-2.0 pkgmgr-info pkgmgr-parser vconf iniparser)
FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(mkext REQUIRED dlog pkgmgr-info libsmack)
FOREACH(flag ${mkext_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")

add_executable(pkgcmd
		pkg_cmd.c)
target_link_libraries(pkgcmd pkgmgr-client ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkgcmd DESTINATION bin)

add_executable(pkginfo
                pkg_info.c)
target_link_libraries(pkginfo pkgmgr-client pkgmgr_installer ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkginfo DESTINATION bin)

add_executable(pkg_getsize
                pkg_getsize.c)
target_link_libraries(pkg_getsize pkgmgr_installer ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_getsize DESTINATION bin)

add_executable(pkg_getjunkinfo
                pkg_getjunkinfo.c
				pkg_magic.c)
target_link_libraries(pkg_getjunkinfo pkgmgr_installer ${pkgs_test_LDFLAGS} -lmagic)
INSTALL(TARGETS pkg_getjunkinfo DESTINATION bin)

add_executable(test_junk
                test_junk.c)
target_link_libraries(test_junk pkgmgr-client pkgmgr_installer ${pkgs_test_LDFLAGS})
INSTALL(TARGETS test_junk DESTINATION bin)

add_executable(pkg_clearcache
                pkg_clearcache.c)
target_link_libraries(pkg_clearcache ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_clearcache DESTINATION bin)

add_executable(pkg_mkext
                pkg_mkext.c)
target_link_libraries(pkg_mkext ${mkext_LDFLAGS})
INSTALL(TARGETS pkg_mkext DESTINATION bin)

add_executable(pkg_initdb
                pkg_initdb.c)
target_link_libraries(pkg_initdb ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_initdb DESTINATION bin)

add_executable(pkg_fota
                pkg_fota.c)
target_link_libraries(pkg_fota ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_fota DESTINATION bin)

add_executable(pkg
                pkg.c)
target_link_libraries(pkg pkgmgr-client ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg DESTINATION bin)

add_executable(pkgmgr-install pkgmgr-install.c)
target_link_libraries(pkgmgr-install pkgmgr-client pkgmgr-info ${toolpkgs_LDFLAGS})
install(TARGETS pkgmgr-install DESTINATION bin)

configure_file(com.samsung.pkgmgr-install.xml.in ${CMAKE_BINARY_DIR}/com.samsung.pkgmgr-install.xml @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/com.samsung.pkgmgr-install.xml DESTINATION /usr/share/packages/)

configure_file(pkg_recovery.sh.in pkg_recovery.sh @ONLY)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pkg_recovery.sh DESTINATION /usr/etc/package-manager/)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mime.wac.xml DESTINATION /usr/share/mime/packages/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mime.tpk.xml DESTINATION /usr/share/mime/packages/)

