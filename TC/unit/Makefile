CC ?= gcc

TARGETS = utc_ApplicationFW_pkgmgr_client_activate_func \
	utc_ApplicationFW_pkgmgr_client_broadcast_status_func \
	utc_ApplicationFW_pkgmgr_client_clear_user_data_func \
	utc_ApplicationFW_pkgmgr_client_move_func \
	utc_ApplicationFW_pkgmgr_client_deactivate_func \
	utc_ApplicationFW_pkgmgr_client_free_func \
	utc_ApplicationFW_pkgmgr_client_install_func \
	utc_ApplicationFW_pkgmgr_client_listen_status_func \
	utc_ApplicationFW_pkgmgr_client_new_func \
	utc_ApplicationFW_pkgmgr_client_uninstall_func \
	utc_ApplicationFW_pkgmgr_get_pkg_list_func \
	utc_ApplicationFW_pkgmgr_info_free_func \
	utc_ApplicationFW_pkgmgr_info_get_string_func \
	utc_ApplicationFW_pkgmgr_info_new_from_file_func \
	utc_ApplicationFW_pkgmgr_info_new_func \
	utc_ApplicationFW_pkgmgr_installer_free_func \
	utc_ApplicationFW_pkgmgr_installer_get_license_path_func \
	utc_ApplicationFW_pkgmgr_installer_get_move_type_func \
	utc_ApplicationFW_pkgmgr_installer_get_request_info_func \
	utc_ApplicationFW_pkgmgr_installer_get_request_type_func \
	utc_ApplicationFW_pkgmgr_installer_get_session_id_func \
	utc_ApplicationFW_pkgmgr_installer_is_quiet_func \
	utc_ApplicationFW_pkgmgr_installer_new_func \
	utc_ApplicationFW_pkgmgr_installer_receive_request_func \
	utc_ApplicationFW_pkgmgr_installer_send_signal_func

PKGS = glib-2.0 dlog pkgmgr pkgmgr-installer

LDFLAGS = `pkg-config --libs $(PKGS)`
LDFLAGS += $(TET_ROOT)/lib/tet3/tcm_s.o
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -ltcm_s
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -lapi_s
LDFLAGS += -L/usr/lib -lpthread

CFLAGS = -I. `pkg-config --cflags $(PKGS)`
CFLAGS += -I$(TET_ROOT)/inc/tet3
CFLAGS += -Wall

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(TARGETS)
