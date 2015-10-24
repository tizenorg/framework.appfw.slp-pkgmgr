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





#include "comm_config.h"
#include "comm_internal.h"
#include <gio/gio.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "comm_pkg_mgr_server.h"
#include "comm_pkg_mgr_gdbus_generated.h"


struct pkg_mgr_server_gdbus_s {
	OrgTizenPkgmgr *obj;
	GDBusConnection *connection;
	guint owner_id;

	request_callback req_cb;
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	request_tep_callback req_tep_cb;
#endif
	create_directory_cb create_dir_cb;

	drm_generate_license_request_cb gen_license_req_cb;
	drm_register_license_cb reg_license_cb;
	drm_decrypt_package_cb decrypt_pkg_cb;

	void *req_cb_data;
};

static int pkg_mgr_get_sender_pid(GDBusConnection *connection, char *sender_name)
{
	guint pid = 0;
	GError *error = NULL;
	GVariant *ret;

	ret = g_dbus_connection_call_sync(connection,
			"org.freedesktop.DBus",
			"/org/freedesktop/DBus",
			"org.freedesktop.DBus",
			"GetConnectionUnixProcessID",
			g_variant_new("(s)", sender_name),
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);
	if (ret != NULL) {
		g_variant_get(ret, "(u)", &pid);
		g_variant_unref(ret);
	}

	dbg("zone pid : %d", pid);

	return pid;
}

#define MAX_ZONE_NAME_LEN 128
#define ZONE_HOST "host"

/**
 * Set request callback function
 */
void pkg_mgr_set_request_callback(pkgmgr_server_gdbus_h handle, request_callback req_cb,
		void *cb_data)
{
	handle->req_cb = req_cb;
	handle->req_cb_data = cb_data;
}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
void pkg_mgr_set_request_tep_callback(pkgmgr_server_gdbus_h handle, request_tep_callback req_tep_cb,
		void *cb_data)
{
	handle->req_tep_cb = req_tep_cb;
	handle->req_cb_data = cb_data;
}
#endif

void pkg_mgr_set_callback_to_create_directory(pkgmgr_server_gdbus_h handle, create_directory_cb callback)
{
	handle->create_dir_cb = callback;
	handle->req_cb_data = NULL;
}

void pkg_mgr_set_drm_generate_license_request_callback(pkgmgr_server_gdbus_h handle,
		drm_generate_license_request_cb gen_license_req_cb)
{
	handle->gen_license_req_cb = gen_license_req_cb;
	handle->req_cb_data = NULL;
}

void pkg_mgr_set_drm_register_license_callback(pkgmgr_server_gdbus_h handle,
		drm_register_license_cb reg_license_cb)
{
	handle->reg_license_cb = reg_license_cb;
	handle->req_cb_data = NULL;
}

void pkg_mgr_set_drm_decrypt_package_callback(pkgmgr_server_gdbus_h handle,
		drm_decrypt_package_cb decrypt_pkg_cb)
{
	handle->decrypt_pkg_cb = decrypt_pkg_cb;
	handle->req_cb_data = NULL;
}

/* dbus-glib methods */

static gboolean pkgmgr_request(OrgTizenPkgmgr *obj,
		GDBusMethodInvocation *invocation,
		const gchar *req_id,
		const gint req_type,
		const gchar *pkg_type,
		const gchar *pkgid,
		const gchar *args,
		const gchar *cookie,
		gpointer user_data)
{
	dbg("Called");
	int ret = COMM_RET_OK;	/* TODO: fix this! */
	int pid;
	char *sender_name;
	char temp_name[MAX_ZONE_NAME_LEN] = {0, };
	char *zone = NULL;

	struct pkg_mgr_server_gdbus_s *pkgmgr_server = (struct pkg_mgr_server_gdbus_s *)user_data;
	if (pkgmgr_server == NULL) {
		ERR("pkg_mgr_server_gdbus_s is null");
		g_dbus_method_invocation_return_value(invocation, g_variant_new("(i)", COMM_RET_ERROR));
		return FALSE;
	}

	/* TODO: Add business logic
	 * - add to queue, or remove from queue
	 * */

	sender_name = g_dbus_method_invocation_get_sender(invocation);
	dbg("sender_name: %s", sender_name);
	pid = pkg_mgr_get_sender_pid(pkgmgr_server->connection, sender_name);
	dbg("sender_pid: %d", pid);

	get_zone_name(pid, temp_name, MAX_ZONE_NAME_LEN);
	if (strlen(temp_name)) {
		zone = strdup(temp_name);
	}

	if (pkgmgr_server->req_cb) {
		SECURE_LOGD("Call request callback(obj, %s, %d, %s, %s, %s, %s)",
		    req_id, req_type, pkg_type, pkgid, args, zone);
		pkgmgr_server->req_cb(pkgmgr_server->req_cb_data, req_id, req_type, pkg_type,
			    pkgid, args, cookie, zone, &ret);
	} else {
		dbg("Attempt to call request callback,"
		" but request callback is not set. Do nothing.\n"
		"Use pkg_mgr_set_request_callback()"
		" to register your callback.");
	}

	if (zone)
		free(zone);
	g_dbus_method_invocation_return_value(invocation, g_variant_new("(i)", ret));

	return TRUE;
}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
static gboolean pkgmgr_tep_request(OrgTizenPkgmgr *obj,
		GDBusMethodInvocation *invocation,
		const gchar *req_id,
		const gint req_type,
		const gchar *pkg_type,
		const gchar *pkgid,
		const gchar *tep_path,
		const gchar *args,
		const gchar *cookie,
		gpointer user_data)
{
	dbg("Called");
	int ret = COMM_RET_OK;	/* TODO: fix this! */
	int pid;
	char *sender_name;
	char temp_name[MAX_ZONE_NAME_LEN] = {0, };
	char *zone = NULL;

	/* TODO: Add business logic
	 * - add to queue, or remove from queue
	 * */

	struct pkg_mgr_server_gdbus_s *pkgmgr_server = (struct pkg_mgr_server_gdbus_s *)user_data;
	if (pkgmgr_server == NULL) {
		ERR("pkg_mgr_server_gdbus_s is null");
		g_dbus_method_invocation_return_value(invocation, g_variant_new("(i)", COMM_RET_ERROR));
		return FALSE;
	}

	sender_name = g_dbus_method_invocation_get_sender(invocation);
	dbg("sender_name: %s", sender_name);
	pid = pkg_mgr_get_sender_pid(pkgmgr_server->connection, sender_name);
	dbg("sender_pid: %d", pid);

	get_zone_name(pid, temp_name, MAX_ZONE_NAME_LEN);
	if (strlen(temp_name)) {
		zone = strdup(temp_name);
	}

	if (pkgmgr_server->req_tep_cb) {
		SECURE_LOGD("Call request callback(obj, %s, %d, %s, %s, %s, %s, %s)",
		    req_id, req_type, pkg_type, pkgid, tep_path, args, zone);
		pkgmgr_server->req_tep_cb(pkgmgr_server->req_cb_data, req_id, req_type, pkg_type,
			    pkgid, tep_path, args, cookie, zone, &ret);
	} else {
		dbg("Attempt to call request_tep callback,"
		" but request callback is not set. Do nothing.\n"
		"Use pkg_mgr_set_request_tep_callback()"
		" to register your callback.");
	}

	if (zone) {
		free(zone);
		zone = NULL;
	}

	g_dbus_method_invocation_return_value(invocation, g_variant_new("(i)", ret));
	return TRUE;
}
#endif

static gboolean pkgmgr_create_external_directory(OrgTizenPkgmgr *obj,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	int res = 0;
	int pid;
	char *sender_name;
	char temp_name[MAX_ZONE_NAME_LEN] = {0, };
	char *zone = NULL;

	struct pkg_mgr_server_gdbus_s *pkgmgr_server = (struct pkg_mgr_server_gdbus_s *)user_data;
	if (pkgmgr_server == NULL) {
		ERR("pkg_mgr_server_gdbus_s is null");
		g_dbus_method_invocation_return_value(invocation, g_variant_new("(i)", COMM_RET_ERROR));
		return FALSE;
	}

	sender_name = g_dbus_method_invocation_get_sender(invocation);
	dbg("sender_name: %s", sender_name);
	pid = pkg_mgr_get_sender_pid(pkgmgr_server->connection, sender_name);
	dbg("sender_pid: %d", pid);

	get_zone_name(pid, temp_name, MAX_ZONE_NAME_LEN);
	if (strlen(temp_name)) {
		zone = strdup(temp_name);
	}
	dbg("zone(%s)", zone);

	dbg("Try to create external directories.");
	if (pkgmgr_server->create_dir_cb)
	{
		res = pkgmgr_server->create_dir_cb(zone);
		if (res < 0) {
			ERR("_create_external_directory() is failed. error = [%d]", res);
		}
	} else {
		res = -1;
	}

	g_dbus_method_invocation_return_value(invocation, g_variant_new("(i)", res));

	if (zone) {
		free(zone);
		zone = NULL;
	}
	return TRUE;
}

static gboolean pkgmgr_drm_generate_license_request(OrgTizenPkgmgr *obj,
		GDBusMethodInvocation *invocation,
		const gchar *resp_data,
		const gchar *cookie,
		gpointer user_data)
{
	int res = -1;
	gchar *req_data = NULL;
	gchar *license_url = NULL;
	int ret = 0;
	struct pkg_mgr_server_gdbus_s *pkgmgr_server = (struct pkg_mgr_server_gdbus_s *)user_data;
	dbg("Try to call package_manager_drm_generate_license_request.");
	if (pkgmgr_server->gen_license_req_cb)
	{
		int res = pkgmgr_server->gen_license_req_cb(resp_data, cookie, &req_data, &license_url, &ret);
		if (res < 0)
		{
			ERR("Calling package_manager_drm_generate_license_request is failed. error = [%d]", res);
		}
	}

	g_dbus_method_invocation_return_value(invocation, g_variant_new("(ssi)",req_data, license_url, ret));
	return TRUE;
}

static gboolean pkgmgr_drm_register_license(OrgTizenPkgmgr *obj,
		GDBusMethodInvocation *invocation,
		const gchar *resp_data,
		const gchar *cookie,
		gpointer user_data)
{
	int res = -1;
	int ret = 0;
	struct pkg_mgr_server_gdbus_s *pkgmgr_server = (struct pkg_mgr_server_gdbus_s *)user_data;
	dbg("Try to call package_manager_drm_register_license.");
	if (pkgmgr_server->reg_license_cb)
	{
		res = pkgmgr_server->reg_license_cb(resp_data, cookie, &ret);
		if (res < 0)
		{
			ERR("Calling package_manager_drm_register_license is failed. error = [%d]",	res);
		}
	}

	g_dbus_method_invocation_return_value(invocation, g_variant_new("(i)", ret));
	return TRUE;
}

static gboolean pkgmgr_drm_decrypt_package(OrgTizenPkgmgr *obj,
		GDBusMethodInvocation *invocation,
		const gchar *drm_file_path,
		const gchar *decrypted_file_path,
		const gchar *cookie,
		gpointer user_data)
{
	int res = -1;
	int ret = 0;
	struct pkg_mgr_server_gdbus_s *pkgmgr_server = (struct pkg_mgr_server_gdbus_s *)user_data;
	dbg("Try to call package_manager_drm_decrypt_package.");
	if (pkgmgr_server->decrypt_pkg_cb)
	{
		res = pkgmgr_server->decrypt_pkg_cb(drm_file_path, decrypted_file_path, cookie, &ret);
		if (res < 0)
		{
			ERR("Calling package_manager_drm_decrypt_package is failed. error = [%d]", res);
		}
	}

	g_dbus_method_invocation_return_value(invocation, g_variant_new("(i)", ret));
	return TRUE;
}

static void on_bus_acquired(GDBusConnection *connection, const gchar *name, gpointer user_data)
{
	dbg("on_bus_acquired");
	struct pkg_mgr_server_gdbus_s *pkgmgr_server = (struct pkg_mgr_server_gdbus_s *)user_data;

	pkgmgr_server->obj = org_tizen_pkgmgr_skeleton_new();
	if (pkgmgr_server->obj == NULL) {
		ERR("Creating a skeleton object is failed.");
		return;
	}

	g_signal_connect(pkgmgr_server->obj, "handle-request", G_CALLBACK(pkgmgr_request), pkgmgr_server);
	g_signal_connect(pkgmgr_server->obj, "handle-tep-request", G_CALLBACK(pkgmgr_tep_request), pkgmgr_server);
	g_signal_connect(pkgmgr_server->obj, "handle-create-external-directory", G_CALLBACK(pkgmgr_create_external_directory), pkgmgr_server);
	g_signal_connect(pkgmgr_server->obj, "handle-drm-generate-license-request", G_CALLBACK(pkgmgr_drm_generate_license_request), pkgmgr_server);
	g_signal_connect(pkgmgr_server->obj, "handle-drm-register-license", G_CALLBACK(pkgmgr_drm_register_license), pkgmgr_server);
	g_signal_connect(pkgmgr_server->obj, "handle-drm-decrypt-package", G_CALLBACK(pkgmgr_drm_decrypt_package), pkgmgr_server);

	if (!g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(pkgmgr_server->obj), connection, COMM_PKG_MGR_DBUS_PATH, NULL)) {
		ERR("Exporting the obj is failed.");
		g_object_unref(pkgmgr_server->obj);
		pkgmgr_server->obj = NULL;
		return;
	}

	pkgmgr_server->connection = connection;
	dbg("on_bus_acquired done");
}

int pkg_mgr_server_gdbus_init(pkgmgr_server_gdbus_h *pkgmgr_server_h)
{
	dbg("initialize_gdbus Enter");
	struct pkg_mgr_server_gdbus_s *pkgmgr_server;
	pkgmgr_server = calloc(1, sizeof(struct pkg_mgr_server_gdbus_s));
	if (pkgmgr_server == NULL) {
		ERR("Out of memory");
		return -1;
	}

	pkgmgr_server->owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM, COMM_PKG_MGR_DBUS_SERVICE,
				G_BUS_NAME_OWNER_FLAGS_NONE, on_bus_acquired, NULL, NULL, pkgmgr_server, NULL);

	if (pkgmgr_server->owner_id == 0) {
		ERR("Acquiring the own name is failed.");
		free(pkgmgr_server);
		return -1;
	}

	*pkgmgr_server_h = pkgmgr_server;
	dbg("initialize_gdbus Exit");
	return 0;
}

void pkg_mgr_server_gdbus_fini(pkgmgr_server_gdbus_h pkgmgr_server)
{
	g_object_unref(pkgmgr_server->obj);
	g_object_unref(pkgmgr_server->connection);
	free(pkgmgr_server);
	pkgmgr_server = NULL;
}
