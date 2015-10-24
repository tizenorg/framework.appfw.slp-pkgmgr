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


/*
 * comm_client_gdbus.c
 * comm_client library using gdbus
 */

#include <glib.h>
#include <gio/gio.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include "comm_config.h"
#include "comm_client.h"
#include "comm_internal.h"
#include "comm_pkg_mgr_gdbus_generated.h"

#define MAX_ZONE_NAME_LEN 128
#define ZONE_HOST "host"

static bool unmatched_zone_filter(const char *zone, const char *signal)
{
	int len_zone = 0;
	int len_sig = strlen(signal);
	bool filtered = true;
	char temp[MAX_ZONE_NAME_LEN] = {0, };

	if (!zone)
		filtered = false;

	if (zone && strlen(zone)) {
		len_zone = strlen(zone);
		if (strcmp(zone, ZONE_HOST) == 0) {
			filtered = false;
		} else {
			if (len_sig >= len_zone) {
				snprintf(temp, len_zone + 1, "%s", &signal[len_sig - len_zone]);

				if (strcmp(temp, zone) == 0) {
					filtered = false;
				}
			}
		}
	}

	if (filtered && zone) {
		dbg("filtered : (%s, %s, %d)\n", signal, zone, len_sig - len_zone);
	}

	return filtered;
}

static int get_sender_zone_name(const char *zone, const char *signal, char *sender_zone)
{
	int len_sig = 0;
	int len_sig_tmp = 0;
	int diff = 0;
	int ret = -1;
	char temp[MAX_ZONE_NAME_LEN] = {0, };

	if (!zone || !signal)
		return -1;

	len_sig = strlen(signal);

	if (strcmp(zone, ZONE_HOST)) {
		/* skip, unless host zone */
		return -1;
	}

	if (signal && len_sig) {
		if (!strncmp(signal, COMM_STATUS_BROADCAST_SIGNAL_STATUS,
			LEN_COMM_STATUS_BROADCAST_SIGNAL_STATUS)) {
			len_sig_tmp = LEN_COMM_STATUS_BROADCAST_SIGNAL_STATUS;
		} else if (!strncmp(signal, COMM_STATUS_BROADCAST_EVENT_INSTALL,
			LEN_COMM_STATUS_BROADCAST_EVENT_INSTALL)) {
			len_sig_tmp = LEN_COMM_STATUS_BROADCAST_EVENT_INSTALL;
		} else if (!strncmp(signal, COMM_STATUS_BROADCAST_EVENT_UNINSTALL,
			LEN_COMM_STATUS_BROADCAST_EVENT_UNINSTALL)) {
			len_sig_tmp = LEN_COMM_STATUS_BROADCAST_EVENT_UNINSTALL;
		} else if (!strncmp(signal, COMM_STATUS_BROADCAST_EVENT_UPGRADE,
			LEN_COMM_STATUS_BROADCAST_EVENT_UPGRADE)) {
			len_sig_tmp = LEN_COMM_STATUS_BROADCAST_EVENT_UPGRADE;
		} else if (!strncmp(signal, COMM_STATUS_BROADCAST_EVENT_MOVE,
			LEN_COMM_STATUS_BROADCAST_EVENT_MOVE)) {
			len_sig_tmp = LEN_COMM_STATUS_BROADCAST_EVENT_MOVE;
		} else if (!strncmp(signal, COMM_STATUS_BROADCAST_EVENT_GET_SIZE,
			LEN_COMM_STATUS_BROADCAST_EVENT_GET_SIZE)) {
			len_sig_tmp = LEN_COMM_STATUS_BROADCAST_EVENT_GET_SIZE;
		} else if (!strncmp(signal, COMM_STATUS_BROADCAST_EVENT_INSTALL_PROGRESS,
			LEN_COMM_STATUS_BROADCAST_EVENT_INSTALL_PROGRESS)) {
			len_sig_tmp = LEN_COMM_STATUS_BROADCAST_EVENT_INSTALL_PROGRESS;
		}

		if (len_sig_tmp) {
			if (len_sig > len_sig_tmp) {
				len_sig_tmp += 1; /* for '_' */
				diff = len_sig - len_sig_tmp;
				snprintf(temp, diff + 1, "%s", &signal[len_sig_tmp]);

				if (strlen(temp)) {
					memcpy(sender_zone, temp, strlen(temp));
					dbg("temp(%s), sender_zone(%s)", temp, sender_zone);
					ret = 0;
				}
			}
		}
	}

	return ret;
}

/*******************
 * ADT description
 */

/* Storing status_cb */
struct signal_callback_data {
	status_cb cb;
	void *cb_data;
};

/* comm_client ADT */
struct comm_client {
	guint subscription_id;
	GDBusConnection *conn;
	struct signal_callback_data *sig_cb_data;
};

#define COMM_CLIENT_RETRY_MAX 	5

static int __retry_request(comm_client *cc,
	const gchar *req_id,
	gint req_type,
	const gchar *pkg_type,
	const gchar *pkgid,
	const gchar *args,
	const gchar *cookie,
	gint *ret)
{
	OrgTizenPkgmgr *proxy;
	GError *error = NULL;
	int rc = 0;

	proxy = org_tizen_pkgmgr_proxy_new_sync(cc->conn,
			G_DBUS_PROXY_FLAGS_NONE, COMM_PKG_MGR_DBUS_SERVICE,
			COMM_PKG_MGR_DBUS_PATH,
			NULL, &error);
	if (proxy == NULL) {
		ERR("Unable to create proxy[rc=%d, err=%s]\n", rc, error->message);
		return FALSE;
	}

	rc = org_tizen_pkgmgr_call_request_sync(proxy,
			req_id, req_type, pkg_type, pkgid, args, cookie, ret, NULL, &error);
	if (!rc) {
		ERR("Failed to send request[rc=%d, err=%s]\n", rc, error->message);
		return FALSE;
	}
	return TRUE;
}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
static bool __retry_request_with_tep(comm_client *cc,
	const gchar *req_id,
	gint req_type,
	const gchar *pkg_type,
	const gchar *pkgid,
	const gchar *tep_path,
	const gchar *args,
	const gchar *cookie,
	gint *ret)
{
	OrgTizenPkgmgr *proxy;
	GError *error = NULL;
	int rc = 0;

	ERR("tep_install request send failed, retrying...");

	proxy = org_tizen_pkgmgr_proxy_new_sync(cc->conn,
			G_DBUS_PROXY_FLAGS_NONE, COMM_PKG_MGR_DBUS_SERVICE,
			COMM_PKG_MGR_DBUS_PATH,
			NULL, &error);
	if (proxy == NULL) {
		ERR("Unable to create proxy[rc=%d, err=%s]\n", rc, error->message);
		return FALSE;
	}

	//jungh function name should be checked
	org_tizen_pkgmgr_call_tep_request_sync(proxy,
			req_id, req_type, pkg_type, pkgid, tep_path, args, cookie, ret, NULL, &error);
#if 0
	if (!rc) {
		ERR("Failed to send request[rc=%d, err=%s]\n", rc, error->message);
		return FALSE;
	}
#endif
	return TRUE;
}
#endif

static char *__get_interface(int status_type)
{
	char *ifc = NULL;

	switch (status_type) {
		case COMM_STATUS_BROADCAST_ALL:
			ifc = COMM_STATUS_BROADCAST_DBUS_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_INSTALL:
			ifc = COMM_STATUS_BROADCAST_DBUS_INSTALL_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_UNINSTALL:
			ifc = COMM_STATUS_BROADCAST_DBUS_UNINSTALL_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_MOVE:
			ifc = COMM_STATUS_BROADCAST_DBUS_MOVE_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_INSTALL_PROGRESS:
			ifc = COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_UPGRADE:
			ifc = COMM_STATUS_BROADCAST_DBUS_UPGRADE_INTERFACE;
			break;

		case COMM_STATUS_BROADCAST_GET_SIZE:
			ifc = COMM_STATUS_BROADCAST_DBUS_GET_SIZE_INTERFACE;
			break;

		default:
			break;
	}
	return ifc;
}

/**
 * signal handler filter
 * Filter signal, and run user callback
 */
void _on_signal_handle_filter(GDBusConnection *conn,
		const gchar *sender_name,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *signal_name,
		GVariant *parameters,
		gpointer user_data)
{
	char temp_name[MAX_ZONE_NAME_LEN] = {0, };
	char *zone = NULL;
	char *sender_zone = NULL;
	int pid = getpid();

	if(!signal_name){
		dbg("signal_name is empty");
		goto catch;
	}

	if (get_zone_name(pid, temp_name, MAX_ZONE_NAME_LEN) == -1) {
		gethostname(temp_name, sizeof(temp_name));
	}
	if (strlen(temp_name)) {
		zone = strdup(temp_name);
	}

	if (unmatched_zone_filter(zone, signal_name)) {
		dbg("zone name did not match. Drop the message");
		goto catch;
	}

	if (interface_name && strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_INSTALL_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_UNINSTALL_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_UPGRADE_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_MOVE_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_GET_SIZE_INTERFACE) &&
		strcmp(interface_name, COMM_STATUS_BROADCAST_DBUS_INSTALL_PROGRESS_INTERFACE)) {
		dbg("Interface name did not match. Drop the message");
		goto catch;
	}

	if (signal_name && strncmp(signal_name, COMM_STATUS_BROADCAST_SIGNAL_STATUS,
						 LEN_COMM_STATUS_BROADCAST_SIGNAL_STATUS) &&
		strncmp(signal_name, COMM_STATUS_BROADCAST_EVENT_INSTALL,
						 LEN_COMM_STATUS_BROADCAST_EVENT_INSTALL) &&
		strncmp(signal_name, COMM_STATUS_BROADCAST_EVENT_UNINSTALL,
						 LEN_COMM_STATUS_BROADCAST_EVENT_UNINSTALL) &&
		strncmp(signal_name, COMM_STATUS_BROADCAST_EVENT_UPGRADE,
						 LEN_COMM_STATUS_BROADCAST_EVENT_UPGRADE) &&
		strncmp(signal_name, COMM_STATUS_BROADCAST_EVENT_MOVE,
						 LEN_COMM_STATUS_BROADCAST_EVENT_MOVE) &&
		strncmp(signal_name, COMM_STATUS_BROADCAST_EVENT_GET_SIZE,
						 LEN_COMM_STATUS_BROADCAST_EVENT_GET_SIZE) &&
		strncmp(signal_name, COMM_STATUS_BROADCAST_EVENT_INSTALL_PROGRESS,
						 LEN_COMM_STATUS_BROADCAST_EVENT_INSTALL_PROGRESS)) {
		dbg("Signal name did not match. Drop the message");

		goto catch;
	}

	memset(temp_name, 0, MAX_ZONE_NAME_LEN);

	if (get_sender_zone_name(zone, signal_name, temp_name) == 0) {
		if (strlen(temp_name)) {
			sender_zone = strdup(temp_name);
		}
	}

	/* Values to be received by signal */
	char *req_id = NULL;
	char *pkg_type = NULL;
	char *pkgid = NULL;
	char *key = NULL;
	char *val = NULL;

	/* User's signal handler */
	struct signal_callback_data *sig_cb_data;
	if (user_data)
		sig_cb_data = (struct signal_callback_data *)user_data;
	else
		goto catch;

	g_variant_get(parameters, "(&s&s&s&s&s)", &req_id, &pkg_type, &pkgid, &key, &val);

	/* Got signal! */
	SECURE_LOGD("signal_name=[%s], req_id=[%s], pkg_type=[%s], pkgid=[%s], key=[%s], value=[%s]",
				signal_name, req_id, pkg_type, pkgid, key, val);

	/* Run signal callback if exist */
	if (sig_cb_data && sig_cb_data->cb) {
		// invoke callback
		sig_cb_data->cb(sig_cb_data->cb_data, req_id, pkg_type, pkgid, key, val, sender_zone);
	} else {
		ERR("signal callback is NOT invoked!!");
	}

catch:
	if (zone)
		free(zone);

	if (sender_zone)
		free(sender_zone);

	return;
}

/**
 * signal_callback_data free function
 * Just free it!
 */
void _free_sig_cb_data(void *data)
{
	struct signal_callback_data *sig_cb_data = NULL;
	if (data)
		sig_cb_data = (struct signal_callback_data *)data;
	if (!sig_cb_data)
		return;
	free(sig_cb_data);
}

/*******************
 * API description
 */

/**
 * Create a new comm_client object
 */
comm_client *comm_client_new(void)
{
	GError *error = NULL;
	comm_client *cc = NULL;

	/* Allocate memory for ADT:comm_client */
	g_type_init();
	cc = calloc(1, sizeof(comm_client));
	if (NULL == cc) {
		ERR("No memory");
		goto ERROR_CLEANUP;
	}

	/* Connect to gdbus. Gets shared BUS */
	cc->conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (error) {
		ERR("gdbus connection error (%s)", error->message);
		g_error_free(error);
		goto ERROR_CLEANUP;
	}
	if (NULL == cc->conn) {
		ERR("gdbus connection is not set, even gdbus error isn't raised");
		goto ERROR_CLEANUP;
	}
	return cc;

 ERROR_CLEANUP:
	if (cc)
		free(cc);
	return NULL;
}

/**
 * Create a new comm_client object (for private connection)
 */
comm_client *comm_client_new_private(void)
{
	GError *error = NULL;
	comm_client *cc = NULL;
	gchar *addr = NULL;

	/* Allocate memory for ADT:comm_client */
	g_type_init();
	cc = calloc(1, sizeof(comm_client));
	if (NULL == cc) {
		ERR("No memory");
		return NULL;
	}

	/* Connect to gdbus. Gets private BUS */
	addr = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (error) {
		ERR("gdbus connection error (%s)", error->message);

		g_error_free(error);
		goto ERROR_CLEANUP;
	}

	cc->conn = g_dbus_connection_new_for_address_sync(addr, G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
	if (NULL == cc->conn) {
		ERR("gdbus connection is not set, even gdbus error isn't raised");
		g_error_free(error);
		free(addr);

		goto ERROR_CLEANUP;
	}

	free(addr);

	return cc;

 ERROR_CLEANUP:
	if (cc)
		free(cc);

	return NULL;
}

/**
 * Free comm_client object
 */
int comm_client_free(comm_client *cc)
{
	if (!cc)
		return -1;
	if (!(cc->conn) || g_dbus_connection_is_closed(cc->conn)) {
		ERR("Invalid gdbus connection");
		return -2;
	}

	/* Cleanup ADT */
	/* flush remaining buffer: blocking mode */
	g_dbus_connection_flush_sync(cc->conn, NULL, NULL);

	/* Free signal filter if signal callback is exist */
	if (cc->sig_cb_data) {
		g_dbus_connection_signal_unsubscribe(cc->conn, cc->subscription_id);
		/* TODO: Is it needed to free cc->sig_cb_data here? */
		/* _free_sig_cb_data(cc->sig_cb_data); */
	}
	/* just unref because it is shared BUS.
	If ref count is 0 it will get free'd automatically
	*/
	g_object_unref(cc->conn);

	if(cc)
		free(cc);

	return 0;
}

/**
 * Request a message
 */
int
comm_client_request(
		comm_client *cc,
		const char *req_id,
		const int req_type,
		const char *pkg_type,
		const char *pkgid,
		const char *args,
		const char *cookie,
		int is_block)
{
	GError *error = NULL;
	int ret = 0;
	int rc = 0;
	int retry_cnt = 0;

	OrgTizenPkgmgr *proxy;
	if (!cc){
		ERR("Invalid gdbus input");
		return COMM_RET_ERROR;
	}
	proxy = org_tizen_pkgmgr_proxy_new_sync(cc->conn,
			G_DBUS_PROXY_FLAGS_NONE, COMM_PKG_MGR_DBUS_SERVICE,
			COMM_PKG_MGR_DBUS_PATH,
			NULL, &error);
	if (proxy == NULL) {
		ERR("Unable to create proxy[rc=%d, err=%s]\n", rc, error->message);
		return COMM_RET_ERROR;
	}

	/* Assign default values if NULL (NULL is not allowed) */
	if (req_id == NULL)
		req_id = "tmp_reqid";
	if (pkg_type == NULL)
		pkg_type = "none";
	if (pkgid == NULL)
		pkgid = "";
	if (args == NULL)
		args = "";
	if (cookie == NULL)
		cookie = "";

	rc = org_tizen_pkgmgr_call_request_sync(proxy,
			req_id, req_type, pkg_type, pkgid, args, cookie, &ret, NULL, &error);

	while (rc == FALSE) {
		ERR("Failed to send request, sleep and retry[rc=%d, err=%s]\n", rc, error->message);
		sleep(1);

		if(retry_cnt == COMM_CLIENT_RETRY_MAX) {
			ERR("retry_cnt is max, stop retry\n");
			return COMM_RET_ERROR;
		}
		retry_cnt++;

		rc = __retry_request(cc, req_id, req_type, pkg_type, pkgid, args, cookie, &ret);
		if(rc == TRUE) {
			ERR("__retry_request is success[retry_cnt=%d]\n", retry_cnt);
			break;
		}
	}

	return ret;
}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
/**
 * Request a message
 */
int
comm_client_request_with_tep(
		comm_client *cc,
		const char *req_id,
		const int req_type,
		const char *pkg_type,
		const char *pkgid,
		const char *tep_path,
		const char *args,
		const char *cookie,
		int is_block)
{
	GError *error = NULL;
	int ret = 0;
	int rc = 0;
	int retry_cnt = 0;

	ERR("sending the tep_install request to pkgmgr-server");

	OrgTizenPkgmgr *proxy;
	if (!cc){
		ERR("Invalid gdbus input");
		return COMM_RET_ERROR;
	}
	proxy = org_tizen_pkgmgr_proxy_new_sync(cc->conn,
			G_DBUS_PROXY_FLAGS_NONE, COMM_PKG_MGR_DBUS_SERVICE,
			COMM_PKG_MGR_DBUS_PATH,
			NULL, &error);
	if (proxy == NULL) {
		ERR("Unable to create proxy[rc=%d, err=%s]\n", rc, error->message);
		return COMM_RET_ERROR;
	}

	/* Assign default values if NULL (NULL is not allowed) */
	if (req_id == NULL)
		req_id = "tmp_reqid";
	if (pkg_type == NULL)
		pkg_type = "none";
	if (pkgid == NULL)
		pkgid = "";
	if (args == NULL)
		args = "";
	if (cookie == NULL)
		cookie = "";
	if (tep_path == NULL)
		tep_path = "";

	rc = org_tizen_pkgmgr_call_tep_request_sync(proxy,
			req_id, req_type, pkg_type, pkgid, tep_path, args, cookie, &ret, NULL, &error);

	while (rc == FALSE) {
		ERR("Failed to send request, sleep and retry[rc=%d, err=%s]\n", rc, error->message);
		sleep(1);

		if(retry_cnt == COMM_CLIENT_RETRY_MAX) {
			ERR("retry_cnt is max, stop retry\n");
			return COMM_RET_ERROR;
		}
		retry_cnt++;

		rc = __retry_request_with_tep(cc, req_id, req_type, pkg_type, pkgid, tep_path, args, cookie, &ret);
		if(rc == TRUE) {
			ERR("__retry_request is success[retry_cnt=%d]\n", retry_cnt);
			break;
		}
	}
	return ret;
}
#endif


/**
 * Set a callback for status signal
 */
int
comm_client_set_status_callback(int comm_status_type, comm_client *cc, status_cb cb, void *cb_data)
{
	int r = COMM_RET_ERROR;
	char *ifc = NULL;

	if (NULL == cc)
		goto ERROR_CLEANUP;

	ifc = __get_interface(comm_status_type);
	if (ifc == NULL) {
		ERR("Invalid interface name\n");
		return COMM_RET_ERROR;
	}

	/* Create new sig_cb_data */
	cc->sig_cb_data = calloc(1, sizeof(struct signal_callback_data));
	if(cc->sig_cb_data == NULL){
		ERR("calloc failed!!");
		return COMM_RET_ERROR;
	}
	(cc->sig_cb_data)->cb = cb;
	(cc->sig_cb_data)->cb_data = cb_data;

	/* Add a filter for signal */
	cc->subscription_id = g_dbus_connection_signal_subscribe(cc->conn, NULL, ifc,
		NULL, NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
		_on_signal_handle_filter, (gpointer)cc->sig_cb_data, _free_sig_cb_data);
	if (!cc->subscription_id) {
		ERR("Failed to add filter\n");
		r = COMM_RET_ERROR;
		goto ERROR_CLEANUP;
	}

	return COMM_RET_OK;

 ERROR_CLEANUP:
	ERR("General error");
	return r;
}

