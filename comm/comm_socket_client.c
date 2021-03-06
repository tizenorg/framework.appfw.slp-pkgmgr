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





#include "comm_socket_client.h"

#include <sys/types.h>
#include <sys/socket.h>

#define CHK_CSC_RET(r) \
	do { if (NULL == csc) return (r); } while (0)

struct comm_socket_client {
	int sockfd;
};

comm_socket_client *_comm_socket_client_new(const char *server_sock_path)
{
	int fd = -1;
	fd = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		if (EINVAL == errno) {
			/* Try again, without SOCK_CLOEXEC option */
			fd = socket(AF_LOCAL, SOCK_STREAM, 0);
			if (fd < 0) {
				return NULL;
			}
		} else {
			return NULL;
		}
	}

	/* Try to connect to server_sock_path */
	struct sockaddr_un saddr = { 0, };

}

int _comm_socket_client_free(comm_socket_client *csc)
{
	CHK_CSC_RET(-EINVAL);
	free(csc);
	return 0;
}

