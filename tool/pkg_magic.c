#include <stdio.h>
#include <stdlib.h>
#include <magic.h>

#include "pkg_magic.h"

static const char const __mime_table[_MIME_MAX][12] = {"application", "audio", "image", "message", "model", "multipart", "text", "video"};

int get_mime_type(const char *file_path);


static magic_t __magic_cookie = NULL;

void  __magic_finalize(void)
{
	if (__magic_cookie) {
		magic_close(__magic_cookie);
	}
	return ;
}

int __magic_init(void)
{
	if (__magic_cookie != NULL) {
		return 0;
	}
	__magic_cookie = magic_open(MAGIC_MIME);
	if (__magic_cookie == NULL) {
		LOGE("unable to initialize magic library");
		return -1;
	}
	if (magic_load(__magic_cookie, NULL) != 0) {
		LOGE("cannot load magic database - %s", magic_error(__magic_cookie));
		magic_close(__magic_cookie);
		__magic_cookie = NULL;
		return -1;
	}
	atexit(__magic_finalize);
	return 0;
}

int get_mime_type(const char *file_path)
{
	int i = 0;

	if (__magic_init() < 0){
		LOGE("failed to initialize magic library");
		return -1;
	}

	const char *mime_str = magic_file(__magic_cookie, file_path);
	if (mime_str == NULL) {
		LOGE("failed to get mime type");
		return -1;
	}

	for (i = 0; i < _MIME_MAX; ++i) {
		if (strncmp(mime_str, __mime_table[i], 2) == 0) {
			return i;
		}
	}
	LOGE("failed to find mime type");
	return -1;
}
