#include <dlog.h>

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "PKGMGR_JUNKINFO"
#endif				/* LOG_TAG */

enum _mime_type {
	_MIME_APPLICATION = 0,
	_MIME_AUDIO = 1,
	_MIME_IMAGE = 2,
	_MIME_MESSAGE = 3,
	_MIME_MODEL = 4,
	_MIME_MULTIPART = 5,
	_MIME_TEXT = 6,
	_MIME_VIDEO = 7,
	_MIME_MAX = 8
};


int get_mime_type(const char *file_path);
