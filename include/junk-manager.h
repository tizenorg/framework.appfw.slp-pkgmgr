/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __JUNK_MANAGER_H__
#define __JUNK_MANAGER_H__

#include <package-manager.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *junkmgr_h;        /** junkmgr handle */
typedef void *junkmgr_result_h; /** junkmgr result handle */

typedef enum {
	JUNKMGR_CATEGORY_IMAGES = 0,    /** Images directory */
	JUNKMGR_CATEGORY_SOUNDS = 1,    /** Sounds directory */
	JUNKMGR_CATEGORY_VIDEOS = 2,    /** Videos directory */
	JUNKMGR_CATEGORY_CAMERA = 3,    /** Camera directory */
	JUNKMGR_CATEGORY_DOWNLOADS = 4, /** Downloads directory */
	JUNKMGR_CATEGORY_MUSIC = 5,     /** Music directory */
	JUNKMGR_CATEGORY_DOCUMENTS = 6, /** Documents directory */
	JUNKMGR_CATEGORY_OTHERS = 7,    /** Othres directory */
	JUNKMGR_CATEGORY_SYSTEM_RINGTONES = 8, /** System ringtones directory */
	JUNKMGR_CATEGORY_DCIM = 9,      /** DCIM directory */
	JUNKMGR_CATEGORY_MISC = 10      /** Directories not belonging to the category above */
} junkmgr_category_e;

typedef enum {
	JUNKMGR_FILE_TYPE_FILE = 0, /** File */
	JUNKMGR_FILE_TYPE_DIR = 1   /** Directory */
} junkmgr_file_type_e;

typedef enum {
	JUNKMGR_STORAGE_TYPE_INTERNAL = 0,  /** Internal storage */
	JUNKMGR_STORAGE_TYPE_EXTERNAL = 1   /** External storage */
} junkmgr_storage_type_e;

typedef enum {
	JUNKMGR_E_SUCCESS = 0,
	JUNKMGR_E_INVALID = -1,
	JUNKMGR_E_PRIV = -2,
	JUNKMGR_E_ACCESS = -3,
	JUNKMGR_E_NOMEM = -4,
	JUNKMGR_E_NOT_FOUND = -5,
	JUNKMGR_E_END_OF_RESULT = -6,
	JUNKMGR_E_OBJECT_LOCKED = -7,
	JUNKMGR_E_IO = -8,
	JUNKMGR_E_SYSTEM = -9
} junkmgr_error_e;

/**
 * @brief	Creates the junkmgr instance.
 *
 * @return	junkmgr handle on success, otherwise NULL
*/
junkmgr_h junkmgr_create_handle(void);

/**
 * @brief	Destroys the junkmgr instance.
 *
 * @param[in] junkmgr	junkmgr handle
 *
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	Invalid parameter
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_destroy_handle(junkmgr_h junkmgr);

/**
 * @brief		Called when searching the junk entries is completed.
 * @details		The specified handle is used to get information of junk files such as size.
 * @see			junkmgr_result_cursor_step_next()
 */
typedef void (*junkmgr_result_receive_cb)(int reqid, const junkmgr_result_h handle, void *user_data);

/**
 * @brief		Called when clearing the junk files are completed.
 */
typedef void (*junkmgr_clear_completed_cb)(int reqid, void *user_data);

/**
 * @brief		Gets the topmost directories including junk files.
 * @details		The root directories including junk files are asynchronously obtained by the specified callback function.
 *
 * @param[in] junkmgr	junkmgr handle
 * @param[in] result_cb	The asynchronous callback function to get the topmost directories including junk files
 * @param[in] user_data	User data to be passed to the callback function
 * @param[out] reqid	Request ID
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	    Invalid parameter
 * @retval #JUNKMGR_E_PRIV			Privilege denied
 * @retval #JUNKMGR_E_NOMEM	    	Insufficient memory
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_get_junk_root_dirs(junkmgr_h junkmgr, junkmgr_result_receive_cb result_cb, void *user_data, int *reqid);

/**
 * @brief		Gets the junk files.
 * @details		The junk files are asynchronously obtained by the specified callback function.
 *
 * @param[in] junkmgr	junkmgr handle
 * @param[in] junk_path	The root directory including junk files
 * @param[in] result_cb	The asynchronous callback function to get the junk files
 * @param[in] user_data	User data to be passed to the callback function
 * @param[out] reqid	Request ID
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	Invalid parameter
 * @retval #JUNKMGR_E_PRIV			Privilege denied
 * @retval #JUNKMGR_E_NOMEM	    	Insufficient memory
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_get_junk_files(junkmgr_h junkmgr, char const *junk_path, junkmgr_result_receive_cb result_cb, void *user_data, int *reqid);

/**
 * @brief	Moves the cursor to the next position.
 *
 * @param[in] handle	The pointer handling the result information for junk files
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	Invalid parameter
 * @retval #JUNKMGR_E_END_OF_RESULT	The cursor has reached out of the result set.
 * @retval #JUNKMGR_E_OBJECT_LOCKED The cursor is locked.
 * @retval #JUNKMGR_E_NOMEM	    	Insufficient memory
 * @retval #JUNKMGR_E_IO			I/O error
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_result_cursor_step_next(junkmgr_result_h handle);

/**
 * @brief	Gets the junk file name.
 * @remarks The returned junk name should be released.
 *
 * @param[in] handle		The pointer handling the result information for junk files
 * @param[out] junk_name	The junk file name
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	Invalid parameter
 * @retval #JUNKMGR_E_OBJECT_LOCKED The cursor is locked.
 * @retval #JUNKMGR_E_NOMEM	    	Insufficient memory
 * @retval #JUNKMGR_E_IO			I/O error
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_result_cursor_get_junk_name(junkmgr_result_h handle, char **junk_name);

/**
 * @brief	Gets the category.
 *
 * @param[in] handle		The pointer handling the result information for junk files
 * @param[out] category		The junk file name
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	Invalid parameter
 * @retval #JUNKMGR_E_OBJECT_LOCKED The cursor is locked.
 * @retval #JUNKMGR_E_NOMEM	    	Insufficient memory
 * @retval #JUNKMGR_E_IO			I/O error
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_result_cursor_get_category(junkmgr_result_h handle, junkmgr_category_e *category);

/**
 * @brief	Gets the file type.
 *
 * @param[in] handle		The pointer handling the result information for junk files
 * @param[out] file_type	The type is file or directory.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	Invalid parameter
 * @retval #JUNKMGR_E_OBJECT_LOCKED The cursor is locked.
 * @retval #JUNKMGR_E_NOMEM	    	Insufficient memory
 * @retval #JUNKMGR_E_IO			I/O error
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_result_cursor_get_file_type(junkmgr_result_h handle, junkmgr_file_type_e *file_type);

/**
 * @brief	Gets the storage type.
 *
 * @param[in] handle		The pointer handling the result information for junk files
 * @param[out] storage		The storage where junk files are stored
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	Invalid parameter
 * @retval #JUNKMGR_E_OBJECT_LOCKED The cursor is locked.
 * @retval #JUNKMGR_E_NOMEM	    	Insufficient memory
 * @retval #JUNKMGR_E_IO			I/O error
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_result_cursor_get_storage_type(junkmgr_result_h handle, junkmgr_storage_type_e *storage);

/**
 * @brief	Gets the size of the junk file.
 *
 * @param[in] handle		The pointer handling the result information for junk files
 * @param[out] junk_size	The file size of the junk file
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	Invalid parameter
 * @retval #JUNKMGR_E_OBJECT_LOCKED The cursor is locked.
 * @retval #JUNKMGR_E_NOMEM	    	Insufficient memory
 * @retval #JUNKMGR_E_IO			I/O error
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_result_cursor_get_junk_size(junkmgr_result_h handle, long long *junk_size);

/**
 * @brief	Gets the path of the junk file.
 * @remarks The returned junk path should be released.
 *
 * @param[in] handle		The pointer handling the result information for junk files
 * @param[out] junk_path	The path of the junk file
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS		Successful
 * @retval #JUNKMGR_E_INVALID	Invalid parameter
 * @retval #JUNKMGR_E_OBJECT_LOCKED The cursor is locked.
 * @retval #JUNKMGR_E_NOMEM	    	Insufficient memory
 * @retval #JUNKMGR_E_IO			I/O error
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_result_cursor_get_junk_path(junkmgr_result_h handle, char **junk_path);

/**
 *
 * @brief	Removes the specified junk file
 *
 * @param[in] junkmgr		junkmgr handle
 * @param[in] junk_path		The path of the specified junk file
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS       Successful
 * @retval #JUNKMGR_E_INVALID       Invalid parameter
 * @retval #JUNKMGR_E_PRIV          Privilege denied
 * @retval #JUNKMGR_E_ACCESS		Access denied
 * @retval #JUNKMGR_E_OBJECT_LOCKED The cursor is locked.
 * @retval #JUNKMGR_E_NOMEM         Insufficient memory
 * @retval #JUNKMGR_E_NOT_FOUND		Junk not found
 * @retval #JUNKMGR_E_SYSTEM        Internal error
 */
int junkmgr_remove_junk_file(junkmgr_h junkmgr, const char *junk_path);

/**
 * @brief	Remove all the junk files.
 *
 * @param[in] junkmgr		junkmgr handle
 * @param[in] result_cb		The asynchronous callback function called when clearing the junk files are completed.
 * @param[in] user_data		User data to be passed to the callback function
 * @param[out] reqid		Request ID
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #JUNKMGR_E_SUCCESS       Successful
 * @retval #JUNKMGR_E_INVALID       Invalid parameter
 * @retval #JUNKMGR_E_PRIV          Privilege denied
 * @retval #JUNKMGR_E_NOMEM         Insufficient memory
 * @retval #JUNKMGR_E_SYSTEM		Internal error
 */
int junkmgr_clear_all_junk_files(junkmgr_h junkmgr, junkmgr_clear_completed_cb result_cb, void *user_data, int *reqid);

#ifdef __cplusplus
}
#endif

#endif //__JUNK_MANAGER_H__
