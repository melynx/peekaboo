#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "peekaboo_utils.h"
#include "drx.h"

file_t file_open(client_id_t id, void *drcontext, const char *path, const char *name, uint32_t flags)
{
	file_t log;
	char log_dir[MAX_PATH];
	char buf[MAX_PATH];
	size_t len;
	char *dirsep;
	DR_ASSERT(name != NULL);

	path = (path == NULL) ? dr_get_client_path(id) : path;
	len = dr_snprintf(log_dir, MAX_PATH, "%s", path);
	DR_ASSERT(len > 0);

	// forcefully terminate the array...
	// locate the last '/', removing the file element
	log_dir[MAX_PATH-1] = 0;
	char *last_sep = strrchr(log_dir, '/');
	if (!last_sep) DR_ASSERT(false);
	*(last_sep+1) = 0;

	log = drx_open_unique_appid_file(log_dir, dr_get_process_id(), name, "log", flags, buf, MAX_PATH);
	if (log != INVALID_FILE)
	{
		char msg[MAX_PATH];
		len = dr_snprintf(msg, MAX_PATH, "Data file %s created.", buf);
		DR_ASSERT(len > 0);
		msg[MAX_PATH-1] = 0;
		dr_log(drcontext, DR_LOG_ALL, 1, "%s", msg);
	}
	else
	{
		DR_ASSERT(false);
	}
	return log;
}

void file_close(file_t log)
{
	dr_close_file(log);
}
