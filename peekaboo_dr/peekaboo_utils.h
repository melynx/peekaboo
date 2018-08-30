#include <stdint.h>
#include "dr_api.h"

file_t file_open(client_id_t id, void *drcontext, const char *path, const char *name, uint32_t flags);

void file_close(file_t log);

