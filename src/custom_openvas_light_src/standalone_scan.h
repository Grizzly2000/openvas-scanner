//socket unix
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include <sys/wait.h>

// gvm stuff
#include <gvm/util/kb.h>

#define SERVER_SOCK_FILE "/tmp/server-openvas.sock"
#define CHUNK_SIZE 1024

#include "../openvas.h"
#include "../pluginload.h"

// Custom
#include "init_kb/init_scanprefs.h"
#include "init_kb/init_vars.h"
#include "utils/strings.h"


int run_standalone_scan(void);
int run_scan(char * data_JSON);
void * thread_loop_update_nvti(void*);
void * thread_loop_garbage_collector_zombies(void*);