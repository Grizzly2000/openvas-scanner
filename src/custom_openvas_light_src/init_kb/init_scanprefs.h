#include <stdio.h>
#include <string.h>
#include <json-glib/json-glib.h>

#include <hiredis/hiredis.h>
#include <gvm/base/nvti.h>      /* for prefs_get() */
#include <gvm/base/prefs.h>     /* for prefs_get() */
#include <gvm/util/kb.h>

#include "init_vars.h"

/**
 * @brief Subclass of struct kb, it contains the redis-specific fields, such as
 *        the redis context, current DB (namespace) id and the server socket
 *        path.
 */
struct kb_redis
{
  struct kb kb;        /**< Parent KB handle. */
  unsigned int max_db; /**< Max # of databases. */
  unsigned int db;     /**< Namespace ID number, 0 if uninitialized. */
  redisContext *rctx;  /**< Redis client context. */
  char *path[0];        /**< Path to the server socket. */
};
#define redis_kb(__kb) ((struct kb_redis *) (__kb))


// Init all scanprefs, return scan_id
char *  init_kb__scanprefs(char * data_JSON);

// Value provided to scan the target (interface, ip and/or creadentials)
//int init_kb__interface_value(kb_t kb_main, char * scan_id, char * interface);
int init_kb__ip_value(kb_t kb_main, char * scan_id, char * ip);
int init_kb__credentials_value(kb_t kb_main, char * scan_id, char * type, char * username, char * password);
int init_kb__plugin_set(kb_t kb_main, char * scan_id, char * plugin_set);
int init_kb__set_ov_maindbid(kb_t kb_main, char * scan_id);
int init_kb__port_range(kb_t kb_main, char * scan_id, char * port_range);

// Set default value belongs to "Full and Fast" template
int init_kb__default_port_range(kb_t kb_main, char * scan_id);
int init_kb__default_plugin_set(kb_t kb_main, char * scan_id, char * plugin_set);
int init_kb__default_scanprefs(kb_t kb_main, char * scan_id);
int init_kb__default_plugins_params(kb_t kb_main, char * scan_id);