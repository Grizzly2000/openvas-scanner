#include "init_vars.h"

// Init plugin_set : list of plugins to execute.
// Use nvticache to get plugins oid
// return char *. return NULL if an error occurs.
/*
char * init_buffer__plugin_set(){
      char * tmp__plugin_set = NULL;
      GSList *oids = nvticache_get_oids();

      if(!oids){
        return NULL;
      }

      concat_str(&tmp__plugin_set, "plugin_set|||");
      while(oids){
            concat_str(&tmp__plugin_set, (char*)oids->data);
            concat_str(&tmp__plugin_set, ";");
            oids = oids->next;
      }

    return KB_VALUE_plugins_discovery;
}*/


// Init port_range : port to use during the scan
// Use ports defined in init_vars.h
char * init_buffer__port_range(){
    return KB_VALUE_port_range;
}

