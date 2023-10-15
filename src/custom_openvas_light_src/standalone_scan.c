#include "standalone_scan.h"

int run_standalone_scan(){
    // JSON data input from socket domain unix
    char data_JSON_chunk[CHUNK_SIZE+1] = {0};
    char * data_JSON = NULL;
    // socket stuff
    int sock, msgsock, rval;
    struct sockaddr_un server;

    pid_t child_pid;
    pthread_t thread_id_update_nvti;
    pthread_t thread_id_garbage_collector_zombies;


    /*char * data_JSON_chunk = \
    "{"
    "	\"ip\":\"172.17.2.209\","
    "	\"iface\":\"eth0\","
    "	\"credentials\":["
    "		{"
    "			\"type\":\"smb\","
    "			\"login\":\"admin\","
    "			\"password\":\"adminadmin\""
    "		},"
    "		{"
    "			\"type\":\"ssh\","
    "			\"login\":\"msfadmin\","
    "			\"password\":\"msfadmin\""
    "		}"
    "	]"
    "}";*/

    // debug read KB result
    /*plugins_init();
    get_json_result();
    exit(0);*/

    // Remove unix domain socket previously created
    remove(SERVER_SOCK_FILE);

    // Flush all KB !!! NE MARCHE PAS DU TOUT
    //printf("Flush KB all except nvti\n");
    //flush_all_kbs();

    // Init NVTs
    plugins_init();

    // Init plugin_set value (big value)
    //kb_value__plugin_set = init_buffer__plugin_set();
    // Init port_range (big value)


    // Init loop
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("opening stream socket");
        exit(1);
    }
    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, SERVER_SOCK_FILE);
    if (bind(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un))) {
        perror("binding stream socket");
        exit(1);
    }

    if(pthread_create (&thread_id_update_nvti, NULL, thread_loop_update_nvti, NULL))
    {
        printf("Thread ERROR !\n");
    }

    if(pthread_create (&thread_id_garbage_collector_zombies, NULL, thread_loop_garbage_collector_zombies, NULL))
    {
        printf("Thread ERROR !\n");
    }

    printf("Socket has name %s\n", server.sun_path);
    listen(sock, 5);
    // run scan with provided parameters

    for (;;) {
        msgsock = accept(sock, 0, 0);
        if (msgsock == -1)
        {
            perror("accept");
        }
        else do {
            memset(data_JSON_chunk, 0, sizeof(data_JSON_chunk));
            rval = recv(msgsock, data_JSON_chunk, CHUNK_SIZE, 0);
            if (rval < 0)
            {
                printf("reading stream message\n");
            }
            else if (rval == 0)
            {
                if (data_JSON)
                {
                    char * scan_id = init_kb__scanprefs(data_JSON);
                    free(data_JSON);
                    data_JSON = NULL;
                    if(scan_id)
                    {
                        //sleep(5);
                        //child_pid = create_process ((process_func_t) run_scan, &scan_id);

                        child_pid =  fork();
                        if(child_pid < 0)
                        {
                            printf("ERROR\n");
                        }
                        else if (child_pid == 0)
                        {
                            run_scan(scan_id);
                            exit(0);
                        }


                        /*if(pthread_create (&tid, NULL, run_scan, (void *) scan_id))
                        {
                            printf("Thread ERROR !\n");
                        }*/
                        //waitpid (child_pid, &ret, 0);
                    }
                }
            }
            else
            {
                concat_str(&data_JSON, data_JSON_chunk);
            }
        } while (rval > 0);
        close(msgsock);
    }
    close(sock);
    unlink(SERVER_SOCK_FILE);

    return 1;
}

void * thread_loop_update_nvti()
{
    int counter_refresh_plugin = 0;
    int max_refresh = 760; // 5(sleep) * 12 = 1 minute => 5(sleep) * 12 * 60 = 1 heure => 12 * 60 = 720.
    for(;;)
    {
        counter_refresh_plugin++;
        sleep(5);

        // Update plugins NASL every hour.
        if(counter_refresh_plugin == max_refresh)
        {
            printf("Refreshing DB\n");
            counter_refresh_plugin = 0;
            plugins_init();
        }
    }

    pthread_exit(NULL);
}

void* thread_loop_garbage_collector_zombies()
{
    for(;;)
    {
        while (waitpid(WAIT_ANY, NULL, WNOHANG) != 0)
        {
            sleep(5);
        }
    }
    pthread_exit(NULL);
}

int run_scan(char * scan_id)
{
    char key[1024];

    // Run scan using scan_id configuration
    start_single_task_scan(scan_id);

    // Delete db after the scan.
    snprintf (key, sizeof (key), "internal/%s", (char * )scan_id);
    kb_t kb;
    kb = kb_find (prefs_get ("db_address"), key);
    kb_delete (kb);

    //return 1;
    free(scan_id);
    return 1;
}
