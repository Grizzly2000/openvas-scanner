#include "init_scanprefs.h"

/*
JSON provided :
{
	"ip":"172.17.2.209",
	"iface":"eth0", // optionnal
	"credentials":[ // optionnal
		{
			"type":"ssh",
			"login":"msfadmin",
			"password":"msfadmin"
		}
	],
    "port_range":"port_range|||T:445",
	"plugin_set":"plugin_set|||<oid>;<oid>;<oid>;....",
	"scan_id":<uuid.uuid4>
}
*/

char *  init_kb__scanprefs(char * data_JSON)
{
    // JSON stuff
    JsonParser *parser = json_parser_new ();
    JsonReader *reader = json_reader_new (NULL);
    int json_value_size = 0;
    GError *error = NULL;
    char *scan_id_pattern = "internal/%s/scanprefs";
    // KB handler
    kb_t kb_main;
    // Connect to main kb to register scanprefs of the current target

    switch(kb_new(&kb_main, prefs_get("db_address")))
    {
        case -2:
            printf("Not enough DB available\n");
            return NULL;
        case -1:
            printf("Connection error\n");
            return NULL;
    }

    // Scan id
    // Set parameters provided from JSON data
    if (!json_parser_load_from_data (parser, data_JSON, strlen(data_JSON), &error)) {
        printf("error in parsing json data : %s\n", error->message);
        g_object_unref (parser);
        g_object_unref (reader);
        kb_delete (kb_main);
        return NULL;
    }

    // Get scan_id
    json_reader_set_root (reader, json_parser_get_root (parser));
    json_reader_read_member (reader, "scan_id");
    if(!json_reader_is_value (reader))
    {
        g_object_unref (parser);
        g_object_unref (reader);
        kb_delete (kb_main);
        printf("Error in scan_id JSON\n");
        return NULL;
    }
    json_value_size = strlen((char *)json_reader_get_string_value(reader)) + 1;
    char *scan_id = malloc (sizeof (char) * json_value_size);
    strncpy(scan_id, (char *)json_reader_get_string_value(reader), json_value_size);
    json_reader_end_element (reader);

    // init scan_id_key
    int scan_id_key_size = (strlen(scan_id_pattern) - 2) + json_value_size;
    char *scan_id_key = malloc (sizeof (char) * scan_id_key_size);
    snprintf (scan_id_key, scan_id_key_size, scan_id_pattern, scan_id);

    // Init scan_id in kb
    kb_item_add_str (kb_main, scan_id_key, "new", 0);
    // Init internal/scanid
    kb_item_add_str (kb_main, "internal/scanid", scan_id, 0);

    // Set target IP
    json_reader_set_root (reader, json_parser_get_root (parser));
    json_reader_read_member (reader, "ip");
    if(!json_reader_is_value (reader))
    {
        g_object_unref (parser);
        g_object_unref (reader);
        free(scan_id_key);
        kb_delete (kb_main);
        printf("Error in IP JSON\n");
        return NULL;
    }
    init_kb__ip_value(kb_main, scan_id_key, (char * )json_reader_get_string_value (reader));
    json_reader_end_element (reader);

    // Set interface
    /*json_reader_set_root (reader, json_parser_get_root (parser));
    json_reader_read_member (reader, "iface");
    if(!json_reader_is_value (reader))
    {
        g_object_unref (reader);
        g_object_unref (parser);
        free(scan_id_key);
        kb_delete (kb_main);
        printf("Error in iface JSON\n");
        return NULL;
    }
    init_kb__interface_value(kb_main, scan_id_key, (char * )json_reader_get_string_value (reader));
    json_reader_end_element (reader);*/

    // Set plugin_set : list of oid built from openvas template : Discovery, Full and Fast or only run a specific plugin
    json_reader_set_root (reader, json_parser_get_root (parser));
    json_reader_read_member (reader, "plugin_set");
    if(!json_reader_is_value (reader))
    {
        printf("Error in plugin_set JSON\n");
        g_object_unref (reader);
        g_object_unref (parser);
        free(scan_id_key);
        kb_delete (kb_main);
        return NULL;
    }
    init_kb__plugin_set(kb_main, scan_id_key, (char * )json_reader_get_string_value (reader));
    json_reader_end_element (reader);

    // Set port_range
    json_reader_set_root (reader, json_parser_get_root (parser));
    json_reader_read_member (reader, "port_range");
    if(!json_reader_is_value (reader))
    {
        printf("Error in port_range JSON\n");
        g_object_unref (reader);
        g_object_unref (parser);
        free(scan_id_key);
        kb_delete (kb_main);
        return NULL;
    }
    init_kb__port_range(kb_main, scan_id_key, (char * )json_reader_get_string_value (reader));
    json_reader_end_element (reader);

    // Set credentials
    json_reader_set_root (reader, json_parser_get_root (parser));
    json_reader_read_member (reader, "credentials");
    if (json_reader_is_array (reader))
    {
        unsigned int creds_len = json_reader_count_elements (reader);
        for(unsigned int i = 0; i < creds_len; i++)
        {

            json_reader_read_element (reader, i);
            if(json_reader_is_object (reader))
            {
                json_reader_read_member (reader, "type");
                char * type = (char *)json_reader_get_string_value(reader);
                json_reader_end_element (reader);

                json_reader_read_member (reader, "login");
                char * username = (char *)json_reader_get_string_value(reader);
                json_reader_end_element (reader);

                json_reader_read_member (reader, "password");
                char * password = (char *)json_reader_get_string_value(reader);
                json_reader_end_element (reader);

                init_kb__credentials_value(kb_main, scan_id_key, type, username, password);

                json_reader_end_element (reader);
            }
        }
    }
    json_reader_end_element (reader);

    // Set default value

    // Set ov_maindbid TODO
    init_kb__set_ov_maindbid(kb_main, scan_id_key);
    // Set port_range
    //init_kb__default_port_range(kb_main, scan_id_key);
    // Set default scanprefs TODO : brute force disabled ?
    init_kb__default_scanprefs(kb_main, scan_id_key);
    // Set plugins parameters
    init_kb__default_plugins_params(kb_main, scan_id_key);

    // free json stuff
    g_object_unref (reader);
    g_object_unref (parser);
    free(scan_id_key);

    return scan_id;
}

int init_kb__plugin_set(kb_t kb_main, char * scan_id, char * plugin_set)
{
    kb_item_add_str (kb_main, scan_id, plugin_set, 0);
    return 1;
}

int init_kb__port_range(kb_t kb_main, char * scan_id, char * port_range)
{
    kb_item_add_str (kb_main, scan_id, port_range, 0);
    return 1;
}

/*
int init_kb__interface_value(kb_t kb_main, char * scan_id, char * interface)
{
    char value[300];
    char * value_pattern = "source_iface|||%s";
    snprintf (value, sizeof (value), value_pattern, interface);
    kb_item_add_str (kb_main, scan_id, value, 0);
    return 1;
}
*/
int init_kb__ip_value(kb_t kb_main, char * scan_id, char * ip)
{
    char value[300]; // TODO plusieurs ip
    char * value_pattern = "TARGET|||%s";
    printf("New scan - %s (%s)\n", ip, scan_id);
    snprintf (value, sizeof (value), value_pattern, ip);
    kb_item_add_str (kb_main, scan_id, value, 0);
    return 1;
}

int init_kb__credentials_value(kb_t kb_main, char * scan_id, char * type, char * username, char * password)
{
    if (strcmp(type, "smb") == 0)
    {
        char * smb_login_pattern = "1.3.6.1.4.1.25623.1.0.90023:1:entry:SMB login:|||%s";
        char * smb_password_pattern = "1.3.6.1.4.1.25623.1.0.90023:2:password:SMB password:|||%s";
        char value_login[500];
        char value_password[500];

        snprintf (value_login, sizeof (value_login), smb_login_pattern, username);
        snprintf (value_password, sizeof (value_password), smb_password_pattern, password);

        kb_item_add_str (kb_main, scan_id, value_login, 0);
        kb_item_add_str (kb_main, scan_id, value_password, 0);
    }
    else if (strcmp(type, "esxi") == 0)
    {
        char * esxi_login_pattern = "1.3.6.1.4.1.25623.1.0.105058:1:entry:ESXi login name:|||%s";
        char * esxi_password_pattern = "1.3.6.1.4.1.25623.1.0.105058:2:password:ESXi login password:|||%s";
        char value_login[500];
        char value_password[500];

        snprintf (value_login, sizeof (value_login), esxi_login_pattern, username);
        snprintf (value_password, sizeof (value_password), esxi_password_pattern, password);

        kb_item_add_str (kb_main, scan_id, value_login, 0);
        kb_item_add_str (kb_main, scan_id, value_password, 0);
    }
    else if (strcmp(type, "ssh") == 0)
    {
        char * ssh_login_pattern = "1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login name:|||%s";
        char * ssh_password_pattern = "1.3.6.1.4.1.25623.1.0.103591:3:password:SSH password (unsafe!):|||%s";
        char value_login[500];
        char value_password[500];

        snprintf (value_login, sizeof (value_login), ssh_login_pattern, username);
        snprintf (value_password, sizeof (value_password), ssh_password_pattern, password);

        kb_item_add_str (kb_main, scan_id, value_login, 0);
        kb_item_add_str (kb_main, scan_id, value_password, 0);
        kb_item_add_str (kb_main, scan_id, "auth_port_ssh|||22", 0);
    }
    return 1;
}

int init_kb__default_port_range(kb_t kb_main, char * scan_id)
{
    kb_item_add_str (kb_main, scan_id, init_buffer__port_range(), 0);
    return 1;
}

int init_kb__default_plugin_set(kb_t kb_main, char * scan_id, char * plugin_set)
{
    kb_item_add_str (kb_main, scan_id, plugin_set, 0);
    return 1;
}


int init_kb__set_ov_maindbid(kb_t kb_main, char * scan_id)
{
    char value[300];

    struct kb_redis *kbr;
    kbr = redis_kb(kb_main); // TODO risqueeeeuuuh ????
    printf("db id : %d\n",kbr->db);

    char * value_pattern = "ov_maindbid|||%d";
    snprintf (value, sizeof (value), value_pattern, kbr->db);
    kb_item_add_str (kb_main, scan_id, value, 0); // TODO a étudier
    return 1;
}

int init_kb__default_scanprefs(kb_t kb_main, char * scan_id)
{
    kb_item_add_str (kb_main, scan_id, "exclude_hosts|||1.1.1.1", 0);
    kb_item_add_str (kb_main, scan_id, "unscanned_closed|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "plugins_timeout|||320", 0);
    kb_item_add_str (kb_main, scan_id, "unscanned_closed_udp|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "timeout_retry|||3", 0);
    kb_item_add_str (kb_main, scan_id, "non_simult_ports|||139, 445, 3389, Services/irc", 0);
    kb_item_add_str (kb_main, scan_id, "hosts_ordering|||sequential", 0);
    kb_item_add_str (kb_main, scan_id, "optimize_test|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "max_checks|||4", 0);
    kb_item_add_str (kb_main, scan_id, "scanner_plugins_timeout|||36000", 0);
    kb_item_add_str (kb_main, scan_id, "cgi_path|||/cgi-bin:/scripts", 0);
    kb_item_add_str (kb_main, scan_id, "report_host_details|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "open_sock_max_attempts|||5", 0);
    kb_item_add_str (kb_main, scan_id, "time_between_request|||0", 0);
    kb_item_add_str (kb_main, scan_id, "expand_vhosts|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "test_empty_vhost|||no", 0);
    kb_item_add_str (kb_main, scan_id, "checks_read_timeout|||5", 0);
    kb_item_add_str (kb_main, scan_id, "auto_enable_dependencies|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "max_hosts|||20", 0);
    kb_item_add_str (kb_main, scan_id, "safe_checks|||yes", 0);
    return 1;
}

int init_kb__default_plugins_params(kb_t kb_main, char * scan_id)
{
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100206:0:entry:timeout|||3600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:0:entry:timeout|||1440", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103482:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103550:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103625:1:checkbox:Enable|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103807:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103940:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103978:1:checkbox:Silent|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103997:0:entry:timeout|||3600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105211:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10662:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.107305:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.107307:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108013:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108041:0:entry:timeout|||1800", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108157:1:checkbox:Enable|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108346:0:entry:timeout|||720", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108439:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108525:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108562:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108564:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:1:checkbox:NTLMSSP|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108708:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108717:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109040:1:radio:Berichtformat|||Text", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109074:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109094:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109095:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109102:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109152:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109170:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109193:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109194:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109220:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109227:1:entry:Value|||None", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109231:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109232:1:radio:DES-CBC-CRC|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109232:2:radio:DES-CBC-MD5|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109232:3:radio:RC4-HMAC|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109232:4:radio:AES128-CTS-HMAC-SHA1-96|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109232:5:radio:AES256-CTS-HMAC-SHA1-96|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109233:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109234:1:radio:Value|||5", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109241:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109242:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109243:1:radio:Value|||2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109244:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109245:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109246:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109247:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109248:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109249:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109264:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109266:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109267:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109268:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109270:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109271:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109272:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109282:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109286:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109297:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109306:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109307:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109313:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109315:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109339:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109353:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109364:1:radio:Value|||2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109365:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109366:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109368:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109369:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109378:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109379:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109381:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109382:1:entry:Value|||2.16.840.1.101.3.4.1.2;2.16.840.1.101.3.4.1.42", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109388:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109396:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109398:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109399:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109400:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109404:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109406:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109417:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109418:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109419:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109420:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109430:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109434:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109447:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109448:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109449:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109450:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109452:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109464:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109465:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109466:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109467:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109468:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109472:1:entry:Maximum|||900000", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109473:1:entry:Maximum|||60000", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109474:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109475:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109478:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109480:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109481:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109484:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109485:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109486:1:radio:Value|||Warn", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109487:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109488:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109489:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109494:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109497:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109498:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109519:1:radio:Value|||3", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109520:1:radio:Value|||2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109521:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109522:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109523:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109524:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109527:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109533:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109535:1:radio:Value|||1000000000000", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109542:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109543:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109546:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109547:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109548:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109552:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109553:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109554:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109555:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109556:1:entry:Value|||%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109557:1:entry:Minimum|||16384", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109558:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109559:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109560:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109561:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109562:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109563:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109564:1:entry:Value|||%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109565:1:entry:Minimum|||16384", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109566:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109567:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109568:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109569:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109570:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109571:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109572:1:entry:Value|||%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109573:1:entry:Minimum|||16384", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109574:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109575:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109589:1:radio:Value|||Success", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109601:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109604:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109605:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109606:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109607:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109608:1:radio:Value|||AllSigned", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109610:1:entry:Proxy|||None", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109616:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109682:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109688:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109689:1:radio:Value|||3", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109714:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109715:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109716:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109717:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109718:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109719:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109720:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109721:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109722:1:entry:Options|||nodev,nosuid,noexec", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109724:1:entry:Options|||nodev,nosuid,noexec", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109725:1:entry:Options|||nodev,nosuid,noexec", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109726:1:entry:Options|||nodev,nosuid,noexec", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109727:1:entry:Options|||nodev,nosuid,noexec", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109728:1:entry:Options|||nodev,nosuid,noexec", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109735:1:radio:Status|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109737:1:radio:Status|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109740:1:radio:Status|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109755:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109756:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109757:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109758:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109759:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109760:1:radio:Status|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109761:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109762:1:radio:Status|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109763:1:radio:Status|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109764:1:radio:Status|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109765:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109801:1:entry:Days|||30", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109887:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109907:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109909:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109910:1:entry:Value|||*", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109931:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109932:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109933:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109934:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109935:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109936:1:radio:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109937:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11032:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.111013:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.111022:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.111084:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.111108:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11139:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.112798:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.113634:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.116000:1:radio:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140853:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14788:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150060:1:entry:Options|||nodev,nosuid,noexec", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150066:1:entry:Value|||2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150067:1:radio:Value|||INFO", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150068:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150069:1:entry:Value|||4", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150070:1:radio:Value|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150071:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150072:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150073:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150074:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150075:1:entry:Value|||3", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150076:1:entry:Value|||/etc/issue.net", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150077:1:entry:Value|||curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150078:1:entry:Value|||3", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150079:1:entry:Value|||300", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150084:1:entry:Value|||root:root", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150085:1:entry:Value|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150086:1:entry:Value|||tcpd", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150090:1:entry:Value|||644", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150091:1:entry:Value|||root:root", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150092:1:entry:Value|||root:root", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150093:1:entry:Value|||644", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150095:1:entry:Value|||IPv4,IPv6", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150102:1:entry:Permissions|||700", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150102:2:entry:Owner|||root:root", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150103:1:entry:Permissions|||700", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150103:2:entry:Owner|||root:root", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150107:1:entry:Value|||/root", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150108:1:entry:Value|||/bin/bash,/bin/csh,/bin/jsh,/bin/ksh,/bin/rbash,/bin/sh,/bin/tcsh,/bin/zsh,/bin/false,/usr/bin/bash,/sbin/jsh,/sbin/sh,/usr/bin/csh,/usr/bin/jsh,/usr/bin/ksh,/usr/bin/sh,/usr/bin/rksh,/usr/bin/tcsh,/usr/sbin/ksh", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150109:1:entry:Whitelist|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150112:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150118:1:radio:Value|||No", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150120:1:entry:Value|||root:root", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150121:1:radio:Value|||No", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150122:1:entry:Value|||644", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150123:1:entry:Value|||root:root", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150124:1:radio:Value|||No", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150126:1:radio:Value|||Yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150127:1:radio:Value|||Yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150128:1:entry:Value|||1800", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150131:1:entry:Value|||5", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150132:1:entry:Value|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150134:1:entry:Value|||sha512", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150136:1:radio:Value|||Yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150139:1:radio:Value|||Yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150144:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150145:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150146:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150150:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150151:1:radio:Status|||Disabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150152:1:entry:Value|||4096", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150153:1:entry:Value|||60", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150157:1:radio:Value|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150158:1:entry:Value|||/var/log/auth.log,/var/log/authlog", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150159:1:entry:Value|||/var/log/authlog", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150160:1:entry:Value|||/var/log/syslog", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150161:1:entry:Value|||/var/log/daemon.log", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150162:1:entry:Value|||/var/log/cron", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150164:1:entry:Value|||@@loghost.example.com", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150166:1:entry:Value|||/var/log/kern_emerg.log,/dev/console", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150167:1:entry:Value|||application1,application2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150168:1:entry:Value|||/var/log/kernel.log", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150169:1:entry:Value|||/var/log/secure.log", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150171:1:radio:Value|||enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150172:1:radio:Value|||enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150174:1:entry:Value|||ip1,ip2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150175:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150177:1:entry:Value|||/sbin/sulogin", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150183:1:radio:Value|||none", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150187:1:entry:Value|||700", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150188:1:entry:Value|||700", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150189:1:entry:Value|||700", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150190:1:entry:Value|||700", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150191:1:entry:Value|||700", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150192:1:entry:Value|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150193:1:entry:Value|||400", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150197:1:entry:Value|||69", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150197:2:entry:Maximum|||8192", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150198:1:radio:Value|||TRUE", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150202:1:entry:Value|||60", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150203:1:radio:Value|||FALSE", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150204:1:radio:Value|||TRUE", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150206:1:entry:Value|||60", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150207:1:entry:Value|||3", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150208:1:entry:Value|||10", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150209:1:entry:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150210:1:entry:Value|||90", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150211:1:entry:Value|||7", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150212:1:entry:Value|||30", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150212:2:entry:Maximum|||800", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150213:1:radio:Value|||TRUE", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150214:1:entry:Value|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150215:1:entry:Value|||/home/gaussdba/data/log", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150216:1:entry:Value|||10M", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150217:1:entry:Value|||10", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150218:1:entry:Value|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150219:1:entry:Value|||700", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150220:1:entry:Value|||7", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150222:1:radio:Value|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150223:1:radio:Value|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150224:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150225:1:entry:Value|||aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150226:1:radio:Value|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150227:1:radio:Value|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150228:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150229:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150230:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150231:1:radio:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150232:1:entry:Value|||subsystem", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150233:1:radio:Value|||AUTH", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150259:1:entry:User|||SYS", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150259:2:password:Password|||Changeme_123", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150259:3:entry:IP|||127.0.0.1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150259:4:entry:Port|||1611", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150259:5:entry:GSDB_HOME|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150259:6:entry:GSDB_DATA|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150263:1:entry:Blacklist|||binary1,binary2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150265:1:entry:Blacklist|||service1,service2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150266:1:entry:Value|||3", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150267:1:entry:Value|||14", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150271:1:entry:Value|||400", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150276:1:entry:Value|||7", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150321:1:checkbox:Value|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150403:1:entry:Database|||postgres", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150403:2:entry:Port|||26000", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150404:1:entry:Database|||postgres", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150404:2:entry:Port|||8000", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.66286:0:entry:timeout|||900", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.804489:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900234:0:entry:timeout|||3600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900239:1:checkbox:Silent|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.902269:0:entry:timeout|||360", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.94171:1:radio:Berichtformat|||Text", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96047:1:radio:Value|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96100:0:entry:timeout|||2400", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96104:0:entry:timeout|||2400", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96171:1:checkbox:Enable|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96180:0:entry:timeout|||600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:9:checkbox:Report about reachable Hosts|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:6:checkbox:Report about unrechable Hosts|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:11:entry:POP3 account :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:13:entry:IMAP account :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:2:entry:HTTP account :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:4:entry:NNTP account :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:9:entry:POP2 account :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:6:entry:FTP account :|||anonymous", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:10:entry:nmap additional ports for -PA|||137,587,3128,8081", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80086:2:entry:From address :|||nobody@example.com", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11033:1:entry:From address :|||OpenVASVT <listme@listme.dsbl.org>", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80086:3:entry:To address :|||postmaster@[AUTO_REPLACED_IP]", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109795:1:entry:MAC algorithms|||hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103940:2:checkbox:List all and not only the first 100 entries|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96180:1:checkbox:List all and not only the first 100 entries|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11748:1:checkbox:Check all detected CGI directories:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:24:checkbox:1.6 Allow Docker to make changes to iptables.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105778:1:radio:Minimum allowed TLS version:|||TLS 1.2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109587:1:radio:Value|||Success and Failure", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109588:1:radio:Value|||Success and Failure", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.112060:1:checkbox:Collect and report Microsoft Windows DNS Cache|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:3:checkbox:Do an ICMP ping|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105420:2:password:NSX API Password:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105420:1:entry:NSX API Username:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11033:5:checkbox:No archive|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:4:checkbox:Use ARP|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:25:checkbox:No ARP or ND Ping|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:1:checkbox:Do a TCP ping|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96104:1:checkbox:BruteForce Attacke with Default-Usern and -Passwords|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:36:checkbox:5.8 Avoid container sprawl.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:32:checkbox:5.7 Avoid image sprawl.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:16:radio:PCI-DSS Berichtsprache/Report Language|||Deutsch", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:40:checkbox:4.6 Bind incoming container traffic to a specific host interface.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103697:3:checkbox:Disable brute force checks|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:18:checkbox:Disable caching of web pages during CGI scanning|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:17:checkbox:Random case sensitivity (Nikto only)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:6:file:SSL certificate :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:2:checkbox:Enable CGI scanning|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.804489:1:checkbox:Shellshock: Check CGIs in KB:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:49:checkbox:2.2 Check default cgroup usage.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105778:2:checkbox:Perform check:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140038:1:checkbox:Perform check:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:1:checkbox:Perform check:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96176:1:checkbox:Perform check:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103940:1:file:Target checksum File|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96180:4:file:Target checksum File|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:100:radio:TLS_DHE_PSK_WITH_NULL_SHA384|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:101:radio:TLS_RSA_PSK_WITH_NULL_SHA384|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:102:radio:TLS_ECDHE_PSK_WITH_NULL_SHA384|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:107:radio:TLS_RSA_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:108:radio:TLS_FORTEZZA_KEA_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:109:radio:TLS_PSK_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:10:radio:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:110:radio:TLS_DHE_PSK_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:111:radio:TLS_RSA_PSK_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:112:radio:TLS_ECDH_ECDSA_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:113:radio:TLS_ECDHE_ECDSA_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:114:radio:TLS_ECDH_RSA_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:115:radio:TLS_ECDHE_RSA_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:116:radio:TLS_ECDH_anon_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:117:radio:TLS_ECDHE_PSK_WITH_NULL_SHA|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:11:radio:TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:125:radio:TLS_RSA_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:126:radio:TLS_KRB5_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:127:radio:TLS_DHE_DSS_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:128:radio:TLS_PSK_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:129:radio:TLS_DHE_PSK_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:12:radio:TLS_PSK_WITH_CHACHA20_POLY1305_SHA256|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:130:radio:TLS_RSA_PSK_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:131:radio:TLS_ECDH_ECDSA_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:132:radio:TLS_ECDHE_ECDSA_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:133:radio:TLS_ECDH_RSA_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:134:radio:TLS_ECDHE_RSA_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:135:radio:TLS_ECDH_anon_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:136:radio:TLS_ECDHE_PSK_WITH_RC4_128_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:137:radio:TLS_NULL_WITH_NULL_NULL|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:138:radio:TLS_RSA_EXPORT_WITH_RC4_40_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:139:radio:TLS_DH_anon_EXPORT_WITH_RC4_40_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:13:radio:TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:140:radio:TLS_KRB5_WITH_DES_CBC_MD5|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:141:radio:TLS_KRB5_WITH_3DES_EDE_CBC_MD5|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:142:radio:TLS_KRB5_WITH_IDEA_CBC_MD5|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:143:radio:TLS_KRB5_EXPORT_WITH_RC4_40_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:144:radio:TLS_RSA_WITH_AES_128_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:145:radio:TLS_DHE_RSA_WITH_AES_128_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:146:radio:TLS_PSK_WITH_AES_128_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:147:radio:TLS_DHE_PSK_WITH_AES_128_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:148:radio:TLS_ECDHE_ECDSA_WITH_AES_128_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:149:radio:TLS_RSA_WITH_NULL_MD5|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:14:radio:TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:150:radio:TLS_RSA_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:151:radio:TLS_RSA_WITH_AES_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:152:radio:TLS_DH_DSS_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:153:radio:TLS_DH_RSA_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:154:radio:TLS_DHE_DSS_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:155:radio:TLS_DHE_RSA_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:156:radio:TLS_DH_DSS_WITH_AES_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:157:radio:TLS_DH_RSA_WITH_AES_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:158:radio:TLS_DHE_DSS_WITH_AES_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:159:radio:TLS_DHE_RSA_WITH_AES_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:15:radio:TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:160:radio:TLS_DH_anon_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:161:radio:TLS_DH_anon_WITH_AES_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:162:radio:TLS_RSA_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:163:radio:TLS_DHE_RSA_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:164:radio:TLS_DH_RSA_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:165:radio:TLS_DHE_DSS_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:166:radio:TLS_DH_DSS_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:167:radio:TLS_DH_anon_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:168:radio:TLS_PSK_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:169:radio:TLS_DHE_PSK_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:170:radio:TLS_RSA_PSK_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:171:radio:TLS_PSK_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:172:radio:TLS_DHE_PSK_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:173:radio:TLS_RSA_PSK_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:174:radio:TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:175:radio:TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:176:radio:TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:177:radio:TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:178:radio:TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:179:radio:TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:180:radio:TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:181:radio:TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:182:radio:TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:183:radio:TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:184:radio:TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:185:radio:TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:186:radio:TLS_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:187:radio:TLS_AES_128_CCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:188:radio:TLS_AES_128_CCM_8_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:189:radio:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:190:radio:TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:191:radio:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:192:radio:TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:193:radio:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:194:radio:TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:195:radio:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:196:radio:TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:197:radio:TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:198:radio:TLS_RSA_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:199:radio:TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:1:radio:TLS_RSA_WITH_RC4_128_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:200:radio:TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:201:radio:TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:202:radio:TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:203:radio:TLS_DH_anon_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:204:radio:TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:205:radio:TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:206:radio:TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:207:radio:TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:208:radio:TLS_RSA_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:209:radio:TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:210:radio:TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:211:radio:TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:212:radio:TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:213:radio:TLS_DH_anon_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:214:radio:TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:215:radio:TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:216:radio:TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:217:radio:TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:218:radio:TLS_PSK_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:219:radio:TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:220:radio:TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:221:radio:TLS_PSK_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:222:radio:TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:223:radio:TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:224:radio:TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:225:radio:TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:226:radio:TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:227:radio:TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:228:radio:TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:229:radio:TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:230:radio:TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:231:radio:TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:232:radio:TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:233:radio:TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:234:radio:TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:235:radio:TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:236:radio:TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:237:radio:TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:238:radio:TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:239:radio:TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:240:radio:TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:241:radio:TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:242:radio:TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:243:radio:TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:244:radio:TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:245:radio:TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:246:radio:TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:247:radio:TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:248:radio:TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:249:radio:TLS_RSA_EXPORT_WITH_DES40_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:250:radio:TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:251:radio:TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:252:radio:TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:253:radio:TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:254:radio:TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:255:radio:TLS_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:257:radio:TLS_RSA_WITH_SEED_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:258:radio:TLS_RSA_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:259:radio:TLS_DHE_RSA_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:260:radio:TLS_DH_RSA_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:261:radio:TLS_DHE_DSS_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:262:radio:TLS_DH_DSS_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:263:radio:TLS_DH_anon_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:264:radio:TLS_PSK_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:265:radio:TLS_DHE_PSK_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:266:radio:TLS_RSA_PSK_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:267:radio:TLS_PSK_WITH_AES_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:268:radio:TLS_DHE_PSK_WITH_AES_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:269:radio:TLS_RSA_PSK_WITH_AES_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:270:radio:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:271:radio:TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:272:radio:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:273:radio:TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:274:radio:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:275:radio:TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:276:radio:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:277:radio:TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:278:radio:TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:279:radio:TLS_RSA_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:280:radio:TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:281:radio:TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:282:radio:TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:283:radio:TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:284:radio:TLS_DH_anon_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:285:radio:TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:286:radio:TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:287:radio:TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:288:radio:TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:289:radio:TLS_RSA_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:28:radio:TLS_AES_256_GCM_SHA384|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:290:radio:TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:291:radio:TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:292:radio:TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:293:radio:TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:294:radio:TLS_DH_anon_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:295:radio:TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:296:radio:TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:297:radio:TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:298:radio:TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:299:radio:TLS_PSK_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:2:radio:TLS_DH_anon_WITH_RC4_128_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:300:radio:TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:301:radio:TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:302:radio:TLS_PSK_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:303:radio:TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:304:radio:TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:305:radio:TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:306:radio:TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:307:radio:TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:308:radio:TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:309:radio:TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:310:radio:TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:311:radio:TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:312:radio:TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:313:radio:TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:314:radio:TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:315:radio:TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:316:radio:TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:317:radio:TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:318:radio:TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:319:radio:TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:320:radio:TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:321:radio:TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:322:radio:TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:323:radio:TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:324:radio:TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:325:radio:TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:326:radio:TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:327:radio:TLS_RSA_WITH_AES_128_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:328:radio:TLS_RSA_WITH_AES_256_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:329:radio:TLS_DHE_RSA_WITH_AES_128_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:32:radio:TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:330:radio:TLS_DHE_RSA_WITH_AES_256_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:331:radio:TLS_PSK_WITH_AES_128_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:332:radio:TLS_PSK_WITH_AES_256_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:333:radio:TLS_PSK_DHE_WITH_AES_128_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:334:radio:TLS_PSK_DHE_WITH_AES_256_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:335:radio:TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:336:radio:TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:337:radio:TLS_RSA_WITH_IDEA_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:338:radio:TLS_RSA_WITH_DES_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:339:radio:TLS_RSA_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:340:radio:TLS_DH_DSS_WITH_DES_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:341:radio:TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:342:radio:TLS_DH_RSA_WITH_DES_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:343:radio:TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:344:radio:TLS_DHE_DSS_WITH_DES_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:345:radio:TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:346:radio:TLS_DHE_RSA_WITH_DES_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:347:radio:TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:348:radio:TLS_DH_anon_WITH_DES_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:349:radio:TLS_DH_anon_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:350:radio:TLS_KRB5_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:351:radio:TLS_KRB5_WITH_IDEA_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:352:radio:TLS_RSA_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:353:radio:TLS_DH_DSS_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:354:radio:TLS_DH_RSA_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:355:radio:TLS_DHE_DSS_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:356:radio:TLS_DHE_RSA_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:357:radio:TLS_DH_anon_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:358:radio:TLS_RSA_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:359:radio:TLS_RSA_WITH_CAMELLIA_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:360:radio:TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:361:radio:TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:362:radio:TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:363:radio:TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:364:radio:TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:365:radio:TLS_RSA_WITH_CAMELLIA_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:366:radio:TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:367:radio:TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:368:radio:TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:369:radio:TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:370:radio:TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:371:radio:TLS_PSK_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:372:radio:TLS_PSK_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:373:radio:TLS_PSK_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:374:radio:TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:375:radio:TLS_DHE_PSK_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:376:radio:TLS_DHE_PSK_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:377:radio:TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:378:radio:TLS_RSA_PSK_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:379:radio:TLS_RSA_PSK_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:380:radio:TLS_DH_DSS_WITH_SEED_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:381:radio:TLS_DH_RSA_WITH_SEED_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:382:radio:TLS_DHE_DSS_WITH_SEED_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:383:radio:TLS_DHE_RSA_WITH_SEED_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:384:radio:TLS_DH_anon_WITH_SEED_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:385:radio:TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:386:radio:TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:387:radio:TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:388:radio:TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:389:radio:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:390:radio:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:391:radio:TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:392:radio:TLS_ECDH_RSA_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:393:radio:TLS_ECDH_RSA_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:394:radio:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:395:radio:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:396:radio:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:397:radio:TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:398:radio:TLS_ECDH_anon_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:399:radio:TLS_ECDH_anon_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:3:radio:TLS_KRB5_WITH_RC4_128_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:400:radio:TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:401:radio:TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:402:radio:TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:403:radio:TLS_SRP_SHA_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:404:radio:TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:405:radio:TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:406:radio:TLS_SRP_SHA_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:407:radio:TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:408:radio:TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:409:radio:TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:410:radio:TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:411:radio:TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:4:radio:TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:55:radio:TLS_DH_DSS_WITH_AES_256_CBC_SHA|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:56:radio:TLS_DH_RSA_WITH_AES_256_CBC_SHA|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:57:radio:TLS_DHE_DSS_WITH_AES_256_CBC_SHA|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:58:radio:TLS_DHE_RSA_WITH_AES_256_CBC_SHA|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:59:radio:TLS_DH_anon_WITH_AES_256_CBC_SHA|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:5:radio:TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:62:radio:TLS_RSA_WITH_NULL_SHA256|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:63:radio:TLS_RSA_EXPORT1024_WITH_RC4_56_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:64:radio:TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:65:radio:TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:66:radio:TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:67:radio:TLS_RSA_EXPORT1024_WITH_RC4_56_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:68:radio:TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:69:radio:TLS_PSK_WITH_NULL_SHA256|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:70:radio:TLS_DHE_PSK_WITH_NULL_SHA256|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:71:radio:TLS_RSA_PSK_WITH_NULL_SHA256|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:72:radio:TLS_ECDHE_PSK_WITH_NULL_SHA256|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:73:radio:TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:74:radio:TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:75:radio:TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:82:radio:TLS_RSA_WITH_AES_256_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:83:radio:TLS_DHE_RSA_WITH_AES_256_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:84:radio:TLS_PSK_WITH_AES_256_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:85:radio:TLS_DHE_PSK_WITH_AES_256_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:86:radio:TLS_ECDHE_ECDSA_WITH_AES_256_CCM|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:87:radio:TLS_KRB5_EXPORT_WITH_RC4_40_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:8:radio:TLS_CHACHA20_POLY1305_SHA256|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:99:radio:TLS_PSK_WITH_NULL_SHA384|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:9:radio:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:17:entry:Testuser Common Name|||CN", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96055:1:entry:Testuser Common Name|||CN", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96170:1:entry:Testuser Common Name|||CN", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10747:1:checkbox:Use complete password list (not only vendor specific passwords)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.17638:1:checkbox:Use complete password list (not only vendor specific passwords)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.18414:1:checkbox:Use complete password list (not only vendor specific passwords)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.18415:1:checkbox:Use complete password list (not only vendor specific passwords)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.23938:1:checkbox:Use complete password list (not only vendor specific passwords)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:15:checkbox:Launch Compliance Test|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109741:1:entry:Policy configuration|||targeted", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:33:checkbox:1.9 Configure TLS authentication.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:19:checkbox:5.3 Confirm cgroup usage.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:3:entry:Network connection timeout :|||20", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:25:checkbox:4.1 Container ports mapped to a privileged port.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:38:checkbox:4.5 Containers root filesystem should mounted as read only.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:17:file:File containing grepable results :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150009:1:entry:Value|||Server Core", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103962:1:entry:Single CPE|||cpe:/", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11033:3:entry:Max crosspost :|||7", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:12:checkbox:Launch Cyber Essentials|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:20:checkbox:Run dangerous port scans even if safe checks are set|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.94194:1:checkbox:Alle Dateien Auflisten|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103697:4:checkbox:Disable default account checks|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:3:checkbox:Enable Detection of Portable Apps on Windows|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:6:checkbox:Exclude directories containing detected known server manuals from CGI scanning|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:8:checkbox:Self-reference directories|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:2:checkbox:Descend directories on other filesystem (don't add -xdev to find)|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:8:checkbox:2.5 Disable legacy registry v1.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:17:checkbox:Service discovery on non-default UDP ports (slow)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11033:4:checkbox:Local distribution|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:18:checkbox:2.8 docker.service file ownership must set to root:root|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:21:checkbox:2.9 docker.service file permissions must set to 644 or more restrictive.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:44:checkbox:3.4 Docker socket file ownership must set to root:docker.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:34:checkbox:3.0 docker.socket file ownership must set to root:root|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:37:checkbox:3.1 docker.socket file permissions must set to 644 or more restrictive.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:47:checkbox:3.5 Docker socket file permissions must set to 660 or more restrictive.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:29:checkbox:5.6 Docker socket must not mount inside any containers.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:5:entry:Minimum docker version for test 1.1:|||1.12", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:19:radio:Windows Domaenenfunktionsmodus|||Unbekannt", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:16:checkbox:5.2 Do not disable default seccomp profile.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:51:checkbox:2.3 Do not increase base device size if not needed.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:22:checkbox:4.0 Do not run sshd within containers|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:26:checkbox:5.5 Do not share the hosts user namespaces.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:28:checkbox:4.2 Do not skip placing the container inside a separate network stack.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:27:checkbox:1.7 Do not use insecure registries|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:14:checkbox:1.3 Do not use lxc execution driver.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:55:checkbox:3.8 Do not use privileged containers.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:10:checkbox:5.0 Do not use propagation mode \"shared\" for mounts.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:30:checkbox:1.8 Do not use the \"aufs\" storage driver.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:15:checkbox:2.7 Do not use Userland Proxy|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:50:checkbox:3.6 Do not use user root for container.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:60:radio:TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft1)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:61:radio:TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft1)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:6:radio:TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft2)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:7:radio:TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft2)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:16:radio:TLS_ECDH_ECDSA_WITH_DES_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:17:radio:TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:18:radio:TLS_ECDH_RSA_WITH_DES_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:24:radio:TLS_KRB5_WITH_3DES_EDE_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:25:radio:TLS_KRB5_WITH_3DES_EDE_CBC_MD5 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:26:radio:TLS_KRB5_WITH_DES_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:27:radio:TLS_KRB5_WITH_DES_CBC_MD5 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:29:radio:TLS_ECCPWD_WITH_AES_128_GCM_SHA256 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:30:radio:TLS_ECCPWD_WITH_AES_128_CCM_SHA256 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:31:radio:TLS_ECCPWD_WITH_AES_256_CCM_SHA384 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:33:radio:TLS_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:34:radio:TLS_RSA_WITH_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:35:radio:TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:36:radio:TLS_ECDHE_RSA_WITH_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:37:radio:TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:38:radio:TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:39:radio:TLS_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:40:radio:TLS_PSK_WITH_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:41:radio:TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:42:radio:TLS_ECDHE_PSK_WITH_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:43:radio:TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:44:radio:TLS_RSA_PSK_WITH_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:45:radio:TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:46:radio:TLS_DHE_PSK_WITH_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:47:radio:TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:48:radio:TLS_DHE_RSA_WITH_SALSA20_SHA1 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:49:radio:TLS_RSA_FIPS_WITH_DES_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:50:radio:TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:51:radio:TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:52:radio:TLS_RSA_FIPS_WITH_DES_CBC_SHA_2 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:53:radio:TLS_RSA_WITH_DES_CBC_MD5 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:54:radio:TLS_RSA_WITH_3DES_EDE_CBC_MD5 (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:118:radio:TLS_ECDH_ECDSA_WITH_NULL_SHA (Draft)|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:119:radio:TLS_ECDH_RSA_WITH_NULL_SHA (Draft)|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:121:radio:TLS_KRB5_WITH_NULL_SHA (Draft)|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:122:radio:TLS_KRB5_WITH_NULL_MD5 (Draft)|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:123:radio:TLS_GOSTR341094_WITH_NULL_GOSTR3411 (Draft)|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:124:radio:TLS_GOSTR341001_WITH_NULL_GOSTR3411 (Draft)|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:89:radio:TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_40_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:90:radio:TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_56_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:21:radio:TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:120:radio:TLS_ECDH_anon_NULL_WITH_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA (Draft)|||Null cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:23:radio:TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:20:radio:TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:93:radio:TLS_ECDH_RSA_EXPORT_WITH_RC4_56_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:22:radio:TLS_ECDH_anon_WITH_DES_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:19:radio:TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA (Draft)|||Medium cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:92:radio:TLS_ECDH_RSA_EXPORT_WITH_RC4_40_SHA (Draft) or TLS_SRP_SHA_WITH_AES_128_CBC_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:94:radio:TLS_ECDH_anon_WITH_RC4_128_SHA (Draft) or TLS_SRP_SHA_WITH_AES_256_CBC_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:76:radio:TLS_GOSTR341094_WITH_28147_CNT_IMIT (Draft)|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:77:radio:TLS_GOSTR341001_WITH_28147_CNT_IMIT (Draft)|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:78:radio:TLS_ECCPWD_WITH_AES_256_GCM_SHA384 (Draft)|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:79:radio:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:80:radio:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:81:radio:TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)|||Strong cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:103:radio:TLS_SHA256_SHA256 (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:104:radio:TLS_SHA384_SHA384 (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:105:radio:TLS_RSA_WITH_RC2_CBC_MD5 (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:106:radio:TLS_RSA_WITH_IDEA_CBC_MD5 (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:88:radio:TLS_ECDH_ECDSA_WITH_RC4_128_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:91:radio:TLS_ECDH_RSA_WITH_RC4_128_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:95:radio:TLS_KRB5_WITH_RC4_128_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:96:radio:TLS_KRB5_WITH_RC4_128_MD5 (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:97:radio:TLS_KRB5_WITH_AES_128_CBC_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:98:radio:TLS_KRB5_WITH_AES_256_CBC_SHA (Draft)|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:43:checkbox:2.0 Enable a default ulimit as appropriate.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:12:checkbox:2.6 Enable live restore.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:46:checkbox:2.1 Enable user namespace support.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:3:radio:URL encoding|||none", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109232:6:radio:Future encryption types|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:4:checkbox:Report errors:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:39:checkbox:3.2 /etc/docker directory ownership must set to root:root.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:41:checkbox:3.3 /etc/docker directory permissions must set to 755 or more restrictive|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:13:checkbox:Launch EU GDPR|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80011:1:radio:TCP evasion technique|||none", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:10:entry:Folder exclusion regex for file search on Unixoide targets|||^/(afs|dev|media|mnt|net|run|sfs|sys|tmp|udev|var|etc/init\\.d|usr/share/doc)", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:13:checkbox:Log failed nmap calls|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:3:checkbox:Report failed tests:|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80011:2:checkbox:Send fake RST when establishing a TCP connection|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:9:file:CA file :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103697:1:file:Credentials file:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140853:1:entry:Backup File Extensions|||.backup, .bak, .copy, .bkp, .old, .orig, .temp, .tmp, ~, .swp, .save", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103625:2:checkbox:Use File|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:5:checkbox:Disable file search via WMI on Windows|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105880:1:entry:SHA-1 fingerprints of CA certificates to trust|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103437:1:entry:Search for dir(s)|||/admin;/manager", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11149:2:entry:Login form :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11149:3:entry:Login form fields :|||user=%USER%&pass=%PASS%", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103962:3:radio:Check for|||present", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10107:1:checkbox:Show full HTTP headers in output|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:7:checkbox:Enable generic web application scanning|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11033:2:entry:Test group name regex :|||f[a-z]\\.tests?", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96180:3:checkbox:Delete hash test Programm after the test|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96180:2:checkbox:Install hash test Programm on the Target|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:11:checkbox:Parameter hiding|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:3:checkbox:Add historic /scripts and /cgi-bin to directories for CGI scanning|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:16:checkbox:Mark host as dead if going offline (failed ICMP ping) during scan|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:1:checkbox:Enable HTTP evasion techniques|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:2:checkbox:Use HTTP HEAD instead of GET|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103437:2:entry:Valid http status codes indicating that a directory was found|||200;301;302;401;403", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:23:checkbox:Defeat ICMP ratelimit|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80103:1:entry:Network interface on OpenVAS box (used for scanning):|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.106431:1:file:Cisco IOS Policies|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80103:2:entry:Fake IP (alive and on same subnet as scanner):|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:4:checkbox:Fragment IP packets (bypasses firewalls)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14788:1:checkbox:Run IP protocols scan|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:48:checkbox:4.9 Isolate the containers from the hosts IPC namespace.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:45:checkbox:4.8 Isolate the containers from the hosts process namespace.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:13:checkbox:5.1 Isolate the containers from the hosts UTS namespace.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140038:2:entry:Certificate Issuer|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:1:checkbox:Launch IT-Grundschutz (10. EL)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:2:checkbox:Launch IT-Grundschutz (11. EL)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:3:checkbox:Launch IT-Grundschutz (12. EL)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:4:checkbox:Launch IT-Grundschutz (13. EL)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:5:checkbox:Launch IT-Grundschutz (15. EL)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:8:checkbox:Verbose IT-Grundschutz results|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:14:checkbox:Exclude known fragile devices/ports from scan|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:6:checkbox:Launch latest IT-Grundschutz version|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:10:checkbox:Launch latest PCI-DSS version|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:19:entry:Data length :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:11:entry:Debug level|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103962:2:file:CPE List|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109809:1:entry:User list (semi-colon separated)|||root", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109131:1:entry:Value|||Guests, Local account", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10736:1:checkbox:Report local DCE services|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103447:1:entry:ESXi login name:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103447:2:password:ESXi login password:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:54:checkbox:2.4 Make use of authorization plugins.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108251:1:entry:Minimum max-age value (in seconds)|||10886400", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108250:1:entry:Minimum max-age value (in seconds)|||5184000", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:13:checkbox:Null method|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80103:4:checkbox:Report missing configuration or dependencies|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103625:3:entry:File name /tmp/|||scan_info.txt", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:12:checkbox:Log nmap output|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:21:checkbox:Log nmap output|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:8:checkbox:Use nmap|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:5:checkbox:Do not randomize the  order  in  which ports are scanned|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:18:checkbox:Do not scan targets not in the file|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.111038:1:entry:Maximum number of items shown for each list|||100", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96204:1:entry:Maximum number of log lines|||0", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.111091:1:checkbox:Report NVT debug logs|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10662:3:entry:Number of cgi directories to save into KB :|||128", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:2:entry:Number of connections done in parallel :|||6", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80103:3:entry:Number of packets:|||1000000", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10662:1:entry:Number of pages to mirror :|||200", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:7:radio:Level of Security (IT-Grundschutz)|||Basis", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103697:2:checkbox:Use only credentials listed in uploaded file:|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:18:entry:Testuser Organization Unit|||OU", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96055:2:entry:Testuser Organization Unit|||OU", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96170:2:entry:Testuser Organization Unit|||OU", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.900238:256:radio:TLS_FORTEZZA_KEA_WITH_RC4_128_SHA or TLS_KRB5_WITH_DES_CBC_SHA|||Weak cipher", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108021:2:checkbox:Guess OS more aggressively even if safe checks are set|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108021:1:checkbox:Guess OS more aggressively (safe checks off only)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.802042:1:checkbox:Create OVAL System Characteristics for NIST Windows OVAL Definitions|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103998:1:checkbox:Create OVAL System Characteristics|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109738:1:entry:Blacklisted packages|||prelink,setroubleshoot,mcstrans,xorg-x11,xserver-xorg,ypbind,rsh,talk,telnet,openldap-clients", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10662:2:entry:Start page :|||/", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.11149:1:entry:Login page :|||/", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109738:2:radio:Show partial matches|||No", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150058:1:radio:Separate partition|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150059:1:radio:Separate partition|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150061:1:radio:Separate partition|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150062:1:radio:Separate partition|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150063:1:radio:Separate partition|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150064:1:radio:Separate partition|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80086:1:entry:Third party domain :|||example.com", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105778:3:checkbox:Report passed tests:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140038:3:checkbox:Report passed tests:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:2:checkbox:Report passed tests:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:8:password:PEM password :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105262:2:password:API Password:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105536:2:password:APIC Password:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105569:2:password:XenMobile Password:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.106431:2:password:Enable Password|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.112771:2:password:DSX Password|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.113120:2:password:API Password|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100151:2:password:Postgres Password:|||postgres", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:10:password:POP2 password (sent in clear) :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:12:password:POP3 password (sent in clear) :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:14:password:IMAP password (sent in clear) :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:3:password:HTTP password (sent in clear) :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:5:password:NNTP password (sent in clear) :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:7:password:FTP password (sent in clear) :|||anonymous@example.com", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10662:4:entry:Regex pattern to exclude cgi scripts :|||\\.(js|css)$", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:4:entry:Regex pattern to exclude directories from CGI scanning :|||/(index\\.php|image|img|css|js$|js/|javascript|style|theme|icon|jquery|graphic|grafik|picture|bilder|thumbnail|media/|skins?/)", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:11:checkbox:Verbose PCI-DSS results|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:9:checkbox:Launch PCI-DSS (Version 2.0)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:2:checkbox:TCP ping tries also TCP-SYN ping|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:7:checkbox:TCP ping tries only TCP-SYN ping|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12241:1:entry:Exclude PJL printer ports from scan|||2000,2501,9100,9101,9102,9103,9104,9105,9106,9107,9112,9113,9114,9115,9116,10001", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:7:radio:Timing policy :|||Aggressive", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.95888:14:checkbox:Verbose Policy Controls|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:6:entry:Source port :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:3:checkbox:RPC port scan|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:13:checkbox:Exclude printers from scan|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103625:6:radio:Syslog priority|||info", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:7:file:SSL private scan_id :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109733:1:radio:Password protection|||Enabled", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:16:entry:Force protocol string :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:4:entry:Network read/write timeout :|||20", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10662:5:checkbox:Use regex pattern to exclude cgi scripts :|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:5:checkbox:Use regex pattern to exclude directories from CGI scanning :|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105988:1:file:Policy registry file|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109113:1:entry:Value|||Administrators, Remote Desktop Users", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109117:1:entry:Value|||Administrators, Remote Desktop Users", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:9:checkbox:Premature request ending|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:15:checkbox:HTTP/0.9 requests|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10386:1:entry:Maximum response time (in seconds)|||60", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:17:checkbox:1.4 Restrict network traffic between containers.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:8:entry:Max Retries :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96057:1:file:X.509 Root Authority Certificate(PEM)|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108072:1:checkbox:Run routine|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108021:3:checkbox:Run routine|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:22:checkbox:Defeat RST ratelimit|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:12:entry:Initial RTT timeout (ms) :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:10:entry:Min RTT Timeout (ms) :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:11:entry:Max RTT Timeout (ms) :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:13:entry:Ports scanned in parallel (max)|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:14:entry:Ports scanned in parallel (min)|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:1:radio:TCP scanning technique :|||connect()", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:2:checkbox:Service scan|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103625:8:entry:Message|||Security Scan of ::HOSTNAME:: finished. Start: ::SCAN_START:: Stop: ::SCAN_STOP::", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96171:2:entry:Message|||Security Scan of ::HOSTNAME:: finished. Start: ::SCAN_START:: Stop: ::SCAN_STOP::", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80091:1:entry:Delay (seconds):|||1", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:10:checkbox:CGI.pm semicolon separator|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:15:checkbox:Never send SMB credentials in clear text|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:9:checkbox:3.9 Sensitive host system directories should not be mounted in containers.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:14:checkbox:TAB separator|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:5:entry:Wrapped service read timeout :|||20", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:23:checkbox:5.4 Set no-new-privileges for Container.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:20:checkbox:1.5 Set the logging level to \"info\".|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:42:checkbox:4.7 Set the \"on-failure\" container restart policy to 5 or less.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.19506:1:checkbox:Be silent|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:6:checkbox:Report skipped tests:|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:6:checkbox:Double slashes|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108298:1:entry:Exclude specific port(s) from scan|||2000:all:full,2501:all:full,9100:all:full,9101:all:full,9102:all:full,9103:all:full,9104:all:full,9105:all:full,9106:all:full,9107:all:full,9112:all:full,9113:all:full,9114:all:full,9115:all:full,9116:all:full,10001:all:full", 0); // Exclude printer port
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:15:checkbox:Enable SSH Debug|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10330:1:radio:Test SSL based services|||All", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:8:radio:Use 'su - USER' option on SSH commands|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:12:checkbox:Dos/Windows syntax|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103625:5:checkbox:Use Syslog|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103625:7:entry:Syslog tag|||VulScan", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96107:1:entry:Telnet Testuser Name|||UserName", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.96107:2:password:Telnet Testuser Password|||PassWord", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:7:entry:Integer that sets the directory depth when using 'find' on unixoide systems|||12", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:4:checkbox:Disable the usage of win_cmd_exec for remote commands on Windows|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103437:3:checkbox:Run this Plugin|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:9:entry:Use this user for 'su - USER' option on SSH commands|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:9:entry:Host Timeout (ms) :|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103239:1:checkbox:Report timeout|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103240:1:checkbox:Report timeout|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108718:1:checkbox:Report timeout|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108975:1:checkbox:Report timeout|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108976:1:checkbox:Report timeout|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.802067:1:checkbox:Report timeout|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:14:radio:nmap timing policy|||Normal", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103823:1:checkbox:Report TLS version|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.103625:4:checkbox:Append to File|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.810000:2:checkbox:Silent tool check on Greenbone OS (GOS)|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.810000:1:checkbox:Silent tool check|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108013:1:entry:Seconds to wait between probes|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:7:radio:Reverse traversal|||none", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:11:checkbox:nmap: try also with only -sP|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:8:radio:Network type|||Mixed (use RFC 1918)", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109806:1:entry:Default umask|||027", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:1:checkbox:Strictly unauthenticated|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100315:5:checkbox:Mark unrechable Hosts as dead (not scanning)|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:5:radio:Absolute URI host|||none", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.80010:4:radio:Absolute URI type|||none", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:53:checkbox:1.0 Use a separate partition for containers.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:11:checkbox:1.2 Use a up to date Docker version.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:35:checkbox:4.4 Use CPU priority for container.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:1:checkbox:Also use 'find' command to search for Applications|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:52:checkbox:3.7 Use HEALTHCHECK for the container image.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:7:checkbox:1.1 Use Linux Kernel >= 3.10.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.140121:31:checkbox:4.3 Use memory limit for container.|||yes", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:16:checkbox:Only use NTLMv2|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.115000:1:entry:Value|||user1, user2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.150083:1:entry:Value|||user1 user2", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:12:entry:HTTP User-Agent|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105262:1:entry:API Username:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105536:1:entry:APIC Username:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.105569:1:entry:XenMobile Username:|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.113120:1:entry:API Username|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.112771:1:entry:DSX User Name|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100151:1:entry:Postgres Username:|||postgres", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109116:1:entry:Value|||Administrators, Users", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:24:checkbox:Send using IP packets|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.91984:2:entry:sizelimit value|||500", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.91984:1:entry:timelimit value (in seconds)|||3600", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:10:radio:Log verbosity|||Normal", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.12288:9:radio:Report verbosity|||Normal", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.106056:1:entry:Passwords|||admin, vnc, test, password", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.100509:6:checkbox:Report vulnerabilities of inactive Linux Kernel(s) separately|||no", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:15:entry:Minimum wait between probes (ms)|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.14259:16:entry:Maximum wait between probes (ms)|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.108078:1:file:Orientierungshilfe Windows 10 Policies|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109822:1:entry:Files with SGID|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.109821:1:entry:Files with SUID|||", 0);
    kb_item_add_str (kb_main, scan_id, "1.3.6.1.4.1.25623.1.0.10870:8:entry:FTP writeable directory :|||/incoming", 0);
    return 1;
}