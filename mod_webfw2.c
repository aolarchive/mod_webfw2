#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include "httpd.h"
#include "http_core.h"
#include "apr_pools.h"
#include "apr_tables.h"
#include "http_protocol.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_hash.h"
#include "apr_strings.h"
#include "http_request.h"
#include "apr_reslist.h"
#include "apr_thread_rwlock.h"
#include "patricia.h"
#include "filtercloud.h"
#include "version.h"

#define FILTER_CONFIG_KEY "webfw2_filter_config"

module AP_MODULE_DECLARE_DATA webfw2_module;

typedef struct webfw2_config {
    char           *config_file;
    char           *dynamic_srcaddr_rule;
    uint32_t        update_interval;
    apr_table_t    *xff_headers;
    apr_array_header_t *match_env;
    apr_array_header_t *match_note;
    apr_array_header_t *match_file;
} webfw2_config_t;

typedef struct webfw2_filter {
    apr_time_t      last_update;
    apr_time_t      last_modification;
    cloud_filter_t *filter;
    apr_pool_t     *pool;
    apr_thread_rwlock_t *rwlock;
} webfw2_filter_t;

static void    *
webfw2_srcaddr_cb(apr_pool_t * pool, void *fc_data, const void **usrdata)
{
    if (!usrdata)
        return NULL;

    return (void *) usrdata[1];
}

static void    *
webfw2_dstaddr_cb(apr_pool_t * pool, void *fc_data, const void **userdata)
{
    if (!userdata)
        return NULL;

    return (void *) userdata[2];
}

static void    *
webfw2_env_cb(apr_pool_t * pool, void *fc_data, const void **userdata)
{
    request_rec    *rec;
    char *data;

    if (!userdata || !fc_data)
        return NULL;

    rec = (request_rec *) userdata[0];
    data = (char *)apr_table_get(rec->subprocess_env, (char *) fc_data);

    return data?data:"__wf2-NULL__";
}

static void    *
webfw2_note_cb(apr_pool_t * pool, void *fc_data, const void **userdata)
{
    request_rec    *rec;
    char *data;
    if (!userdata || !fc_data)
        return NULL;

    rec = (request_rec *) userdata[0];

    data = (char *) apr_table_get(rec->notes, (char *) fc_data);

    return data?data:"__wf2-NULL__";
}

static void
webfw2_register_callbacks(apr_pool_t * pool, webfw2_config_t * config,
                          webfw2_filter_t * filter)
{
    cloud_register_user_cb(filter->filter,
                           (void *) webfw2_srcaddr_cb, RULE_MATCH_SRCADDR,
                           NULL);

    cloud_register_user_cb(filter->filter, (void *) webfw2_dstaddr_cb,
                           RULE_MATCH_DSTADDR, NULL);

	
    if (config->match_note)
    {
        int i;
        char **list;

        list = (char **)config->match_note->elts;

        for(i=0; i < config->match_note->nelts; i++)
            cloud_register_user_cb(
                    filter->filter, (void *)webfw2_note_cb,
                    RULE_MATCH_STRING, list[i]);
    }

    if (config->match_env)
    {
	int i;
	char **list;

	list = (char **)config->match_env->elts;

	for(i=0; i < config->match_env->nelts; i++)
	    cloud_register_user_cb(
		    filter->filter, (void *)webfw2_env_cb,
		    RULE_MATCH_STRING, list[i]);
    }

}

static void
webfw2_filter_parse(apr_pool_t * pool, webfw2_config_t * config,
                    webfw2_filter_t * filter)
{
    apr_pool_create(&filter->pool, pool);

    filter->filter = cloud_parse_config(filter->pool, config->config_file);

    ap_assert(filter->filter);

    webfw2_register_callbacks(filter->pool, config, filter);
}

static webfw2_filter_t *
webfw2_filter_init(apr_pool_t * pool, webfw2_config_t * config)
{
    webfw2_filter_t *filter;

    filter = apr_pcalloc(pool, sizeof(webfw2_filter_t));
    
    webfw2_filter_parse(pool, config, filter);

#ifdef APR_HAS_THREADS
    ap_assert(apr_thread_rwlock_create(&filter->rwlock, pool) ==
              APR_SUCCESS);
#endif

    return filter;
}

static int
webfw2_updater(request_rec * rec)
{
    webfw2_config_t *config;
    webfw2_filter_t *wf2_filter;
    apr_time_t      now;

    config = ap_get_module_config(rec->server->module_config,
                                  &webfw2_module);

    apr_pool_userdata_get((void **) &wf2_filter,
                          FILTER_CONFIG_KEY, rec->server->process->pool);


#ifdef APR_HAS_THREADS
    if(apr_thread_rwlock_trywrlock(wf2_filter->rwlock) != APR_SUCCESS)
	return 0;

    //apr_thread_rwlock_wrlock(wf2_filter->rwlock);
#endif

    now = apr_time_now();
    do {
        /*
         * first check to see if the file has been modified 
         */
        apr_status_t    rv;
        apr_finfo_t     sb;
        apr_pool_t     *subpool;

        if (now - wf2_filter->last_update <= config->update_interval)
            /*
             * we have not hit our interval yet, so sail on, sailor! 
             */
            break;

        rv = apr_stat(&sb, config->config_file,
                      APR_FINFO_MTIME, rec->pool);

        if (rv != APR_SUCCESS)
            break;

        if (sb.mtime == wf2_filter->last_modification)
            /*
             * file was not modified since the last check 
             */
            break;

        /*
         * the file has infact changed, lets re-read the config and start
         * over 
         */

        /*
         * this will remove everything in our current filter 
         */
        subpool = wf2_filter->pool;
        apr_pool_destroy(subpool);

        webfw2_filter_parse(rec->server->process->pool,
                            config, wf2_filter);

        wf2_filter->last_modification = sb.mtime;
    } while (0);

    wf2_filter->last_update = now;
#ifdef APR_HAS_THREADS
    apr_thread_rwlock_unlock(wf2_filter->rwlock);
#endif
    return 0;
}

static void
webfw2_child_init(apr_pool_t * pool, server_rec * rec)
{
    webfw2_config_t *config;
    webfw2_filter_t *wf2_filter;

    config = ap_get_module_config(rec->module_config, &webfw2_module);
    ap_assert(config);

    /*
     * create a subpool that will be used as the root for our rules and
     * filters, then set it as a server pool key 
     */

    wf2_filter = webfw2_filter_init(pool, config);
    ap_assert(wf2_filter);

    apr_pool_userdata_set(wf2_filter, FILTER_CONFIG_KEY,
                          apr_pool_cleanup_null, rec->process->pool);
}

static apr_array_header_t *
webfw2_find_all_sources(request_rec * rec)
{
    webfw2_config_t *config;
    apr_array_header_t *addr_array;
    apr_table_entry_t *hdrs;
    apr_array_header_t *hdrs_arr;
    int             i;

    config =
        ap_get_module_config(rec->server->module_config, &webfw2_module);

    ap_assert(config);

    addr_array = apr_array_make(rec->pool, 1, sizeof(char *));
    ap_assert(addr_array);

    if (!config->xff_headers) {
        *(const char **) apr_array_push(addr_array) =
            rec->connection->remote_ip;
        return addr_array;
    }

    hdrs_arr = (apr_array_header_t *)
        apr_table_elts(config->xff_headers);

    hdrs = (apr_table_entry_t *) hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; i++) {
        char           *value;
        char           *addr;
        char          **addrs;
        char          **addrs_ptr;

        if (!hdrs[i].key)
            continue;

        value = (char *) apr_table_get(rec->headers_in, hdrs[i].key);

        if (!value)
            continue;

        addrs = cloud_tokenize_str(value, ",");
        addrs_ptr = addrs;

        while ((addr = *addrs++))
            *(const char **) apr_array_push(addr_array) =
                apr_pstrdup(rec->pool, addr);

        free_tokens(addrs_ptr);
    }

    *(const char **) apr_array_push(addr_array) =
        rec->connection->remote_ip;

    return addr_array;
}

static void
webfw2_set_interesting_notes(request_rec *rec)
{
    /* 
     * set interesting parts of the request within the notes section:
     * rec->hostname (the hostname from the request)
     * rec->canonical_filename (the full path to the file on the system)
     * rec->uri (the parsed URI)
     * rec->unparsed_uri (the unparsed URI)
     */
            
    apr_table_set(rec->notes,
	    "__wf2-hostname__", 
	    rec->hostname);
    apr_table_set(rec->notes,
	    "__wf2-canonical-filename__",
	    rec->canonical_filename);
    apr_table_set(rec->notes,
	    "__wf2-uri__", rec->uri);
    apr_table_set(rec->notes,
	    "__wf2-unparsed-uri__",
	    rec->unparsed_uri);
    apr_table_set(rec->notes,
	    "__wf2-protocol__",
	    rec->protocol);

}

static int
webfw2_handler(request_rec * rec)
{
    int             ret;
    webfw2_filter_t *wf2_filter;
    webfw2_config_t *config;

    ret = DECLINED;

    config = ap_get_module_config(rec->server->module_config,
                                  &webfw2_module);
    ap_assert(config);

    apr_pool_userdata_get((void **) &wf2_filter,
                          FILTER_CONFIG_KEY, rec->server->process->pool);

    ap_assert(wf2_filter);
#ifdef APR_HAS_THREADS

#ifdef RADIX_IS_REENTRANT
    apr_thread_rwlock_rdlock(wf2_filter->rwlock);
#else
    apr_thread_rwlock_wrlock(wf2_filter->rwlock);
#endif

#endif

    webfw2_set_interesting_notes(rec);

    do {
        int             i;
        apr_array_header_t *addrs;

        if (!wf2_filter->filter)
            break;

        if (!(addrs = webfw2_find_all_sources(rec)))
            break;

        for (i = 0; i < addrs->nelts; i++) {
            cloud_rule_t   *rule;
            const char     *src_ip;
            const char     *dst_ip;
            void          **callback_data;

            callback_data = apr_pcalloc(rec->pool, sizeof(void *) * 3);

            src_ip = ((const char **) addrs->elts)[i];
            dst_ip = (const char *) rec->connection->local_ip;

            callback_data[0] = (void *) rec;
            callback_data[1] = (void *) src_ip;
            callback_data[2] = (void *) dst_ip;

            if (!(rule = cloud_traverse_filter(wf2_filter->filter,
                                               (void *) callback_data)))
                continue;

            apr_table_set(rec->notes, 
		    "webfw2_rule", rule->name);
	    apr_table_set(rec->subprocess_env, 
		    "webfw2_rule", rule->name);

            ret = 542;

            /*
             * XXX This should be fixed to be a bit more dynamic in both
             * configuration and matching 
             */
            if (config->dynamic_srcaddr_rule) {
                cloud_rule_t   *dynamic_rule;

                if ((dynamic_rule =
                     cloud_filter_get_rule(wf2_filter->filter,
                                           config->dynamic_srcaddr_rule)) == rule)
                    break;

		if (dynamic_rule == NULL) 
		    break;


#ifdef APR_HAS_THREADS
#ifdef RADIX_IS_REENTRANT
                /*
                 * we have to unlock our reader, and set a write lock 
                 */
                apr_thread_rwlock_unlock(wf2_filter->rwlock);
                apr_thread_rwlock_wrlock(wf2_filter->rwlock);
#endif
#endif
                /*
                 * now insert our src addr into our dynamic rule 
                 */
                cloud_rule_add_network(dynamic_rule,
                                       src_ip, RULE_MATCH_SRCADDR, NULL);

            }

            break;
        }
    } while (0);

#ifdef APR_HAS_THREADS
    apr_thread_rwlock_unlock(wf2_filter->rwlock);
#endif
    return ret;
}

static void    *
webfw2_init_config(apr_pool_t * pool, server_rec * svr)
{
    webfw2_config_t *config;
    void           *done;
    const char     *userdata = "webfw2_config";

    apr_pool_userdata_get(&done, userdata, svr->process->pool);

    if (!done) {
        apr_pool_userdata_set((void *) 1,
                              userdata, apr_pool_cleanup_null,
                              svr->process->pool);
        return OK;
    }

    config =
        (webfw2_config_t *) apr_pcalloc(svr->process->pool,
                                        sizeof(*config));

    return config;
}

static const char *
cmd_dynamic_srcaddr_rule(cmd_parms * cmd, void *dummy_config,
                         const char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    config->dynamic_srcaddr_rule = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *
cmd_config_file(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    config->config_file = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *
cmd_update_interval(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    config->update_interval = atoi(arg);
    return NULL;
}

static const char *
cmd_rw_xff(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;
    char           *xff_header;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    if (!config->xff_headers)
        config->xff_headers = apr_table_make(cmd->pool, 1);

    ap_assert(config->xff_headers);

    xff_header = apr_pstrdup(cmd->pool, arg);
    ap_assert(xff_header);
    ap_str_tolower(xff_header);

    apr_table_setn(config->xff_headers, xff_header, (void *) 1);
    return NULL;
}

static const char *
cmd_match_variable(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;
    apr_array_header_t **array;
    char           *note;
    char           *type;

    type = cmd->info;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    if (!strcmp(type, "note"))
        array = &config->match_note;
    else if (!strcmp(type, "env"))
        array = &config->match_env;
    else
	return NULL;

    if (!*array)
        *array = apr_array_make(cmd->pool, 1, sizeof(char *));

    note = apr_pstrdup(cmd->pool, arg);
    ap_assert(note);

    *(const char **) apr_array_push(*array) = note;

    return NULL;
}

static void
webfw2_hooker(apr_pool_t * pool)
{
    static const char *beforeme_list[] = {
        "mod_chad.c",
        NULL
    };

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                 "initializing mod_webfw2 v%s", VERSION);
    ap_hook_child_init(webfw2_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(webfw2_handler, beforeme_list,
                           NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(webfw2_updater, NULL, NULL,
                            APR_HOOK_REALLY_LAST);
}

const command_rec webfw2_directives[] = {

    AP_INIT_TAKE1("webfw2_config", cmd_config_file,
                  NULL, RSRC_CONF,
                  "The full path to where the webfw2 configuration lives"),
    AP_INIT_TAKE1("webfw2_update_interval", cmd_update_interval,
                  NULL, RSRC_CONF,
                  "The time (in seconds) to check for configuration changes"),
    AP_INIT_TAKE1("webfw2_rw_xff", cmd_rw_xff, NULL, RSRC_CONF,
                  "If this header is present, we use this IP address to filter"),
    AP_INIT_TAKE1("webfw2_match_note", cmd_match_variable, "note",
                  RSRC_CONF,
                  "Pass a note to filtercloud"),
    AP_INIT_TAKE1("webfw2_match_env", cmd_match_variable, "env", RSRC_CONF,
                  "Pass an env to the filtercloud"),
    /*
     * webfw2_dynamic_srcaddr_block "test_dynamic" 
     */
    AP_INIT_TAKE1("webfw2_dynamic_srcaddr_block", cmd_dynamic_srcaddr_rule,
                  NULL,
                  RSRC_CONF,
                  "Dynamically update the source-addresses within this filter if another "
                  "rule matches"),

#if 0
    AP_INIT_TAKE1("webfw2_match_file", cmd_match_file, NULL, RSRC_CONF,
                  "Pass the parsed filename to filtercloud"),
#endif
    {NULL}
};

module AP_MODULE_DECLARE_DATA webfw2_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    webfw2_init_config,
    NULL,
    webfw2_directives,
    webfw2_hooker
};
