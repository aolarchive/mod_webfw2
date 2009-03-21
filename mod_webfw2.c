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

#define FILTER_CONFIG_KEY "webfw2_filter_config"

module AP_MODULE_DECLARE_DATA webfw2_module;

typedef struct webfw2_config {
    char           *config_file;
    uint32_t        update_interval;
    apr_table_t    *xff_headers;
} webfw2_config_t;

typedef struct webfw2_filter {
    uint32_t        last_update;
    cloud_filter_t *filter;
    apr_pool_t     *pool;
    apr_thread_rwlock_t *rwlock;
    int             test;
} webfw2_filter_t;

static void *
webfw2_srcaddr_cb(apr_pool_t *pool, const void **usrdata)
{
    if (!usrdata)
        return NULL;

    return (void *)usrdata[1];
}

static void *
webfw2_dstaddr_cb(apr_pool_t *pool, const void **userdata)
{
    if (!userdata)
        return NULL;

    return (void *)userdata[2];
}

static void *
webfw2_chad_ord_cb(apr_pool_t *pool, const void **userdata)
{
    request_rec *rec;
    if(!userdata)
        return NULL;

    rec = (request_rec *)userdata[0];

    return (char *)
        apr_table_get(rec->notes, "chadorder");
}

static void
webfw2_child_init(apr_pool_t * pool, server_rec * rec)
{
    webfw2_config_t *config;
    webfw2_filter_t *wf2_filter;
    apr_pool_t     *subpool;

    config = ap_get_module_config(rec->module_config, &webfw2_module);
    ap_assert(config);

    /*
     * create a subpool that will be used as the root for our rules and
     * filters, then set it as a server pool key 
     */
    apr_pool_create(&subpool, pool);
    wf2_filter = apr_pcalloc(subpool, sizeof(webfw2_filter_t));
    wf2_filter->pool = subpool;
    wf2_filter->test = 500;

    wf2_filter->filter =
        cloud_parse_config(wf2_filter->pool, config->config_file);

    cloud_register_cb(wf2_filter->filter,
	    webfw2_srcaddr_cb, RULE_MATCH_SRCADDR);
    cloud_register_cb(wf2_filter->filter,
	    webfw2_dstaddr_cb, RULE_MATCH_DSTADDR);
    cloud_register_cb(wf2_filter->filter,
	    webfw2_chad_ord_cb, RULE_MATCH_CHAD_ORD);

#ifdef APR_HAS_THREADS
    ap_assert(apr_thread_rwlock_create(&wf2_filter->rwlock,
                                       subpool) == APR_SUCCESS);
#endif
    apr_pool_userdata_set(wf2_filter, FILTER_CONFIG_KEY,
                          apr_pool_cleanup_null, rec->process->pool);
}

apr_array_header_t *
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

    hdrs_arr = (apr_array_header_t *)
        apr_table_elts(config->xff_headers);

    hdrs = (apr_table_entry_t *) hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; ++i) {
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

        while (addr = *addrs++)
            *(const char **) apr_array_push(addr_array) =
                apr_pstrdup(rec->pool, addr);

        free_tokens(addrs_ptr);
    }

    *(const char **) apr_array_push(addr_array) =
        rec->connection->remote_ip;

    return addr_array;
}

static int
webfw2_handler(request_rec * rec)
{
    int             ret;
    webfw2_filter_t *wf2_filter;

    ret = DECLINED;

    apr_pool_userdata_get((void **) &wf2_filter,
                          FILTER_CONFIG_KEY, rec->server->process->pool);

    ap_assert(wf2_filter);
    // apr_thread_rwlock_wrlock
#ifdef APR_HAS_THREADS
    apr_thread_rwlock_rdlock(wf2_filter->rwlock);
#endif

    do {
        int             i;
        char           *chad_order;
        apr_array_header_t *addrs;

        if (!wf2_filter->filter)
            break;

        if (!(addrs = webfw2_find_all_sources(rec)))
            break;

        chad_order = (char *) apr_table_get(rec->notes, "chadorder");

        for (i = 0; i < addrs->nelts; i++) {
            cloud_rule_t   *rule;
            const char     *src_ip;
            const char     *dst_ip;
	    void **callback_data;

	    callback_data = apr_pcalloc(rec->pool, sizeof(void *) * 3); 

            src_ip = ((const char **) addrs->elts)[i];
            dst_ip = (const char *) rec->connection->local_ip;

	    callback_data[0] = (void *)rec;
	    callback_data[1] = (void *)src_ip;
	    callback_data[2] = (void *)dst_ip;

            if (!(rule = cloud_traverse_filter(wf2_filter->filter, 
			    (void *)callback_data)))
                continue;

            ret = 404;
            break;
        }
    } while (0);

#ifdef APR_HAS_THREADS
    apr_thread_rwlock_unlock(wf2_filter->rwlock);
#endif
    return ret;
}

void           *
webfw2_init_config(apr_pool_t * pool, server_rec * svr)
{
    apr_status_t    rv;
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

static void
webfw2_hooker(apr_pool_t * pool)
{
    static const char *beforeme_list[] = {
        "mod_chad.c",
        NULL
    };

    ap_hook_child_init(webfw2_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(webfw2_handler, beforeme_list,
                           NULL, APR_HOOK_MIDDLE);
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
