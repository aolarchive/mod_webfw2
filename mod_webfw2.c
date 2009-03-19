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
    char *config_file;
    uint32_t update_interval;
    apr_table_t *xff_headers;
} webfw2_config_t;

typedef struct webfw2_filter {
    cloud_filter_t *filter;
    apr_pool_t *pool;
    apr_thread_rwlock_t *rwlock;
    int test;
} webfw2_filter_t;

static void
webfw2_child_init(apr_pool_t * pool, server_rec * rec)
{
    webfw2_config_t *config;
    webfw2_filter_t *wf2_filter;
    apr_pool_t *subpool;

    config = ap_get_module_config(rec->module_config, 
	    &webfw2_module);

    ap_assert(config);

    /* create a subpool that will be used as the root for 
     * our rules and filters, then set it as a server
     * pool key */
    apr_pool_create(&subpool, pool);

    wf2_filter = apr_pcalloc(subpool, sizeof(webfw2_filter_t));
    wf2_filter->pool = subpool;
    wf2_filter->test = 500;

#ifdef APR_HAS_THREADS
    ap_assert(apr_thread_rwlock_create(&wf2_filter->rwlock, 
		subpool) == APR_SUCCESS);
#endif
    apr_pool_userdata_set(wf2_filter, FILTER_CONFIG_KEY, 
	    apr_pool_cleanup_null, rec->process->pool);
}

static int
webfw2_handler(request_rec *rec)
{
    webfw2_filter_t *wf2_filter;

    apr_pool_userdata_get((void **)&wf2_filter, 
	    FILTER_CONFIG_KEY, rec->server->process->pool);

    ap_assert(wf2_filter);
    // apr_thread_rwlock_wrlock
    
#ifdef APR_HAS_THREADS
    apr_thread_rwlock_rdlock(wf2_filter->rwlock);
#endif
    printf("test %d\n", wf2_filter->test);
#ifdef APR_HAS_THREADS
    apr_thread_rwlock_unlock(wf2_filter->rwlock);
#endif
    return DECLINED;
}

void *
webfw2_init_config(apr_pool_t * pool, server_rec * svr)
{
    apr_status_t rv;
    webfw2_config_t *config;
    void *done;
    const char *userdata = "webfw2_config";

    apr_pool_userdata_get(&done, userdata, 
	   svr->process->pool); 

    if (!done)
    {
	apr_pool_userdata_set((void *)1, 
		userdata, apr_pool_cleanup_null, 
		svr->process->pool);
	return OK;
    }

    config = (webfw2_config_t *)apr_pcalloc(
	    svr->process->pool, sizeof(*config));

    return config;
}

static const char *
cmd_config_file(cmd_parms * cmd, void *dummy_config, 
	const char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
	    &webfw2_module);

    ap_assert(config);

    config->config_file = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *
cmd_update_interval(cmd_parms *cmd, void *dummy_config,
	const char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
	    &webfw2_module);

    ap_assert(config);

    config->update_interval = atoi(arg);
    return NULL;
}

static const char *
cmd_rw_xff(cmd_parms *cmd, void *dummy_config, 
	const char *arg)
{
    webfw2_config_t *config;
    char *xff_header;

    config = ap_get_module_config(cmd->server->module_config,
            &webfw2_module);

    ap_assert(config);

    if (!config->xff_headers)
	config->xff_headers = apr_table_make(cmd->pool, 1);

    ap_assert(config->xff_headers);

    xff_header = apr_pstrdup(cmd->pool, arg);
    ap_assert(xff_header);
    ap_str_tolower(xff_header);

    apr_table_setn(config->xff_headers, xff_header, (void *)1);
    return NULL;
}

static void
webfw2_hooker(apr_pool_t *pool)
{
    static const char *beforeme_list[] = {
	"mod_chad.c",
	NULL
    };

    ap_hook_child_init(webfw2_child_init, NULL, NULL, 
	    APR_HOOK_MIDDLE);
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

    // "match_src_addr && match_dst_addr || match_http_header" 64.12.23.5 10.0.0.2
