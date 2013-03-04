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
#if 0
#ifdef ENABLE_APREQ
#include "apreq2/apreq_module_apache2.h"
#include "apreq2/apreq_module.h"
#endif
#endif
#include "mod_webfw2.h"
#include "thrasher.h"

module AP_MODULE_DECLARE_DATA webfw2_module;

static void
webfw2_filter_parse(apr_pool_t * pool, webfw2_config_t * config,
                    webfw2_filter_t * filter)
{
    apr_pool_create(&filter->pool, pool);

    if (!config->config_file) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                     "No configuration file specified for webfw2! NO RULES LOADED!");
        return;
    }

    filter->filter =
        filter_parse_config(filter->pool, config->config_file, 1);

    if (!filter->filter) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                     "webfw2 configuration syntax error! NO RULES LOADED!!!!!");
        return;
    }

    webfw2_register_callbacks(filter->pool, config, filter);
}

static webfw2_filter_t *
webfw2_filter_init(apr_pool_t * pool, webfw2_config_t * config)
{
    webfw2_filter_t *filter;
    apr_finfo_t     sb;


    filter = apr_pcalloc(pool, sizeof(webfw2_filter_t));
    webfw2_filter_parse(pool, config, filter);

    /*
     * fetch the current date on the config file 
     */
    apr_stat(&sb, config->config_file, APR_FINFO_MTIME, pool);
    filter->last_modification = sb.mtime;

#ifdef APR_HAS_THREADS
    ap_assert(apr_thread_rwlock_create(&filter->rwlock, pool) ==
              APR_SUCCESS);
#endif

    if (config->thrasher_host && config->thrasher_port) {
        /*
         * create our thrasher socket 
         */
        apr_socket_t   *sock;
        sock = thrasher_connect(pool, config);

        if (sock)
            filter->thrasher_sock = sock;
        else {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                         "webfw2 could not connect to thrasher");
            filter->thrasher_sock = NULL;
            filter->thrasher_downed = time(NULL);
        }
    }

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
    if (apr_thread_rwlock_trywrlock(wf2_filter->rwlock) != APR_SUCCESS)
        return 0;
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
         * the file has in-fact changed, lets re-read the config and start
         * over 
         */

        /*
         * this will remove everything in our current filter 
         */
        subpool = wf2_filter->pool;
        apr_pool_destroy(subpool);

        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                     "Changes found within webfw2 configuration "
                     "reloading rules!");

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

static void
webfw2_add_array_unique(apr_pool_t          *pool, apr_array_header_t  *addr_array, const char *addr)
{
    int i;

    for (i = 0; i < addr_array->nelts; i++) {
        char *src_ip = ((char **) addr_array->elts)[i];
        if (strcmp(src_ip, addr) == 0)
            return;
    }

    *(const char **) apr_array_push(addr_array) =
        apr_pstrdup(pool, addr);
}

static apr_array_header_t *
webfw2_find_all_sources(request_rec * rec)
{
    /*
     * go through every address we can find, whether that be 
     * within an XFF type header, or the real source and add
     * it to an array we can filter on 
     */
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
        /*
         * no xff headers defined, so we only look at the remote addr 
         */
        webfw2_add_array_unique(rec->pool, addr_array, rec->connection->remote_ip);
        return addr_array;
    }

    hdrs_arr = (apr_array_header_t *)
        apr_table_elts(config->xff_headers);
    hdrs = (apr_table_entry_t *) hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; i++) {
        /*
         * go through each defined XFF header from httpd.conf, check for
         * its existence in the request_rec, and if found run through it
         * and stick each addr in an array 
         */

        webfw2_xff_opts_t *xff_opts;
        char           *addr;
        char          **addrs;
        char          **addrs_ptr;
        int             nelts;
        char           *header_in_value;

        if (!hdrs[i].key)
            continue;

        /*
         * find the header key inside our queries headers_in 
         */
        header_in_value =
            (char *) apr_table_get(rec->headers_in, hdrs[i].key);

        if (!header_in_value)
            /*
             * the header does not exists within the request 
             */
            continue;

        xff_opts = (webfw2_xff_opts_t *) hdrs[i].val;

        /*
         * first check to make sure if the source_ip filter for XFF
         * headers is enabled and that we are coming from a trusted 
         * source. 
         */
        if (xff_opts && xff_opts->source_ip &&
            !apr_hash_get(xff_opts->source_ip,
                          (char *) rec->connection->remote_ip,
                          APR_HASH_KEY_STRING)) {
            /*
             * printf("Untrusted source address for XFF %s\n", 
             * rec->connection->remote_ip);
             */
            continue;
        }

        /*
         * get all the addresses we have found in the header val 
         */
        if (!(addrs = filter_tokenize_str(header_in_value, ",", &nelts)))
            continue;

        addrs_ptr = addrs;

        /*
         * do we need to include every address within this array? 
         */
        if (!xff_opts || xff_opts->first + xff_opts->last >= nelts ||
            (xff_opts->first == 0 && xff_opts->last == 0)) {
            /*
             * we need to add every single address to the returned 
             * array 
             */
            while ((addr = *addrs++)) {
                if (!filter_validate_ip(addr))
                    continue;

                webfw2_add_array_unique(rec->pool, addr_array, addr);
            }
        } else {
            /*
             * only add first X and last X entries to our array 
             */
            int             x;

            if (xff_opts->first != 0) {
                /*
                 * stuff the first X into the array 
                 */
                for (x = 0; x < xff_opts->first; x++) {
                    if (!filter_validate_ip(addrs_ptr[x]))
                        continue;

                    /*
                     * printf("Copying first entries %s\n", addrs_ptr[x]);
                     */
                    webfw2_add_array_unique(rec->pool, addr_array, addrs_ptr[x]);
                }
            }

            if (xff_opts->last != 0) {
                /*
                 * stuff the last X into the array 
                 */

                /*
                 * we skip past the last NULL byte by setting the initializer 
                 * to nelts - 1. 
                 */
                for (x = nelts - 1; x >= nelts - xff_opts->last; x--) {
                    /*
                     * we skip over the first NULL on the end of the array 
                     */
                    if (addrs_ptr[x] == NULL)
                        continue;

                    if (!filter_validate_ip(addrs_ptr[x]))
                        continue;

                    /*
                     * printf("Copying last entries %s\n", addrs_ptr[x]);
                     */
                    webfw2_add_array_unique(rec->pool, addr_array, addrs_ptr[x]);
                }
            }
        }

        free_tokens(addrs_ptr);
    }

    webfw2_add_array_unique(rec->pool, addr_array, rec->connection->remote_ip);

    return addr_array;
}

static void
webfw2_set_interesting_notes(request_rec * rec)
{
    /*
     * set interesting parts of the request within the notes section:
     * rec->hostname (the hostname from the request)
     * rec->canonical_filename (the full path to the file on the system)
     * rec->uri (the parsed URI)
     * rec->unparsed_uri (the unparsed URI)
     */

    apr_table_set(rec->notes, "__wf2-hostname__", rec->hostname);
    apr_table_set(rec->notes,
                  "__wf2-canonical-filename__", rec->canonical_filename);
    apr_table_set(rec->notes, "__wf2-uri__", rec->uri);
    apr_table_set(rec->notes, "__wf2-unparsed-uri__", rec->unparsed_uri);
    apr_table_set(rec->notes, "__wf2-protocol__", rec->protocol);

}

static int
webfw2_thrasher(request_rec * rec, webfw2_config_t * config,
                webfw2_filter_t * filter, const char *srcaddr,
                filter_rule_t *rule)
{
    thrasher_pkt_type pkt_type;
    int             query_ret;
    int             ident;

    PRINT_DEBUG("about to make a thrasher query\n");

    if (!config->thrasher_host || !config->thrasher_port) {
        PRINT_DEBUG("%p %p\n", config->thrasher_host,
                    config->thrasher_port);
        return DECLINED;
    }

    /*
     * if this is a v3 packet - we want to randomly generate
     * an ident number, else this will stay 0 
     */
    ident = 0;

    if (!thrasher_is_connected(filter->thrasher_sock)) {
        PRINT_DEBUG("Thrasher isn't connected..\n");

        if (!thrasher_should_retry(config, filter))
            return DECLINED;

        PRINT_DEBUG("Attempting reconnect....\n");

        if (!
            (filter->thrasher_sock =
             thrasher_connect(filter->pool, config))) {
            thrasher_err_shutdown(filter);
            return DECLINED;
        }

    }

    /*
     * our socket is connected 
     */

    if (!srcaddr || !rec->uri || !rec->hostname) {
        /*
         * if none of the normal data is available, we
         * aren't really interested 
         */
        PRINT_DEBUG("!srcaddr || !rec->uri || !rec->hostname\n");
        return DECLINED;
    }

    /*
     * match up our packet types with what came back from
     * the filter rules action 
     */
    switch (rule->action) {
    case FILTER_THRASH_PROFILE_v1:
    case FILTER_THRASH_v1:
        pkt_type = TYPE_THRESHOLD_v1;
        break;
    case FILTER_THRASH_v2:
    case FILTER_THRASH_PROFILE_v2:
        PRINT_DEBUG("Profile v2\n");
        pkt_type = TYPE_THRESHOLD_v2;
        break;
    case FILTER_THRASH_v3:
    case FILTER_THRASH_PROFILE_v3:
        pkt_type = TYPE_THRESHOLD_v3;

        /*
         * generate a random value for our identification 
         * portion of this packet. 
         */
        if (apr_generate_random_bytes((unsigned char *) &ident,
                                      sizeof(uint32_t)) != APR_SUCCESS)
            return DECLINED;

        break;
    case FILTER_THRASH_v4:
    case FILTER_THRASH_PROFILE_v4:
        pkt_type = TYPE_THRESHOLD_v4;

        /*
         * generate a random value for our identification 
         * portion of this packet. 
         */
        if (apr_generate_random_bytes((unsigned char *) &ident,
                                      sizeof(uint32_t)) != APR_SUCCESS)
            return DECLINED;

        break;
    case FILTER_THRASH_v6:
    case FILTER_THRASH_PROFILE_v6:
        pkt_type = TYPE_THRESHOLD_v6;

        /*
         * generate a random value for our identification 
         * portion of this packet. 
         */
        if (apr_generate_random_bytes((unsigned char *) &ident,
                                      sizeof(uint32_t)) != APR_SUCCESS)
            return DECLINED;

        break;
    default:
        /*
         * unknown thrasher type :( 
         */
        return DECLINED;
    }

    query_ret = thrasher_query(rec, config, filter,
                               pkt_type, srcaddr, ident, rule->name);

    PRINT_DEBUG("Blah %d\n", query_ret);

    if (query_ret < 0) {
        thrasher_err_shutdown(filter);
        return DECLINED;
    }

    if (query_ret == 1)
        return config->default_taction;

    return DECLINED;
}


filter_rule_t  *
webfw2_traverse_filter(request_rec * rec,
                       webfw2_config_t * config,
                       webfw2_filter_t * filter,
                       filter_rule_t * current_rule,
                       apr_array_header_t * addrs, char **sip, char **dip)
{
    char           *src_ip;
    char           *dst_ip;
    void          **callback_data;
    filter_rule_t  *rule;
    int             i,
                    ret;

    rule = NULL;
    src_ip = dst_ip = NULL;

    if (!rec->pool || !filter || !addrs)
        return NULL;

    for (i = 0; i < addrs->nelts; i++) {
        current_rule = filter->filter->head;

        ret = DECLINED;

        callback_data = apr_pcalloc(rec->pool, sizeof(void *) * 3);

        src_ip = ((char **) addrs->elts)[i];
        dst_ip = (char *) rec->connection->local_ip;

        callback_data[0] = (void *) rec;
        callback_data[1] = (void *) src_ip;
        callback_data[2] = (void *) dst_ip;

        PRINT_DEBUG("Rule %s Traversing with %s\n",
                    current_rule->name, src_ip);

        do {
            if (!current_rule)
                break;

            rule = filter_traverse_filter(filter->filter,
                                          current_rule,
                                          (void *) callback_data);

            if (!rule)
                break;

            PRINT_DEBUG("MATCHED RULE %s\n", rule->name);

            if (rule->action >= FILTER_THRASH &&
                rule->action <= FILTER_THRASH_PROFILE_v6) {
                /*
                 * we don't want to stop rule processing if a
                 * thrasher rule was found but no thresholds were
                 * hit. We only break out of our do loop if the
                 * response was positive. 
                 */
                ret =
                    webfw2_thrasher(rec, config, filter, src_ip,
                                    rule);

                PRINT_DEBUG
                    ("Thrasher (%d) packet sent for %s. Ret status: %d\n",
                     rule->action, src_ip, ret);

                if (ret != DECLINED)
                    /*
                     * return was positive, we want to stop all
                     * further processing 
                     */
                    break;
            }

            /*
             * check to see if we should continue rule traversal 
             */
            if ((rule->action == FILTER_PASS) ||
                (rule->action >= FILTER_THRASH &&
                rule->action <= FILTER_THRASH_PROFILE_v6)) {
                char           *curr_passes;

                curr_passes = (char *)
                    apr_table_get(rec->notes, "webfw2_passed");

                /*
                 * generate a simple note that shows which rules this
                 * has passed without blocking 
                 */
                if (!curr_passes)
                    curr_passes = apr_psprintf(rec->pool,
                                               "%s:%s", src_ip,
                                               rule->name);
                else
                    curr_passes = apr_psprintf(rec->pool,
                                               "%s -> %s:%s",
                                               curr_passes, src_ip,
                                               rule->name);

                apr_table_set(rec->notes, "webfw2_passed", curr_passes);
                current_rule = rule->next;
                rule = NULL;
                continue;
            }

            /*
             * we have matched a rule with no special conditions 
             */
            ret = rule->action;
            break;
        } while (1);

        if (ret != DECLINED)
            break;
    }

    *sip = src_ip;
    *dip = dst_ip;

    return rule;
}

static int
webfw2_handler(request_rec * rec)
{
    int             ret;
    char           *matched_src_ip,
                   *matched_dst_ip;
    webfw2_filter_t *wf2_filter;
    webfw2_config_t *config;
    filter_rule_t  *current_rule;
    filter_rule_t  *rule;
    apr_array_header_t *addrs;

    rule = NULL;
#if 0
#ifdef ENABLE_APREQ
    const apr_table_t *args;
    apreq_handle_t *h = apreq_handle_apache2(rec);
    apreq_body(h, &args);
    const char     *params = apreq_params_as_string(rec->pool, args, NULL,
                                                    APREQ_JOIN_QUOTE);
    printf("%s\n", params);
#endif
#endif

    config = ap_get_module_config(rec->server->module_config,
                                  &webfw2_module);
    ap_assert(config);

    apr_pool_userdata_get((void **) &wf2_filter,
                          FILTER_CONFIG_KEY, rec->server->process->pool);

    ap_assert(wf2_filter);

    if (!wf2_filter->filter || !wf2_filter->filter->rule_count)
        return DECLINED;

#ifdef APR_HAS_THREADS
    apr_thread_rwlock_wrlock(wf2_filter->rwlock);
#endif
    webfw2_set_interesting_notes(rec);

    /*
     * set our current rule, which is going to be
     * the start of all rules. 
     */
    current_rule = wf2_filter->filter->head;

    /*
     * grab all the source addresses within the request 
     */
    addrs = webfw2_find_all_sources(rec);
    
    do {
        /*
         * initialize our default return 
         */
        ret = DECLINED;

        if (!current_rule || !addrs ||
            !wf2_filter->filter || !current_rule)
            break;

        rule = webfw2_traverse_filter(rec,
                                      config,
                                      wf2_filter,
                                      current_rule,
                                      addrs,
                                      &matched_src_ip, &matched_dst_ip);

        if (!rule)
            /*
             * no rules matched 
             */
            break;

        /*
         * rule matched without any odd exceptions, setup the 
         * right return action 
         */

        switch (rule->action) {

        case FILTER_DENY:
            if (rule->status_code)
                ret = rule->status_code;
            else
                ret = config->default_action;
            break;
        case FILTER_PERMIT:
            ret = DECLINED;
            break;
        case FILTER_REDIRECT:
            ret = 302;
            apr_table_setn(rec->headers_out, "Location", rule->redirect_url);
            break;
        case FILTER_THRASH_v2:
        case FILTER_THRASH_v3:
        case FILTER_THRASH_v4:
        case FILTER_THRASH_v6:
        case FILTER_THRASH:
            if (rule->status_code)
                ret = rule->status_code;
            else
                ret = config->default_taction;
            break;
        case FILTER_THRASH_PROFILE_v2:
        case FILTER_THRASH_PROFILE_v3:
        case FILTER_THRASH_PROFILE_v4:
        case FILTER_THRASH_PROFILE_v6:
        case FILTER_THRASH_PROFILE:
            ret = DECLINED;
            break;
        default:
            ret = rule->action;
            break;
        }

        break;
    } while (1);


    if (rule) {
        if (rule->log) {
            /*
             * logging is enabled for this rule 
             */
            apr_table_set(rec->notes, "webfw2_rule", rule->name);
            apr_table_set(rec->subprocess_env, "webfw2_rule", rule->name);
            apr_table_set(rec->notes, "webfw2_matched_ip", matched_src_ip);
            apr_table_set(rec->subprocess_env, "webfw2_matched_ip",
                          matched_src_ip);
        }

        if (rule->update_rule) {
            PRINT_DEBUG("Updating Dynamic rule %s with src-ip %s\n",
                        rule->update_rule->name, matched_src_ip);
            filter_rule_add_network(rule->update_rule, matched_src_ip,
                                    RULE_MATCH_SRCADDR);
        }

    }
#ifdef APR_HAS_THREADS
    apr_thread_rwlock_unlock(wf2_filter->rwlock);
#endif

    return ret;
}

/*
 * frontend for hooking inside access checker hook 
 */
static int
webfw2_handler_access_hook(request_rec * rec)
{
    webfw2_config_t *config;

    config = ap_get_module_config(rec->server->module_config,
                                  &webfw2_module);

    if (!config->hook_access)
        return DECLINED;

    return webfw2_handler(rec);
}

/*
 * frontend for hooking inside translation hook 
 */
static int
webfw2_handler_translate_hook(request_rec * rec)
{
    webfw2_config_t *config;

    config = ap_get_module_config(rec->server->module_config,
                                  &webfw2_module);

    if (!config->hook_translate)
        return DECLINED;

    return webfw2_handler(rec);
}

static int
webfw2_handler_post_read_hook(request_rec * rec)
{
    webfw2_config_t *config;

    config = ap_get_module_config(rec->server->module_config,
                                  &webfw2_module);

    if (!config->hook_post_read)
        return DECLINED;

    return webfw2_handler(rec);
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

    config->thrasher_timeout = 50000;

    /*
     * set the default return action to 542 
     */
    config->default_action = 418;
    config->default_taction = 420;

    /*
     * set default retry for every 60 seconds if error 
     */
    config->thrasher_retry = 60;

    /*
     * by default we want to hook into the check_access request processing. 
     */
    config->hook_access = 1;
    config->hook_translate = 0;

    return config;
}

static const char *
cmd_thrasher_timeout(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);
    config->thrasher_timeout = atoi(arg);
    return NULL;
}

static const char *
cmd_thrasher_retry(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);
    config->thrasher_retry = atoi(arg);
    return NULL;
}

static const char *
cmd_config_file(cmd_parms * cmd, void *dummy_config, char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    config->config_file = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *
cmd_thrasher_host(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    config->thrasher_host = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *
cmd_thrasher_port(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    config->thrasher_port = atoi(arg);
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

enum {
    XFF_OPT_SRCIP,
    XFF_OPT_LAST,
    XFF_OPT_FIRST
};

static struct xo_t_s {
    int             val;
    const char     *strval;
} name_to_int[] = {
    {
    XFF_OPT_SRCIP, "src-ip"}, {
    XFF_OPT_LAST, "last"}, {
    XFF_OPT_FIRST, "first"}, {
    0, NULL}
};

static int
xffopt_tok_to_int(char *token)
{
    int             i;

    for (i = 0; name_to_int[i].strval != NULL; i++)
        if (!strncasecmp(name_to_int[i].strval, token,
                         strlen(name_to_int[i].strval)))
            return name_to_int[i].val;

    return -1;
}

static webfw2_xff_opts_t *
parse_xff_opts(apr_pool_t * pool, char *xff_header, const char *str)
{
    /*
     * XFF ACL EBNF:
     * start      := directives
     * directives := ((src_ip)+ | last | first), ws?
     * src_ip     := ws?, "src_ip", ws, IP_ADDR
     * last       := ws?, "last", ws, INT
     * first      := ws?, "first", ws, INT
     */

    char          **tokens,
                   *tok;
    webfw2_xff_opts_t *xff_opts;
    int             i = 0;

    xff_opts = apr_pcalloc(pool, sizeof(webfw2_xff_opts_t));
    ap_assert(xff_opts);

    xff_opts->xff_header = xff_header;

    if (!str)
        /*
         * no acl, just return the empty structure 
         */
        return xff_opts;

    tokens = filter_tokenize_str((char *) str, " ", NULL);

    while ((tok = tokens[i++]) != NULL) {
        /*
         * tok is now the key, tokens[i] points to the value 
         */
        if (tokens[i] == NULL) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                         "XFF Token %s has no value", tokens[i]);
            free_tokens(tokens);
            return NULL;
        }

        switch (xffopt_tok_to_int(tok)) {
        case XFF_OPT_SRCIP:
            if (!xff_opts->source_ip)
                xff_opts->source_ip = apr_hash_make(pool);

            apr_hash_set(xff_opts->source_ip,
                         apr_pstrdup(pool, tokens[i]),
                         APR_HASH_KEY_STRING, xff_opts);
            break;
        case XFF_OPT_LAST:
            xff_opts->last = atoi(tokens[i]);
            break;
        case XFF_OPT_FIRST:
            xff_opts->first = atoi(tokens[i]);
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                         "XFF Unknown token key %s", tokens[i]);
            exit(1);
        }

        i++;
    }

    free_tokens(tokens);
    return xff_opts;
}

static const char *
cmd_rw_xff(cmd_parms * cmd, void *dummy_config, const char *arg1,
           const char *arg2)
{
    webfw2_config_t *config;
    webfw2_xff_opts_t *xffopts;
    char           *xff_header;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    if (!config->xff_headers)
        config->xff_headers = apr_table_make(cmd->pool, 1);

    ap_assert(config->xff_headers);

    xff_header = apr_pstrdup(cmd->pool, arg1);
    ap_assert(xff_header);
    ap_str_tolower(xff_header);

    xffopts = parse_xff_opts(cmd->pool, xff_header, arg2);

    apr_table_setn(config->xff_headers, xff_header, (void *) xffopts);

    return NULL;
}

static const char *
cmd_set_action(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;
    char           *type;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    type = cmd->info;

    if (!strcmp(type, "denied"))
        config->default_action = atoi(arg);
    else if (!strcmp(type, "thrasher"))
        config->default_taction = atoi(arg);

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
    else if (!strcmp(type, "header"))
        array = &config->match_header;
    else
        return NULL;

    if (!*array)
        *array = apr_array_make(cmd->pool, 1, sizeof(char *));

    note = apr_pstrdup(cmd->pool, arg);
    ap_assert(note);

    *(const char **) apr_array_push(*array) = note;

    return NULL;
}

static const char *
cmd_hook_level(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    webfw2_config_t *config;
    char           *type;

    type = cmd->info;

    config = ap_get_module_config(cmd->server->module_config,
                                  &webfw2_module);

    ap_assert(config);

    if (!strcmp(type, "access")) {
        config->hook_translate = 0;
        config->hook_post_read = 0;
        config->hook_access = 1;
    } else if (!strcmp(type, "translate")) {
        config->hook_translate = 1;
        config->hook_post_read = 0;
        config->hook_access = 0;
    } else if (!strcmp(type, "post_read")) {
        config->hook_post_read = 1;
        config->hook_translate = 0;
        config->hook_access = 0;
    } else
        return NULL;

    return NULL;
}

static void
webfw2_hooker(apr_pool_t * pool)
{
    static const char *beforeme_list[] = {
        "mod_chad.c",
        "mod_ipintell.c",
        NULL
    };

    static const char *afterme_list[] = {
        "mod_rewrite.c",
        "mod_proxy.c",
        NULL
    };

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                 "initializing mod_webfw2 v%s", VERSION);

    ap_hook_child_init(webfw2_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_translate_name(webfw2_handler_translate_hook,
                           beforeme_list, afterme_list, APR_HOOK_MIDDLE);

    ap_hook_access_checker(webfw2_handler_access_hook,
                           beforeme_list, afterme_list, APR_HOOK_MIDDLE);

    ap_hook_log_transaction(webfw2_updater,
                            NULL, NULL, APR_HOOK_REALLY_LAST);

    ap_hook_post_read_request(webfw2_handler_post_read_hook,
                              beforeme_list,
                              afterme_list, APR_HOOK_MIDDLE);

}

const command_rec webfw2_directives[] = {
    AP_INIT_TAKE1("webfw2_config",
                  (void *) cmd_config_file,
                  NULL,
                  RSRC_CONF,
                  "The full path to where the webfw2 configuration lives"),

    AP_INIT_TAKE1("webfw2_update_interval",
                  cmd_update_interval,
                  NULL,
                  RSRC_CONF,
                  "The time (in seconds) to check for configuration changes"),

    AP_INIT_TAKE12("webfw2_rw_xff",
                   cmd_rw_xff,
                   NULL,
                   RSRC_CONF,
                   "If this header is present, we use this IP address to filter."
                   "Note: This has an optional XFF ACL that may be applied"),

    AP_INIT_TAKE1("webfw2_match_note",
                  cmd_match_variable,
                  "note",
                  RSRC_CONF,
                  "Pass a note to filterfilter"),

    AP_INIT_TAKE1("webfw2_match_env",
                  cmd_match_variable,
                  "env",
                  RSRC_CONF,
                  "Pass an env to the filterfilter"),

    AP_INIT_TAKE1("webfw2_match_header",
                  cmd_match_variable,
                  "header",
                  RSRC_CONF,
                  "Pass a client header to the filter"),

    AP_INIT_TAKE1("webfw2_default_action",
                  cmd_set_action,
                  "denied",
                  RSRC_CONF,
                  "The default return status for a blocked connection"),

    AP_INIT_TAKE1("webfw2_default_thrash_action",
                  cmd_set_action,
                  "thrasher",
                  RSRC_CONF,
                  "The default return status for a thrashed connection"),

    AP_INIT_TAKE1("webfw2_thrasher_host",
                  cmd_thrasher_host,
                  NULL,
                  RSRC_CONF,
                  "Enable thrasher and connect to this host"),

    AP_INIT_TAKE1("webfw2_thrasher_port",
                  cmd_thrasher_port,
                  NULL,
                  RSRC_CONF,
                  "Enable thrasher and connect to this port"),

    AP_INIT_TAKE1("webfw2_thrasher_timeout",
                  cmd_thrasher_timeout,
                  NULL,
                  RSRC_CONF,
                  "Timeout (in usec) for any thrasher socket operation"),

    AP_INIT_TAKE1("webfw2_thrasher_retry",
                  cmd_thrasher_retry,
                  NULL,
                  RSRC_CONF,
                  "If thrasher server is down, wait this long before webfw2 "
                  "attempts a reconnect"),

    AP_INIT_FLAG("webfw2_hook_translate",
                 (void *) cmd_hook_level,
                 "translate",
                 RSRC_CONF,
                 "Hook inside the ap_hook_translate_name() portion of the request "
                 "processing. This is good to process pre mod_rewrite/proxy"),

    AP_INIT_FLAG("webfw2_hook_access",
                 (void *) cmd_hook_level,
                 "access",
                 RSRC_CONF,
                 "Hook inside the ap_hook_access_checker() request processing"),

    AP_INIT_FLAG("webfw2_hook_post_read",
                 (void *) cmd_hook_level,
                 "post_read",
                 RSRC_CONF,
                 "Hook inside post_read_request(), very early on in request processing"),
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
