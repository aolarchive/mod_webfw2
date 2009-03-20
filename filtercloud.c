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
#include "apr.h"
#include "apr_hash.h"
#include "apr_pools.h"
#include "patricia.h"
#include "filtercloud.h"
#include "confuse.h"

static struct n_t_s {
    int             val;
    const char     *strval;
} name_to_int[] = {
    {
    RULE_MATCH_SRCADDR, "match_src_addr"}, {
    RULE_MATCH_DSTADDR, "match_dst_addr"}, {
    RULE_MATCH_CHAD_ORD, "match_chad_ord"}, {
    RULE_MATCH_OPERATOR_OR, "||"}, {
    RULE_MATCH_OPERATOR_AND, "&&"}, {
    0, NULL}

};

void
free_tokens(char **tokens)
{
    char           *tok;
    int             i = 0;

    while ((tok = tokens[i++]) != NULL) {
        free(tok);
    }

    free(tokens);
}

static int
rule_token_to_int(char *token)
{
    int             i;
    int             ret;

    for (i = 0; name_to_int[i].strval != NULL; i++) {
        if (!strcasecmp(name_to_int[i].strval, token))
            return name_to_int[i].val;
    }

    return -1;
}

char          **
cloud_tokenize_str(char *string, const char *sep)
{
    char           *str_copy;
    char           *tok;
    char          **arr;
    int             ncount,
                    arrsize;
    char           *endptr = NULL;

    /*
     * get an initial size of the array 
     */
    arr = calloc(sizeof(char *), 32);
    arrsize = 32;
    ncount = 0;

    str_copy = strdup(string);

    for (tok = strtok_r(str_copy, sep, &endptr);
         tok != NULL; tok = strtok_r(NULL, sep, &endptr)) {
        if (ncount >= arrsize) {
            free_tokens(arr);
            return NULL;
        }

        arr[ncount++] = strdup(tok);
    }

    free(str_copy);
    return arr;
}

rule_flow_t    *
cloud_rule_flow_init(apr_pool_t * pool)
{
    return (rule_flow_t *)
        apr_pcalloc(pool, sizeof(rule_flow_t));
}

static int
cloud_match_srcaddr(apr_pool_t * pool, cloud_rule_t * rule, void *data)
{
    if (!rule->src_addrs)
        return 1;

    if ((try_search_best(pool, rule->src_addrs, (char *) data)))
        return 1;

    return 0;
}

static int
cloud_match_dstaddr(apr_pool_t * pool, cloud_rule_t * rule, void *data)
{
    if (!rule->dst_addrs)
        return 1;

    if ((try_search_best(pool, rule->dst_addrs, (char *) data)))
        return 1;

    return 0;
}

static int
cloud_match_chadorder(apr_pool_t * pool, cloud_rule_t * rule, void *data)
{
    if (!rule->chad_orders)
        return 1;

    if (!data)
	return 0;

    if (apr_hash_get
        (rule->chad_orders, (char *) data, APR_HASH_KEY_STRING))
        return 1;

    return 0;
}


rule_flow_t    *
cloud_flow_from_str(apr_pool_t * pool, char *flowstr)
{
    char          **tokens;
    char           *tok;
    int             i = 0;
    rule_flow_t    *tail = NULL;
    rule_flow_t    *flow = NULL;

    tokens = cloud_tokenize_str(flowstr, " ");

    while ((tok = tokens[i++]) != NULL) {
        rule_flow_t    *new_flow;

        switch (rule_token_to_int(tok)) {
        case RULE_MATCH_SRCADDR:
            new_flow = cloud_rule_flow_init(pool);
            new_flow->callback = cloud_match_srcaddr;
            new_flow->type = RULE_MATCH_SRCADDR;

            if (!flow) {
                flow = tail = new_flow;
            }

            else {
                new_flow->this_operator = tail->next_operator;
                tail->next = new_flow;
                tail = new_flow;
            }
            break;

        case RULE_MATCH_DSTADDR:
            new_flow = cloud_rule_flow_init(pool);
            new_flow->callback = cloud_match_dstaddr;
            new_flow->type = RULE_MATCH_DSTADDR;


            if (!flow)
                flow = tail = new_flow;
            else {
                new_flow->this_operator = tail->next_operator;
                tail->next = new_flow;
                tail = new_flow;
            }

            break;
        case RULE_MATCH_CHAD_ORD:
            new_flow = cloud_rule_flow_init(pool);
            new_flow->callback = cloud_match_chadorder;
            new_flow->type = RULE_MATCH_CHAD_ORD;

            if (!flow)
                flow = tail = new_flow;
            else {
                new_flow->this_operator = tail->next_operator;
                tail->next = new_flow;
                tail = new_flow;
            }
            break;
        case RULE_MATCH_OPERATOR_OR:
            if (!flow)
                /*
                 * we can't have an operator with no starting flow! 
                 */
                return NULL;

            tail->next_operator = RULE_MATCH_OPERATOR_OR;
            break;
        case RULE_MATCH_OPERATOR_AND:
            if (!flow)
                return NULL;

            tail->next_operator = RULE_MATCH_OPERATOR_AND;
            break;
        }
    }
    free_tokens(tokens);
    return flow;
}

int
cloud_rule_add_flow(cloud_rule_t * rule, char *data)
{
    rule->flow = cloud_flow_from_str(rule->pool, data);
    return 0;
}

cloud_filter_t *
cloud_filter_init(apr_pool_t * parent)
{
    cloud_filter_t *ret;
    ret = apr_pcalloc(parent, sizeof(cloud_filter_t));
    apr_pool_create(&ret->pool, parent);

    return ret;
}

cloud_rule_t   *
cloud_rule_init(apr_pool_t * parent)
{
    cloud_rule_t   *rule;

    rule = (cloud_rule_t *)
        apr_pcalloc(parent, sizeof(cloud_rule_t));

    apr_pool_create(&rule->pool, parent);;

    return rule;
}

int
cloud_filter_add_rule(cloud_filter_t * filter, cloud_rule_t * rule)
{
    if (!filter || !rule)
        return -1;

    if (!filter->tail) {
        filter->head = filter->tail = rule;
        return 0;
    }

    filter->tail->next = rule;
    filter->tail = rule;
    return 0;
}

int
cloud_rule_add_network(cloud_rule_t * rule,
                       const char *network, const int direction,
                       void *data)
{
    patricia_tree_t **tree;
    patricia_tree_t *rtree;
    patricia_node_t *pnode;

    switch (direction) {
    case RULE_ADDR_SRC:
        tree = &rule->src_addrs;
        break;
    case RULE_ADDR_DST:
        tree = &rule->dst_addrs;
        break;
    }

    if (*tree == NULL)
        *tree = New_Patricia(rule->pool, 32);

    rtree = *tree;

    if (!(pnode = make_and_lookup(rule->pool, rtree, (char *) network)))
        return -1;

    pnode->data = data;

    return 0;
}

int
cloud_rule_add_chad_order(cloud_rule_t * rule, char *order)
{

    if (!rule->chad_orders)
        rule->chad_orders = apr_hash_make(rule->pool);

    apr_hash_set(rule->chad_orders,
                 (char *) apr_pstrdup(rule->pool, order),
                 APR_HASH_KEY_STRING, (void *) 1);

    return 0;
}


int
cloud_match_rule(apr_pool_t * pool, cloud_rule_t * rule,
                 const char *srcip, const char *dstip, const void *usrdata)
{
    /*
     * go through each rule_flow_t do stuff 
     */
    int             matched_rule = 0;
    rule_flow_t    *flows = rule->flow;

    while (flows != NULL) {
        void           *data;
        switch (flows->type) {
        case RULE_MATCH_SRCADDR:
            data = (void *) srcip;
            break;
        case RULE_MATCH_DSTADDR:
            data = (void *) dstip;
            break;
        case RULE_MATCH_CHAD_ORD:
            data = (void *) usrdata;
            break;
        }

        if (flows->callback(pool, rule, data) == 1) {
            /*
             * We matched something in this callback. 
             */
            if (flows->next_operator == RULE_MATCH_OPERATOR_OR) {
                matched_rule = 1;
                break;
            }

            if (flows->next_operator == RULE_MATCH_OPERATOR_AND) {
                flows = flows->next;
                continue;
            }

            if (flows->next_operator == 0) {
                matched_rule = 1;
                break;
            }
        }

        /*
         * we didn't match anything in the callback :( 
         */
        if (flows->this_operator == RULE_MATCH_OPERATOR_AND &&
            flows->next_operator != RULE_MATCH_OPERATOR_OR) {
            matched_rule = 0;
            break;
        }


        if (flows->this_operator == RULE_MATCH_OPERATOR_OR &&
            flows->next_operator == RULE_MATCH_OPERATOR_AND) {
            matched_rule = 0;
            break;
        }

        flows = flows->next;
    }

    if (matched_rule)
        return 1;

    return 0;
}

cloud_rule_t   *
cloud_traverse_filter(cloud_filter_t * filter,
                      const char *srcip, const char *dstip,
                      const void *data)
{
    cloud_rule_t   *rule = filter->head;
    apr_pool_t     *subpool;

    apr_pool_create(&subpool, NULL);

    while (rule != NULL) {
        if (cloud_match_rule(subpool, rule, srcip, dstip, data) == 1)
            break;

	apr_pool_clear(subpool);
        rule = rule->next;
    }

    apr_pool_destroy(subpool);
    return rule;
}

cloud_filter_t *
cloud_parse_config(apr_pool_t * pool, const char *filename)
{
    cfg_t          *cfg;
    cloud_filter_t *filter;
    int             ret;
    unsigned int    n,
                    i;

    cfg_opt_t       addrs_opts[] = {
        CFG_STR("src", 0, CFGF_NONE),
        CFG_STR("dst", 0, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t       rule_opts[] = {
        CFG_STR("flow",
                "match_src_addr && match_dst_addr || match_http_header",
                CFGF_NONE),
        CFG_BOOL("enabled", cfg_true, CFGF_NONE),
        CFG_STR_LIST("src_addrs", 0, CFGF_MULTI),
        CFG_STR_LIST("dst_addrs", 0, CFGF_MULTI),
        CFG_STR_LIST("chad_orders", 0, CFGF_MULTI),
        CFG_END()
    };

    cfg_opt_t       opts[] = {
        CFG_SEC("rule", rule_opts, CFGF_MULTI | CFGF_TITLE),
        CFG_END()
    };

    cfg = cfg_init(opts, CFGF_NOCASE);
    ret = cfg_parse(cfg, filename);
    filter = cloud_filter_init(pool);

    n = cfg_size(cfg, "rule");

    for (i = 0; i < n; i++) {
        char           *flow;
        int             addr_cnt;
        int             chad_cnt;
        cloud_rule_t   *cloud_rule;
        cfg_t          *rule;

        rule = cfg_getnsec(cfg, "rule", i);
        flow = cfg_getstr(rule, "flow");

        cloud_rule = cloud_rule_init(filter->pool);
        cloud_rule_add_flow(cloud_rule, (char *) apr_pstrdup(pool, flow));

        for (addr_cnt = 0; addr_cnt < cfg_size(rule, "src_addrs");
             addr_cnt++) {
            char           *addr =
                cfg_getnstr(rule, "src_addrs", addr_cnt);
            cloud_rule_add_network(cloud_rule, addr, RULE_ADDR_SRC, NULL);
        }

        for (addr_cnt = 0; addr_cnt < cfg_size(rule, "dst_addrs");
             addr_cnt++) {
            char           *addr =
                cfg_getnstr(rule, "dst_addrs", addr_cnt);
            cloud_rule_add_network(cloud_rule, addr, RULE_ADDR_DST, NULL);
        }

        for (chad_cnt = 0; chad_cnt < cfg_size(rule, "chad_orders");
             chad_cnt++) {
            char           *order =
                cfg_getnstr(rule, "chad_orders", chad_cnt);

            cloud_rule_add_chad_order(cloud_rule, order);
        }

        // cloud_rule_add_chad_order(rule, "abcdef");

        cloud_filter_add_rule(filter, cloud_rule);
    }

    cfg_free(cfg);

    return filter;
}


#ifdef TEST_FILTERCLOUD
int
main(int argc, char **argv)
{
    cloud_filter_t *filter;
    cloud_rule_t   *rule;

    apr_pool_t     *root_pool;
    apr_initialize();
    apr_pool_create(&root_pool, NULL);
    filter = cloud_parse_config(root_pool, "./test.conf");
    cloud_traverse_filter(filter, argv[1], argv[2], NULL);
    apr_pool_destroy(root_pool);
    apr_terminate();
    return 0;
#if 0
    filter = cloud_filter_init(root_pool);
    rule = cloud_rule_init(filter->pool);
    cloud_rule_add_network(rule, "64.12.23.0/27", RULE_ADDR_SRC, NULL);
    cloud_rule_add_network(rule, "127.0.0.0/30", RULE_ADDR_SRC, NULL);
    cloud_rule_add_network(rule, "5.5.5.5", RULE_ADDR_SRC, NULL);
    cloud_rule_add_network(rule, "10.0.0.1/32", RULE_ADDR_DST, NULL);
    cloud_rule_add_flow(rule, argv[1]);
    cloud_filter_add_rule(filter, rule);
    rule = cloud_rule_init(filter->pool);
    cloud_rule_add_network(rule, "3.3.3.3/32", RULE_ADDR_SRC, NULL);
    cloud_rule_add_network(rule, "4.4.4.4/32", RULE_ADDR_DST, NULL);
    cloud_rule_add_chad_order(rule, "abcdef");
    cloud_rule_add_flow(rule, argv[1]);
    cloud_filter_add_rule(filter, rule);
    cloud_traverse_filter(filter, argv[2], argv[3], NULL);
    return 0;
#endif

}
#endif
