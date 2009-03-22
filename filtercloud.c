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
#include "apr_strings.h"
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
    RULE_MATCH_STRING, "match_string"}, {	
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

    for (i = 0; name_to_int[i].strval != NULL; i++) {
        if (!strncasecmp(name_to_int[i].strval, token, strlen(name_to_int[i].strval)))
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
cloud_match_srcaddr(apr_pool_t * pool, cloud_rule_t * rule, void *data, 
	void *usrdata)
{
    if (!rule->src_addrs)
        return 1;

    if ((try_search_best(pool, rule->src_addrs, (char *) data)))
        return 1;

    return 0;
}

static int
cloud_match_dstaddr(apr_pool_t * pool, cloud_rule_t * rule, void *data,
	void *usrdata)
{
    if (!rule->dst_addrs)
        return 1;

    if ((try_search_best(pool, rule->dst_addrs, (char *) data)))
        return 1;

    return 0;
}

static int
cloud_match_string(apr_pool_t *pool, 
	cloud_rule_t *rule, void *val, void *key)
{
    apr_hash_t *string_hash;

    if(!rule->strings)
	return 1;

    if (!key || !val)
    {
	return 0;
    }

    if(!(string_hash=apr_hash_get
		(rule->strings, (char *)key, 
		 APR_HASH_KEY_STRING)))
	return 0;


    if(apr_hash_get(string_hash, (char *)val, APR_HASH_KEY_STRING))
       return 1;	

    return 0;
}


static rule_flow_t    *
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
	case RULE_MATCH_STRING:
	    /* in order to have a proper string matching
	     * along with the proper precedence and ordering
	     * we must set a flow where the value is the 
	     * section of strings to match. */

	    /* remove the match_string( and the ending ) */
	    tok[strlen(tok)-1] = 0;
	    tok = &tok[13];

	    new_flow = cloud_rule_flow_init(pool);
	    new_flow->callback = cloud_match_string;
	    new_flow->type = RULE_MATCH_STRING;
	    new_flow->user_data = (void *)apr_pstrdup(pool, tok);

	    if(!flow)
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

static int
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

static cloud_rule_t   *
cloud_rule_init(apr_pool_t * parent)
{
    cloud_rule_t   *rule;

    rule = (cloud_rule_t *)
        apr_pcalloc(parent, sizeof(cloud_rule_t));

    apr_pool_create(&rule->pool, parent);;

    return rule;
}

static int
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

static int
cloud_rule_add_network(cloud_rule_t * rule,
                       const char *network, const int direction,
                       void *data)
{
    patricia_tree_t **tree;
    patricia_tree_t *rtree;
    patricia_node_t *pnode;

    switch (direction) {
    case RULE_MATCH_SRCADDR:
        tree = &rule->src_addrs;
        break;
    case RULE_MATCH_DSTADDR:
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

static int
cloud_rule_add_string(cloud_rule_t *rule, char *key, char *val)
{
    /* a string match set is a hash of hashes.
     *
     * The "key" in this case is a hash key of our
     * rule->strings hash. The values of that hash
     * will be our value passed to this function.
     */

    /* ok, string matching rules are a bit odd here. I haven't
     * really thought of a more dynamic way to do this that fits
     * in with the current architecture. 
     *
     * With string matching we can have multiple "keys" or 
     * string groups. In order to facilitate these groups 
     * within our rule we have a hash of hashes that can be 
     * found under rule->strings. 
     *
     * For every "group" found within the config, the group
     * name is used as a key to another hash which holds all
     * of the values. Since our string matching is static strings
     * we hash the string values with a value of 1 
     *
     * Now to how strings work with our rule flow.
     *
     * In normal situations we have a set of flow callbacks,
     * these callbacks are run after running a user set callback
     * that fetches the correct data for the flow in question.
     *
     * In a string flow situation 
     *
     * */ 
    apr_hash_t *subnode;
    char *ckey;
    char *cval;

    ckey = (char *)apr_pstrdup(rule->pool, key);
    cval = (char *)apr_pstrdup(rule->pool, val);

    if (!rule->strings)
	rule->strings = apr_hash_make(rule->pool);

    if(!(subnode = apr_hash_get(rule->strings,
		    (char *)ckey, APR_HASH_KEY_STRING)))
    {
	subnode = apr_hash_make(rule->pool);
	apr_hash_set(rule->strings, ckey, 
		APR_HASH_KEY_STRING, subnode); 
		    
    }

    apr_hash_set(subnode, cval, 
	    APR_HASH_KEY_STRING, (void *)1); 

    return 0;

}

static int 
cloud_match_rulen(apr_pool_t *pool, cloud_filter_t *filter, 
	cloud_rule_t *rule, const void *usrdata)
{
    int matched_rule = 0;
    rule_flow_t *flows = rule->flow;


    while(flows != NULL)
    {
	void *data, *extra;
	extra = NULL;

	switch(flows->type)
	{
	    case RULE_MATCH_SRCADDR:
		if (!filter->callbacks.src_addr_cb)
		{
		    flows = flows->next;
		    continue;
		}
		data = filter->callbacks.src_addr_cb(pool, NULL, usrdata);
		break;
	    case RULE_MATCH_DSTADDR:
		if(!filter->callbacks.dst_addr_cb)
		{
		    flows = flows->next;
		    continue;
		}
		data = filter->callbacks.dst_addr_cb(pool, NULL, usrdata);
		break;
	    case RULE_MATCH_STRING:
		/* first we must find the callback associated 
		 * with this string key */
		{
		    void *(*cb)  (apr_pool_t *pool, void *fc_data, const void *usrdata);

		    if(!(cb=apr_hash_get(filter->callbacks.string_callbacks,
				    flows->user_data, APR_HASH_KEY_STRING)))
		    {
			flows = flows->next;
			continue;
		    }
		    data = cb(pool, flows->user_data, usrdata);
		    extra = flows->user_data;
		}
		break;
	}
	
	if (flows->callback(pool, rule, data, extra) == 1)
	{
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

	if (flows->this_operator == RULE_MATCH_OPERATOR_AND &&
		flows->next_operator != RULE_MATCH_OPERATOR_OR)
	{
	    matched_rule = 0;
	    break;
	}

	if (flows->this_operator == RULE_MATCH_OPERATOR_OR &&
		flows->next_operator == RULE_MATCH_OPERATOR_AND) 
	{
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
                      const void *usrdata)
{
    cloud_rule_t   *rule = filter->head;
    apr_pool_t     *subpool;

    apr_pool_create(&subpool, NULL);

    while (rule != NULL) {
	if (cloud_match_rulen(subpool, filter, rule, usrdata) == 1)
	    break;

	apr_pool_clear(subpool);
        rule = rule->next;
    }

    apr_pool_destroy(subpool);
    return rule;
}

int
cloud_register_user_cb(cloud_filter_t *filter, 
	void *(*cb)(apr_pool_t *p, void *fc_data, const void *d), 
	int type, void *data)
{
    /* 
     * If a callback isn't registered for a specific
     * datatype, the rule will not even attempt to match
     * that flow.
     */
    switch(type)
    {
	case RULE_MATCH_SRCADDR:
	    filter->callbacks.src_addr_cb = cb;
	    break;
	case RULE_MATCH_DSTADDR:
	    filter->callbacks.dst_addr_cb = cb;
	    break;
	case RULE_MATCH_STRING:
	    if(!filter->callbacks.string_callbacks)
		filter->callbacks.string_callbacks 
		    = apr_hash_make(filter->pool);

	    apr_hash_set(filter->callbacks.string_callbacks,
		    (char *)apr_pstrdup(filter->pool, data),
		    APR_HASH_KEY_STRING, (void *)cb);
	    break;

    }
    return 0;
}

cloud_filter_t *
cloud_parse_config(apr_pool_t * pool, const char *filename)
{
    cfg_t          *cfg;
    cloud_filter_t *filter;
    int             ret;
    unsigned int    n,
                    i;

    cfg_opt_t       str_match_opts[] = {
	CFG_BOOL("case_sensitive", cfg_true, CFGF_NONE),
	CFG_STR_LIST("values", 0, CFGF_MULTI),
	CFG_END()
    };

    cfg_opt_t       rule_opts[] = {
        CFG_STR("flow",
                "match_src_addr && match_dst_addr || match_http_header",
                CFGF_NONE),
        CFG_BOOL("enabled", cfg_true, CFGF_NONE),
        CFG_STR_LIST("src_addrs", 0, CFGF_MULTI),
        CFG_STR_LIST("dst_addrs", 0, CFGF_MULTI),
	CFG_SEC("match_string", str_match_opts, CFGF_MULTI | CFGF_TITLE),
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
        cloud_rule_t   *cloud_rule;
        cfg_t          *rule;

        rule = cfg_getnsec(cfg, "rule", i);
        flow = cfg_getstr(rule, "flow");

        cloud_rule = cloud_rule_init(filter->pool);
	cloud_rule->name = apr_pstrdup(pool, cfg_title(rule));
        cloud_rule_add_flow(cloud_rule, (char *) apr_pstrdup(pool, flow));

        for (addr_cnt = 0; addr_cnt < cfg_size(rule, "src_addrs");
             addr_cnt++) {
            char           *addr =
                cfg_getnstr(rule, "src_addrs", addr_cnt);
            cloud_rule_add_network(cloud_rule, addr, RULE_MATCH_SRCADDR, NULL);
        }

        for (addr_cnt = 0; addr_cnt < cfg_size(rule, "dst_addrs");
             addr_cnt++) {
            char           *addr =
                cfg_getnstr(rule, "dst_addrs", addr_cnt);
            cloud_rule_add_network(cloud_rule, addr, RULE_MATCH_DSTADDR, NULL);
        }

	int str_match_size = cfg_size(rule, "match_string");
	int sm_n;

	for (sm_n = 0; sm_n < str_match_size; sm_n++)
	{
	    cfg_t *matcher;
	    int value_cnt;

	    matcher = cfg_getnsec(rule, "match_string", sm_n);

	    for (value_cnt = 0; value_cnt < cfg_size(matcher, "values");
		    value_cnt++) {
		char *str =
		    cfg_getnstr(matcher, "values", value_cnt); 

		printf("String Match Title: %s\n", cfg_title(matcher));
		printf("Case sensitive? %s\n",
			cfg_getbool(matcher, "case_sensitive") ?
			"true":"false");
		printf("String value: %s\n", str);
		cloud_rule_add_string(cloud_rule, 
			(char *)cfg_title(matcher), str);
	    }

	}

        cloud_filter_add_rule(filter, cloud_rule);
    }

    cfg_free(cfg);

    return filter;
}


#ifdef TEST_FILTERCLOUD
void *src_addr_cb(apr_pool_t *pool, void *fc_data, const void *d)
{
    char **argv = (char **)d;
    printf("%s\n", __FUNCTION__);
    return argv[1];
}

void *dst_addr_cb(apr_pool_t *pool, void *fc_data, const void *d)
{
    char **argv = (char **)d;

    printf("%s\n", __FUNCTION__);
    return argv[2];
}

void *cloud_str_cb(apr_pool_t *pool, void *fc_data, const void *d)
{
    printf("%s\n", __FUNCTION__);
    return "abcdef";
}

void *cloud_str2_cb(apr_pool_t *pool, void *fc_data, const void *d)
{
    printf("%s\n", __FUNCTION__);
    return "derr";
}

int
main(int argc, char **argv)
{
    cloud_filter_t *filter;
    cloud_rule_t   *rule;

    apr_pool_t     *root_pool;
    apr_initialize();
    apr_pool_create(&root_pool, NULL);
    filter = cloud_parse_config(root_pool, "./test.conf");

    cloud_register_user_cb(filter, src_addr_cb, RULE_MATCH_SRCADDR, NULL); 
    cloud_register_user_cb(filter, dst_addr_cb, RULE_MATCH_DSTADDR, NULL);
    cloud_register_user_cb(filter, cloud_str_cb, RULE_MATCH_STRING, "stuff");
    cloud_register_user_cb(filter, cloud_str2_cb, RULE_MATCH_STRING, "lame");

    rule = cloud_traverse_filter(filter, (void *)argv);

    printf("Matched filter? %s\n", rule?"yes":"no");

    apr_pool_destroy(root_pool);
    apr_terminate();
    return 0;
}
#endif
