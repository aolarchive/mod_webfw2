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
#include <regex.h>
#include "filter.h"
#include "confuse.h"


#define REGEX_KEY "$_R_$_E_$_G_$_X_$"

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
    RULE_MATCH_NOT_SRCADDR, "!match_src_addr"}, {
    RULE_MATCH_NOT_DSTADDR, "!match_dst_addr"}, {
    RULE_MATCH_NOT_STRING, "!match_string"}, {
    0, NULL}
};

int
filter_validate_ip(char *addrstr)
{
    struct in_addr sa;

    if(inet_pton(AF_INET, addrstr, &sa))
	return 1;

    PRINT_DEBUG("%s is not a valid IP address!\n", addrstr);

    return 0;
} 

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
        if (!strncasecmp(name_to_int[i].strval, token,
                         strlen(name_to_int[i].strval)))
            return name_to_int[i].val;
    }

    return -1;
}

char *
filter_trim_str(char *str)
{
    size_t len = 0;
    char *frontp = str - 1;
    char *endp = NULL;

    if( str == NULL )
            return NULL;

    if( str[0] == '\0' )
            return str;

    len = strlen(str);
    endp = str + len;

    while(isspace(*(++frontp)));
    while(isspace(*(--endp)) && endp != frontp);

    if( str + len - 1 != endp )
            *(endp + 1) = '\0';

    else if( frontp != str &&  endp == frontp )
            *str = '\0';

    endp = str;

    if(frontp != str)
    {
	while( *frontp ) 
	    *endp++ = *frontp++;
	*endp = '\0';
    }
    return str;
}


char          **
filter_tokenize_str(char *string, const char *sep, int *nelts)
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
    arr = calloc(sizeof(char *), 128);
    arrsize = 128;
    ncount = 0;

    str_copy = strdup(string);

    for (tok = strtok_r(str_copy, sep, &endptr);
         tok != NULL; tok = strtok_r(NULL, sep, &endptr)) {

        if (ncount >= arrsize-1) 
	    /* leave enough room for the last NULL */
	    break;
	tok = filter_trim_str(tok);

        PRINT_DEBUG("Got token '%s'\n", tok);
        arr[ncount++] = strdup(tok);
    }

    free(str_copy);

    if (nelts)
	*nelts = ncount;

    return arr;
}

rule_flow_t    *
filter_rule_flow_init(apr_pool_t * pool)
{
    return (rule_flow_t *)
        apr_pcalloc(pool, sizeof(rule_flow_t));
}

static int
filter_match_srcaddr(apr_pool_t * pool, filter_rule_t * rule, void *data,
                    void *usrdata)
{
    if (!rule->src_addrs)
        return 1;

    if ((try_search_best(pool, rule->src_addrs, (char *) data)))
        return 1;

    return 0;
}

static int
filter_match_not_dstaddr(apr_pool_t * pool, filter_rule_t * rule, void *data,
                        void *usrdata)
{
    if (!rule->dst_addrs)
        return 1;

    if ((try_search_best(pool, rule->dst_addrs, (char *) data)))
        return 0;

    return 1;
}

static int
filter_match_not_srcaddr(apr_pool_t * pool, filter_rule_t * rule, void *data,
                        void *usrdata)
{
    if (!rule->src_addrs)
        return 1;

    if ((try_search_best(pool, rule->src_addrs, (char *) data)))
        return 0;

    return 1;
}

static int
filter_match_dstaddr(apr_pool_t * pool, filter_rule_t * rule, void *data,
                    void *usrdata)
{
    if (!rule->dst_addrs)
        return 1;

    if ((try_search_best(pool, rule->dst_addrs, (char *) data)))
        return 1;

    return 0;
}

static int
filter_match_string(apr_pool_t * pool,
                   filter_rule_t * rule, void *val, void *key)
{
    apr_hash_t     *string_hash;

    if (!rule->strings)
        return 1;

    if (!key || !val) {
        return 0;
    }

    if (!(string_hash = apr_hash_get
          (rule->strings, (char *) key, APR_HASH_KEY_STRING)))
        return 0;


    if (apr_hash_get(string_hash, (char *) val, APR_HASH_KEY_STRING))
        return 1;

    /*
     * if we got to here and regex strings are found,
     * loop through each one and determine if one matches
     */
    if (rule->strings_have_regex) {
        /*
         * first grab the array of regex that we would like to match
         * against 
         */
        apr_array_header_t *regex_array;
        int             i;

        regex_array = (apr_array_header_t *)
            apr_hash_get(string_hash, REGEX_KEY, APR_HASH_KEY_STRING);

        if (!regex_array)
            /*
             * this is an odd condition, we should never actually get here 
             */
            return 0;

        for (i = 0; i < regex_array->nelts; i++) {
            regex_t        *tomatch = ((regex_t **) regex_array->elts)[i];

            if (regexec(tomatch, val, 0, NULL, 0) == 0)
                return 1;

        }
    }

    return 0;
}

static int 
filter_match_not_string(apr_pool_t *pool,
        filter_rule_t *rule, void *val, void *key)
{
    apr_hash_t *string_hash;

    if (!rule->strings)
        /* there are no strings defined, this is a match */
    {
	PRINT_DEBUG("No strings loaded in rule\n");
        return 1;
    }

    if (!key || !val)
    {
	PRINT_DEBUG("No key/val %p %p\n", key, val);
        return 0;
    }

    string_hash = apr_hash_get(rule->strings, (char *)key, 
            APR_HASH_KEY_STRING);

    if (!string_hash)
	/* the hash for the key was not found, this means
	   the thing doesn't even exist in our rule, so return a 
	   non-match */
    {
	PRINT_DEBUG("%s was not found as a likely candidate in the hash\n",
		(char *)key); 

        return 0;
    }

    if (apr_hash_get(string_hash, (char *)val, APR_HASH_KEY_STRING))
	/* this value was found within our hash, so in this case
	   we want to return a non match */
    {
	PRINT_DEBUG("%s was found\n", (char *)val);
	return 0;
    }

    if (rule->strings_have_regex)
    {
	apr_array_header_t *regex_array;
	int i;

	regex_array = (apr_array_header_t *)
	    apr_hash_get(string_hash, REGEX_KEY, APR_HASH_KEY_STRING);

	if (!regex_array)
	    return 0;

	for (i = 0; i < regex_array->nelts; i++)
	{
	    /* if any of these matched, return a non found. */
	    regex_t *tomatch = ((regex_t **)regex_array->elts)[i];

	    PRINT_DEBUG("Comparing value %s to %p\n", (char *)val, tomatch);

	    if (regexec(tomatch, val, 0, NULL, 0) == 0)
		return 0;
	}
    }

    return 1;
}

#define APPEND_FLOW(cflow, ctail, new) \
    do { \
        if(!cflow) cflow = ctail = new; \
        else { \
            new->this_operator = ctail->next_operator; \
            ctail->next = new; \
            ctail = new; \
        } \
    } while(0);

static rule_flow_t *
filter_flow_from_str(apr_pool_t * pool, char *flowstr)
{
    char          **tokens;
    char           *tok;
    int             i = 0;
    rule_flow_t    *tail = NULL;
    rule_flow_t    *flow = NULL;

    PRINT_DEBUG("Starting the flow parser\n");

    tokens = filter_tokenize_str(flowstr, " ", NULL);

    PRINT_DEBUG("Token array at %p\n", tokens);

    while ((tok = tokens[i++]) != NULL) {
        rule_flow_t    *new_flow;

        PRINT_DEBUG("Setting up flow for token %s\n", tok);

        switch (rule_token_to_int(tok)) {
        case RULE_MATCH_SRCADDR:
            PRINT_DEBUG("Found a RULE_MATCH_SRCADDR\n");

            new_flow = filter_rule_flow_init(pool);
            new_flow->callback = filter_match_srcaddr;
            new_flow->type = RULE_MATCH_SRCADDR;

            APPEND_FLOW(flow, tail, new_flow);

            break;
        case RULE_MATCH_DSTADDR:
            PRINT_DEBUG("Found a RULE_MATCH_DSTADDR\n");

            new_flow = filter_rule_flow_init(pool);
            new_flow->callback = filter_match_dstaddr;
            new_flow->type = RULE_MATCH_DSTADDR;

            APPEND_FLOW(flow, tail, new_flow);

            break;
        case RULE_MATCH_STRING:
            /*
             * in order to have a proper string matching along with the
             * proper precedence and ordering we must set a flow where the 
             * value is the section of strings to match. 
             */

            PRINT_DEBUG("Found a RULE_MATCH_STRING\n");
            /*
             * remove the match_string( and the ending ) 
             */
            tok[strlen(tok) - 1] = 0;
            tok = &tok[13];

            new_flow = filter_rule_flow_init(pool);
            new_flow->callback = filter_match_string;
            new_flow->type = RULE_MATCH_STRING;
            new_flow->user_data = (void *) apr_pstrdup(pool, tok);

            APPEND_FLOW(flow, tail, new_flow);

            break;
	case RULE_MATCH_NOT_STRING:
	    PRINT_DEBUG("Found a RULE_MATCH_NOT_STRING\n");
	    tok[strlen(tok) - 1] = 0;
	    tok = &tok[14];

	    PRINT_DEBUG("Token is %s\n", tok);
	    new_flow = filter_rule_flow_init(pool);
	    new_flow->callback = filter_match_not_string;
	    new_flow->type = RULE_MATCH_NOT_STRING;
	    new_flow->user_data = (void *) apr_pstrdup(pool, tok);
	    APPEND_FLOW(flow, tail, new_flow);
	    break;
        case RULE_MATCH_NOT_SRCADDR:
            PRINT_DEBUG("Foudn a RULE_MATCH_NOT_SRCADDR\n");
            new_flow = filter_rule_flow_init(pool);
            new_flow->callback = filter_match_not_srcaddr;
            new_flow->type = RULE_MATCH_NOT_SRCADDR;

            APPEND_FLOW(flow, tail, new_flow);
            break;
        case RULE_MATCH_NOT_DSTADDR:
            PRINT_DEBUG("Found a RULE_MATCH_NOT_DSTADDR\n");
            new_flow = filter_rule_flow_init(pool);
            new_flow->callback = filter_match_not_dstaddr;
            new_flow->type = RULE_MATCH_NOT_DSTADDR;

            APPEND_FLOW(flow, tail, new_flow);
            break;
        case RULE_MATCH_OPERATOR_OR:
            PRINT_DEBUG("Found a RULE_MATCH_OPERATOR_OR\n");
            if (!flow)
                /*
                 * we can't have an operator with no starting flow! 
                 */
                return NULL;

            PRINT_DEBUG("Setting the last flows next_operator to OR\n");
            tail->next_operator = RULE_MATCH_OPERATOR_OR;
            break;
        case RULE_MATCH_OPERATOR_AND:
            PRINT_DEBUG("Found a RULE_MATCH_OPERATOR_AND\n");

            if (!flow)
                return NULL;

            PRINT_DEBUG("Setting the last flows next_operator to AND\n");
            tail->next_operator = RULE_MATCH_OPERATOR_AND;
            break;
        }
    }
    free_tokens(tokens);
    return flow;
}

static int
filter_rule_add_flow(filter_rule_t * rule, char *data)
{
    rule->flow = filter_flow_from_str(rule->pool, data);
    return 0;
}

filter_t *
filter_init(apr_pool_t * parent)
{
    filter_t *ret;
    ret = apr_pcalloc(parent, sizeof(filter_t));
    apr_pool_create(&ret->pool, parent);


    return ret;
}

static filter_rule_t *
filter_rule_init(apr_pool_t * parent)
{
    filter_rule_t   *rule;

    rule = (filter_rule_t *)
        apr_pcalloc(parent, sizeof(filter_rule_t));

    PRINT_DEBUG("Initialized new rule at %p\n", rule);

    apr_pool_create(&rule->pool, parent);;

    PRINT_DEBUG("Created new pool %p\n", rule->pool);


    return rule;
}

filter_rule_t
    * filter_get_rule(filter_t * filter, const char *rule_name)
{
    filter_rule_t   *ruleptr;

    if (!filter || !rule_name)
        return NULL;

    ruleptr = filter->head;

    while (ruleptr != NULL) {
        if (strcmp(ruleptr->name, rule_name) == 0)
            break;

        ruleptr = ruleptr->next;
    }

    return ruleptr;
}


static int
filter_add_rule(filter_t * filter, filter_rule_t * rule)
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
filter_rule_set_action(filter_rule_t * rule, const char *actionstr)
{
    int             action;

    if (!strcmp(actionstr, "permit"))
        action = FILTER_PERMIT;
    else if (!strcmp(actionstr, "deny"))
        action = FILTER_DENY;
    else if (!strcmp(actionstr, "thrash"))
	action = FILTER_THRASH;
    else if (!strcmp(actionstr, "thrash_profile"))
	action = FILTER_THRASH_PROFILE;
    else if (!strcmp(actionstr, "pass"))
	action = FILTER_PASS;
    else 
        /*
         * application controlled action 
         */
        action = atoi(actionstr);

    rule->action = action;

    return 0;
}


int
filter_rule_add_network(filter_rule_t * rule,
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
filter_rule_add_string(filter_rule_t * rule, char *key, char *val,
                      const int is_regex)
{
    /*
     * a string match set is a hash of hashes. The "key" in this case is
     * a hash key of our rule->strings hash. The values of that hash will
     * be our value passed to this function. 
     */

    /*
     * ok, string matching rules are a bit odd here. I haven't really
     * thought of a more dynamic way to do this that fits in with the
     * current architecture. With string matching we can have multiple
     * "keys" or string groups. In order to facilitate these groups
     * within our rule we have a hash of hashes that can be found under
     * rule->strings. For every "group" found within the config, the
     * group name is used as a key to another hash which holds all of the
     * values. Since our string matching is static strings we hash the
     * string values with a value of 1 Now to how strings work with our
     * rule flow. In normal situations we have a set of flow callbacks,
     * these callbacks are run after running a user set callback that
     * fetches the correct data for the flow in question. 
     */
    apr_hash_t     *subnode;
    char           *ckey;
    char           *cval;

    ckey = (char *) apr_pstrdup(rule->pool, key);
    cval = (char *) apr_pstrdup(rule->pool, val);


    if (!rule->strings)
        rule->strings = apr_hash_make(rule->pool);

    if (!(subnode = apr_hash_get(rule->strings,
                                 (char *) ckey, APR_HASH_KEY_STRING))) {
        subnode = apr_hash_make(rule->pool);
        apr_hash_set(rule->strings, ckey, APR_HASH_KEY_STRING, subnode);

    }

    if (!is_regex) {
        apr_hash_set(subnode, cval, APR_HASH_KEY_STRING, (void *) 1);
    } else {
        /*
         * if a _R_E_G_E_X_ key is not set within our hash we create it
         * using the above string as the key. The value of the key will
         * be an apr_array_header_t (apr array). This array will
         * contain a set of regex values that the input string can be
         * compared against. 
         */
        apr_array_header_t *regex_array;
        regex_t        *pattern;
        int             regcomp_ret;

        if (!(regex_array = apr_hash_get(subnode, REGEX_KEY,
                                         APR_HASH_KEY_STRING))) {
            /*
             * initialize our array to a size of 1 
             */
            regex_array = apr_array_make(rule->pool, 1, sizeof(regex_t *));

            /*
             * insert our array into the subnode hash 
             */
            apr_hash_set(subnode, REGEX_KEY,
                         APR_HASH_KEY_STRING, regex_array);
        }

        pattern = apr_palloc(rule->pool, sizeof(regex_t));
        regcomp_ret = regcomp(pattern, cval, REG_EXTENDED);

        if (regcomp_ret != 0)
            return -1;

        /*
         * since the regcomp will allocate other things within the regex_t 
         * structure, we need to tell our pool cleanup mechanism to call
         * regfree() before killing the pool 
         */
        apr_pool_cleanup_register(rule->pool, pattern, (void *) regfree,
                                  apr_pool_cleanup_null);

        *(regex_t **) apr_array_push(regex_array) = pattern;

        /*
         * notify our string matcher that there are regex matches to
         * process 
         */
        rule->strings_have_regex = 1;
    }

    PRINT_DEBUG("Inserted string match: %s:%10s (regex?%s)\n",
                ckey, cval, is_regex ? "yes" : "no");
    return 0;

}

static int
filter_match_rulen(apr_pool_t * pool, filter_t * filter,
                  filter_rule_t * rule, const void *usrdata)
{
    int             matched_rule = 0;
    rule_flow_t    *flows = rule->flow;

    PRINT_DEBUG("Checking out rule %s\n", rule->name);

    while (flows != NULL) {
        void           *data,
                       *extra;
        extra = NULL;

        switch (flows->type) {
        case RULE_MATCH_NOT_SRCADDR:
        case RULE_MATCH_SRCADDR:
            PRINT_DEBUG("Processing flow SRCADDD\n");
            if (!filter->callbacks.src_addr_cb) {
                PRINT_DEBUG("No SRCADDR Callback defined\n");
                flows = flows->next;
                continue;
            }
            data = filter->callbacks.src_addr_cb(pool, NULL, usrdata);
            break;
        case RULE_MATCH_NOT_DSTADDR:
        case RULE_MATCH_DSTADDR:
            PRINT_DEBUG("Processing flow DSTADDR\n");
            if (!filter->callbacks.dst_addr_cb) {
                PRINT_DEBUG("No DSTADDR callback defined\n");
                flows = flows->next;
                continue;
            }
            data = filter->callbacks.dst_addr_cb(pool, NULL, usrdata);
            break;
	case RULE_MATCH_NOT_STRING:
        case RULE_MATCH_STRING:
            /*
             * first we must find the callback associated with this
             * string key 
             */
            {
                PRINT_DEBUG("Processing flow STRING\n");
                void           *(*cb) (apr_pool_t * pool, void *fc_data,
                                       const void *usrdata);

                if (!filter->callbacks.string_callbacks ||
                    !(cb = apr_hash_get(filter->callbacks.string_callbacks,
                                        flows->user_data,
                                        APR_HASH_KEY_STRING))) {
                    PRINT_DEBUG("No string callback defined\n");
                    flows = flows->next;
                    continue;
                }
                data = cb(pool, flows->user_data, usrdata);
                extra = flows->user_data;
            }
            break;
        }

        if (flows->callback(pool, rule, data, extra) == 1) {
            /*
             * We matched something in this callback. 
             */
            PRINT_DEBUG("Flow matched!\n");
            if (flows->next_operator == RULE_MATCH_OPERATOR_OR) {
                PRINT_DEBUG
                    ("Next operator is an OR, flow processing complete\n");
                matched_rule = 1;
                break;
            }

            if (flows->next_operator == RULE_MATCH_OPERATOR_AND) {
                PRINT_DEBUG
                    ("Next operator is an AND, continue flow processing\n");
                flows = flows->next;
                continue;
            }

            if (flows->next_operator == 0) {
                PRINT_DEBUG("Reached end of flow processing\n");
                matched_rule = 1;
                break;
            }
        }

        matched_rule = 0;

        PRINT_DEBUG("FLOW did NOT match!\n");

        /*
         * we didn't match this, we need to find the next OR flow 
         */
        rule_flow_t    *find_or_flow = flows;

        while (find_or_flow != NULL) {
            if (find_or_flow->next_operator == RULE_MATCH_OPERATOR_OR) {
                /*
                 * found that the next operator is OR, so set the current 
                 * flow to this, we let the final flows = flows->next
                 * handle the transition 
                 */
                flows = find_or_flow;
                break;
            }
            find_or_flow = find_or_flow->next;
        }

        if (!find_or_flow)
            break;

        flows = flows->next;
    }

    return matched_rule;
}

filter_rule_t   *
filter_traverse_filter(filter_t * filter, filter_rule_t *start_rule, 
	const void *usrdata)
{
    filter_rule_t   *rule;
    apr_pool_t     *subpool;

    if (!filter)
        return NULL;

    if (start_rule)
	rule = start_rule;
    else
	rule = filter->head;

    apr_pool_create(&subpool, NULL);

    while (rule != NULL) {
        if (filter_match_rulen(subpool, filter, rule, usrdata) == 1)
            break;

        apr_pool_clear(subpool);
        rule = rule->next;
    }

    apr_pool_destroy(subpool);
    return rule;
}

int
filter_register_user_cb(filter_t * filter,
                       void *(*cb) (apr_pool_t * p, void *fc_data,
                                    const void *d), int type, void *data)
{
    /*
     * If a callback isn't registered for a specific
     * datatype, the rule will not even attempt to match
     * that flow.
     */
    switch (type) {
    case RULE_MATCH_SRCADDR:
        filter->callbacks.src_addr_cb = cb;
        break;
    case RULE_MATCH_DSTADDR:
        filter->callbacks.dst_addr_cb = cb;
        break;
    case RULE_MATCH_STRING:
        if (!filter->callbacks.string_callbacks)
            filter->callbacks.string_callbacks
                = apr_hash_make(filter->pool);

        apr_hash_set(filter->callbacks.string_callbacks,
                     (char *) apr_pstrdup(filter->pool, data),
                     APR_HASH_KEY_STRING, (void *) cb);
        break;

    }
    return 0;
}

static filter_rule_t *
parse_whitelist(filter_t * filter, const char *filename)
{
    FILE           *wlf;
    filter_rule_t   *filter_rule;
    char           *buf;
    char           *bptr;

    if (!filename)
        return NULL;

    wlf = fopen(filename, "r");

    if (!wlf)
        return NULL;

    if (!(filter_rule = filter_rule_init(filter->pool)))
        return NULL;

    filter_rule->name = apr_pstrdup(filter->pool, "__whitelist__");

    filter_rule_add_flow(filter_rule, "match_src_addrs");

    filter_rule_set_action(filter_rule, "permit");

    buf = malloc(1024);

    while ((bptr = fgets(buf, 1023, wlf))) {
	
	buf = filter_trim_str(buf);

        if (!buf || *buf == '\0' || *buf == '#')
            continue;

        if (filter_rule_add_network(filter_rule, buf,
                                   RULE_MATCH_SRCADDR, NULL) == -1) {
            free(buf);
            fclose(wlf);
            return NULL;
        }

    }

    free(buf);
    fclose(wlf);

    return filter_rule;
}

filter_t *
filter_parse_config(apr_pool_t * pool, const char *filename)
{
    cfg_t          *cfg;
    filter_t *filter;
    char           *whitelist_file;
    unsigned int    n,
                    i;

    filter = NULL;

    PRINT_DEBUG("Parsing configuration.\n");
    cfg_opt_t       str_match_opts[] = {
        CFG_STR_LIST("values", 0, CFGF_MULTI),
        CFG_STR_LIST("regex", 0, CFGF_MULTI),
        CFG_END()
    };

    cfg_opt_t       rule_opts[] = {
        CFG_STR("flow",
                "match_src_addr && match_dst_addr || match_http_header",
                CFGF_NONE),
        CFG_BOOL("enabled", cfg_true, CFGF_NONE),
        CFG_BOOL("log", cfg_true, CFGF_NONE),
	CFG_BOOL("pass", cfg_false, CFGF_NONE),
        CFG_STR_LIST("src_addrs", 0, CFGF_MULTI),
        CFG_STR_LIST("dst_addrs", 0, CFGF_MULTI),
        CFG_SEC("match_string", str_match_opts, CFGF_MULTI | CFGF_TITLE),
        CFG_STR("action", "deny", CFGF_NONE),
	CFG_STR("update-rule", NULL, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t       opts[] = {
        CFG_STR("whitelist-file", NULL, CFGF_NONE),
        CFG_BOOL("whitelist-log", cfg_true, CFGF_NONE),
        CFG_SEC("rule", rule_opts, CFGF_MULTI | CFGF_TITLE),
        CFG_END()
    };

    cfg = cfg_init(opts, CFGF_NOCASE);

    if (cfg_parse(cfg, filename) == CFG_PARSE_ERROR) {
        cfg_free(cfg);
        return NULL;
    }

    filter = filter_init(pool);
    whitelist_file = cfg_getstr(cfg, "whitelist-file");

    /*
     * first setup a rule for our whitelist if needed 
     */
    if (whitelist_file) {
        filter_rule_t   *whitelist_rule;
        whitelist_rule = parse_whitelist(filter, whitelist_file);
        if (whitelist_rule) {
            filter_add_rule(filter, whitelist_rule);

            if (cfg_getbool(cfg, "whitelist-log"))
                whitelist_rule->log = 1;
            else
                whitelist_rule->log = 0;
        } else {
            cfg_error(cfg, "Unable to parse whitelist: %s",
                      whitelist_file);
            cfg_free(cfg);
            return NULL;
        }
    }

    n = cfg_size(cfg, "rule");
    PRINT_DEBUG("Found %d rules in configuration\n", n);

    /*
     * it gets ugly right around...(to be continued) 
     */
    for (i = 0; i < n; i++) {
        /*
         * re: ugly [ HERE!! ] 
         */
        char           *flow;
	char           *update_rule;
        int             addr_cnt;
        filter_rule_t   *filter_rule;
        char           *action;
        cfg_t          *rule;

        PRINT_DEBUG("Parsing rule %d\n", i);

        rule        = cfg_getnsec(cfg, "rule", i);
        flow        = cfg_getstr(rule, "flow");
	update_rule = cfg_getstr(rule, "update-rule");

        filter_rule = filter_rule_init(filter->pool);
        filter_rule->name = apr_pstrdup(filter_rule->pool, cfg_title(rule));
        filter_rule->log = cfg_getbool(rule, "log");

        PRINT_DEBUG("Rule name: %s\n", filter_rule->name);
        PRINT_DEBUG("Found flow '%s'\n", flow);

        filter_rule_add_flow(filter_rule,
                            (char *) apr_pstrdup(filter_rule->pool, flow));

        if ((action = cfg_getstr(rule, "action")))
            filter_rule_set_action(filter_rule, action);

        PRINT_DEBUG("%d src_addrs defined\n", cfg_size(rule, "src_addrs"));

        for (addr_cnt = 0; addr_cnt < cfg_size(rule, "src_addrs");
             addr_cnt++) {
            char           *addr =
                cfg_getnstr(rule, "src_addrs", addr_cnt);

            PRINT_DEBUG("Adding %s to our src_addr radix tree\n", addr);
            filter_rule_add_network(filter_rule, addr, RULE_MATCH_SRCADDR,
                                   NULL);
        }

        PRINT_DEBUG("%d dst_addrs defined\n", cfg_size(rule, "dst_addrs"));

        for (addr_cnt = 0; addr_cnt < cfg_size(rule, "dst_addrs");
             addr_cnt++) {
            char           *addr =
                cfg_getnstr(rule, "dst_addrs", addr_cnt);
            PRINT_DEBUG("Adding %s to our dst_addr radix tree\n", addr);
            filter_rule_add_network(filter_rule, addr, RULE_MATCH_DSTADDR,
                                   NULL);
        }

        int             str_match_size = cfg_size(rule, "match_string");
        int             sm_n;

        PRINT_DEBUG("%d string matching groups defined\n", str_match_size);

        for (sm_n = 0; sm_n < str_match_size; sm_n++) {
            cfg_t          *matcher;
            int             value_cnt;

            matcher = cfg_getnsec(rule, "match_string", sm_n);

            for (value_cnt = 0; value_cnt < cfg_size(matcher, "values");
                 value_cnt++) {
                char           *str =
                    cfg_getnstr(matcher, "values", value_cnt);

                filter_rule_add_string(filter_rule,
                                      (char *) cfg_title(matcher), str, 0);
            }

            for (value_cnt = 0; value_cnt < cfg_size(matcher, "regex");
                 value_cnt++) {
                char           *str =
                    cfg_getnstr(matcher, "regex", value_cnt);

                filter_rule_add_string(filter_rule,
                                      (char *) cfg_title(matcher), str, 1);
            }

        }

	if (update_rule)
	{
	    filter_rule_t *ud_rule;

	    ud_rule = filter_get_rule(filter, update_rule);

	    if (ud_rule)
		filter_rule->update_rule = ud_rule;
	}

        filter_add_rule(filter, filter_rule);
    }

    cfg_free(cfg);

    return filter;
}


#ifdef TEST_FILTERCLOUD
void           *
src_addr_cb(apr_pool_t * pool, void *fc_data, const void *d)
{
    char          **argv = (char **) d;
    PRINT_DEBUG("test callback\n");
    return argv[1];
}

void           *
dst_addr_cb(apr_pool_t * pool, void *fc_data, const void *d)
{
    char          **argv = (char **) d;

    return argv[2];
}

void           *
filter_str_cb(apr_pool_t * pool, void *fc_data, const void *d)
{
    return "abcdef";
}

void           *
filter_str2_cb(apr_pool_t * pool, void *fc_data, const void *d)
{
    return "derr";
}

void           *
filter_str3_cb(apr_pool_t * pool, void *fc_data, const void *d)
{
    PRINT_DEBUG("Test callback\n");
    return "iabfjdla";
}


int
main(int argc, char **argv)
{
    filter_t        *filter;
    filter_rule_t   *rule;

    apr_pool_t     *root_pool;
    apr_initialize();
    apr_pool_create(&root_pool, NULL);
    filter = filter_parse_config(root_pool, "./test.conf");
    assert(filter);


    filter_register_user_cb(filter, src_addr_cb, RULE_MATCH_SRCADDR, NULL);
    filter_register_user_cb(filter, dst_addr_cb, RULE_MATCH_DSTADDR, NULL);
    filter_register_user_cb(filter, filter_str_cb, RULE_MATCH_STRING, "stuff");
    filter_register_user_cb(filter, filter_str2_cb, RULE_MATCH_STRING, "lame");
    filter_register_user_cb(filter, filter_str2_cb, RULE_MATCH_STRING, "guh");
    filter_register_user_cb(filter, filter_str3_cb, RULE_MATCH_STRING, "chadorder");

    rule = filter_traverse_filter(filter, (void *) argv);

    printf("Matched filter? %s\n", rule ? "yes" : "no");

    apr_pool_destroy(root_pool);
    apr_terminate();
    return 0;
}
#endif
