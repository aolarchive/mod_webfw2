#include "patricia.h"
typedef struct cloud_rule cloud_rule_t;
typedef struct rule_flow rule_flow_t;
typedef struct cloud_callbacks cloud_callbacks_t;

#define FILTER_DENY 0
#define FILTER_PERMIT 1

struct rule_flow {
    int             type;
    int             (*callback) (apr_pool_t * pool,
                                 cloud_rule_t * rule, 
																 void *data, void *usrdata);
		void            *user_data;

    int             this_operator;
    int             next_operator;
    struct rule_flow *next;
};

struct cloud_callbacks {
  void *(*src_addr_cb)  (apr_pool_t *pool, void *fc_data, const void *usrdata);
  void *(*dst_addr_cb)  (apr_pool_t *pool, void *fc_data, const void *usrdata);
  void *(*chad_ord_cb)  (apr_pool_t *pool, void *fc_data, const void *usrdata);
  /* when you register a callback for a RULE_MATCH_STRING you define 
   * a key in which your callback will be stored. The value will be
   * the callback in the parent application */
  apr_hash_t *string_callbacks;
};

struct cloud_rule {
		char            *name;
		int              action;
		char             dynamic;
    patricia_tree_t *src_addrs;
    patricia_tree_t *dst_addrs;
		apr_hash_t      *strings;
    uint8_t          strings_have_regex;
    rule_flow_t    *flow;
    apr_pool_t     *pool;
    struct cloud_rule *next;
};

typedef struct cloud_filter {
    cloud_rule_t      *head;
    cloud_rule_t      *tail;
    apr_pool_t        *pool;
    struct cloud_callbacks  callbacks; 
    uint32_t        rule_count;
} cloud_filter_t;

enum {
    RULE_MATCH_SRCADDR = 1,
    RULE_MATCH_DSTADDR,
    RULE_MATCH_CHAD_ORD,
		RULE_MATCH_STRING,
    RULE_MATCH_OPERATOR_OR,
    RULE_MATCH_OPERATOR_AND,
		RULE_MATCH_NOT_SRCADDR,
		RULE_MATCH_NOT_DSTADDR,
		RULE_MATCH_NOT_STRING
};

rule_flow_t *cloud_rule_flow_init(apr_pool_t *);
cloud_filter_t *cloud_filter_init(apr_pool_t *);
int cloud_match_rule(apr_pool_t *, cloud_rule_t *, const char *, 
    const char *, const void *);
cloud_rule_t *cloud_traverse_filter(cloud_filter_t *, const void *);
cloud_filter_t *cloud_parse_config(apr_pool_t *, const char *);
char **cloud_tokenize_str(char *, const char *);
void free_tokens(char **);
int cloud_register_user_cb(cloud_filter_t *, void *(*cb)(apr_pool_t *, void *, const void *), int, void *);
cloud_rule_t *cloud_filter_get_rule(cloud_filter_t *filter, const char *rule_name);
int cloud_rule_add_network(cloud_rule_t *, const char *, const int, void *);
