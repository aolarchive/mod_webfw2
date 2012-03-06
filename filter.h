#include <unistd.h>
#include "apr.h"
#include "apr_hash.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_network_io.h"
#include "patricia.h"
#include "httpd/httpd.h"
#include "httpd/http_log.h"

typedef struct filter_rule filter_rule_t;
typedef struct rule_flow rule_flow_t;
typedef struct filter_callbacks filter_callbacks_t;

#define FILTER_DENY                 1
#define FILTER_PERMIT               2
#define FILTER_PASS                 3
#define FILTER_REDIRECT             4
#define FILTER_THRASH            1972
#define FILTER_THRASH_v1         1972
#define FILTER_THRASH_PROFILE    1973
#define FILTER_THRASH_PROFILE_v1 1973
#define FILTER_THRASH_v2         1974
#define FILTER_THRASH_PROFILE_v2 1975
#define FILTER_THRASH_v3         1976
#define FILTER_THRASH_PROFILE_v3 1977
#define FILTER_THRASH_v4         1978
#define FILTER_THRASH_PROFILE_v4 1979

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) \
    printf("[%s] %-25s: \033[31m"format"\033[0m", \
            __FILE__, __PRETTY_FUNCTION__, ##args);
#else
#ifdef APDEBUG
#define PRINT_DEBUG(format, args...) \
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, format, ##args)
#else
#define PRINT_DEBUG(format, args...)
#endif
#endif

struct rule_flow {
    int             type;
    int             (*callback) (apr_pool_t * pool,
                                 filter_rule_t * rule, 
                                 void *data, void *usrdata);
    void            *user_data;

    int             this_operator;
    int             next_operator;
    struct rule_flow *next;
};

struct filter_callbacks {
  void *(*src_addr_cb)  (apr_pool_t *pool, void *fc_data, const void *usrdata);
  void *(*dst_addr_cb)  (apr_pool_t *pool, void *fc_data, const void *usrdata);
  /* when you register a callback for a RULE_MATCH_STRING you define 
   * a key in which your callback will be stored. The value will be
   * the callback in the parent application */
  apr_hash_t *string_callbacks;
};

struct filter_rule {
    char            *name;
    int              action;
    int              status_code;
    uint8_t          log;
    patricia_tree_t *src_addrs;
    patricia_tree_t *dst_addrs;
    apr_hash_t      *strings;
    uint8_t          strings_have_regex;
    rule_flow_t    *flow;
    apr_pool_t     *pool;
    char           *redirect_url;
    struct filter_rule *next;
    struct filter_rule *update_rule;
};

typedef struct filter {
    filter_rule_t      *head;
    filter_rule_t      *tail;
    apr_pool_t        *pool;
    struct filter_callbacks  callbacks; 
    uint32_t        rule_count;
} filter_t;

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

rule_flow_t *filter_rule_flow_init(apr_pool_t *);
filter_t *filter_init(apr_pool_t *);
int filter_match_rule(apr_pool_t *, filter_rule_t *, const char *, 
    const char *, const void *);
filter_rule_t *filter_traverse_filter(filter_t *, filter_rule_t *, const void *);
filter_t *filter_parse_config(apr_pool_t *, const char *, int);
char **filter_tokenize_str(char *, const char *, int *nelts);
void free_tokens(char **);
int filter_register_user_cb(filter_t *, 
  void *(*cb)(apr_pool_t *, void *, const void *), int, void *);
filter_rule_t *filter_get_rule(filter_t *filter, const char *rule_name);
int filter_rule_add_network(filter_rule_t *, const char *, const int, void *);
int filter_validate_ip(char *);
