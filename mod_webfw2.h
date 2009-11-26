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
#include "apr_network_io.h"
#include "filter.h"
#include "version.h"

#define FILTER_CONFIG_KEY "webfw2_filter_config"

typedef struct webfw2_xff_opts {
    char *xff_header;
    unsigned int first; /* only check this num of values in header */
    unsigned int last;  /* only check the last num of values in header */
                        /* if both first and last are undef, check all */
    apr_hash_t *source_ip;    /* optional source address for accepting xff */
} webfw2_xff_opts_t;

typedef struct webfw2_config {
    uint8_t         hook_translate;
    uint8_t         hook_access;
		uint8_t         hook_post_read;
    char           *config_file;
    uint32_t        update_interval;
    char           *thrasher_host;
    int             thrasher_port;
    int             thrasher_timeout;
    int             thrasher_retry;
    int             default_action;
    int             default_taction; /* thrasher */
    apr_table_t    *xff_headers;
    apr_array_header_t *match_env;
    apr_array_header_t *match_note;
    apr_array_header_t *match_file;
    apr_array_header_t *match_header;
} webfw2_config_t;

typedef struct webfw2_filter {
    apr_time_t      last_update;
    apr_time_t      last_modification;
    filter_t *filter;
    apr_pool_t     *pool;
    apr_thread_rwlock_t *rwlock;
    apr_socket_t   *thrasher_sock;
    /*
     * what time did webfw2 deem thrasher was down? 
     */
    uint32_t        thrasher_downed;
} webfw2_filter_t;

