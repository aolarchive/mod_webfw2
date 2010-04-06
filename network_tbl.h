#include <stdio.h>                                                                                                      
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "apr.h"
#include "apr_pools.h"

typedef struct network_node {
    uint32_t key;
    addr_t  *addr;
    struct network_node *next;
} network_node_t;

typedef struct network_tbl {
    uint32_t    hash_size;
    network_node_t **net_table[33];
} network_tbl_t;

network_tbl_t *network_tbl_init(apr_pool_t *pool, uint32_t size);
network_node_t *network_node_str_init(apr_pool_t *pool, const char *addrstr);
int network_add_node(apr_pool_t *pool, network_tbl_t *tbl, network_node_t *node);
network_node_t *network_add_node_from_str(apr_pool_t *pool, network_tbl_t *tbl, const char *addrstr);
network_node_t *network_search_node(apr_pool_t *pool, network_tbl_t *tbl, network_node_t *node);
network_node_t *network_search_tbl_from_str(apr_pool_t *pool, network_tbl_t *tbl, const char *addrstr);
