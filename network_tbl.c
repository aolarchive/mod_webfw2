#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "apr.h"
#include "apr_pools.h"
#include "addr.h"
#include "network_tbl.h"

static uint32_t netmask_tbl[] = {
    0x00000000, 0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
    0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000, 0xFF800000,
    0xFFC00000, 0xFFE00000, 0xFFF00000, 0xFFF80000, 0xFFFC0000,
    0xFFFE0000, 0xFFFF0000, 0xFFFF8000, 0xFFFFC000, 0xFFFFE000,
    0xFFFFF000, 0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
    0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
    0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF
};

#define hash_addr(a) a

network_tbl_t *
network_tbl_init(apr_pool_t *pool, uint32_t size)
{
    network_tbl_t *tbl = NULL;

    tbl = apr_pcalloc(pool, sizeof(network_tbl_t));

    if (tbl == NULL) {
        return(NULL);
    }

    if (tbl->net_table == NULL) {
        return(NULL);
    }

    tbl->hash_size = size;
    return(tbl);
}

network_node_t *
network_node_str_init(apr_pool_t *pool, const char *addrstr)
{
    addr_t         *addr;
    network_node_t *node;

    if (!(node = apr_palloc(pool, sizeof(network_node_t)))) {
        return(NULL);
    }

    if (!(addr = addr_from_string(pool, addrstr))) {
        return(NULL);
    }

    node->addr = addr;
    node->next = NULL;

    return(node);
}

int
network_add_node(apr_pool_t *pool,
                 network_tbl_t *tbl,
                 network_node_t *node)
{
    network_node_t *node_slot;
    uint32_t        key_short;
    uint8_t         blen;
    int             i, is_in;

    is_in = 0;

    if (tbl == NULL || node == NULL || pool == NULL) {
        return(-1);
    }

    if (!node->addr->bitlen) {
        /* if this is a /0, we can safely ignore the rest */
        tbl->any = node;
        return(0);
    }

    if (tbl->any) {
        return(0);
    }

    blen = node->addr->bitlen - 1;

    if (tbl->net_table[blen] == NULL) {
        network_node_t **hash_entry;

        hash_entry = apr_palloc(pool,
                                sizeof(network_node_t *) * tbl->hash_size);

        if (hash_entry == NULL) {
            return(-1);
        }

        tbl->net_table[blen] = hash_entry;
    }

    key_short = node->addr->addr & (tbl->hash_size - 1);

    node_slot = tbl->net_table[blen][key_short];

    if (node_slot != NULL) {
        node->next = node_slot;
    }

    tbl->net_table[blen][key_short] = node;

    for (i = 0; i <= 32; i++) {
        if (tbl->in[i] == 0) {
            break;
        }

        if (tbl->in[i] == node->addr->bitlen) {
            is_in = 1;
            break;
        }
    }

    if (!is_in) {
        tbl->in[i] = node->addr->bitlen;
    }

    return(0);
} /* network_add_node */

network_node_t *
network_add_node_from_str(apr_pool_t *pool,
                          network_tbl_t *tbl,
                          const char *addrstr)
{
    network_node_t *node = NULL;

    if (tbl == NULL || addrstr == NULL || pool == NULL) {
        return(NULL);
    }

    if (!(node = network_node_str_init(pool, addrstr))) {
        return(NULL);
    }

    if (network_add_node(pool, tbl, node)) {
        return(NULL);
    }

    return(node);
}

network_node_t *
network_search_node(apr_pool_t *pool,
                    network_tbl_t *tbl,
                    network_node_t *node)
{
    int             bit_iter;
    uint32_t        addr_masked;
    uint32_t        key;
    network_node_t *match;
    int             i = 0;

    if (tbl->any) {
        return(tbl->any);
    }

    while (1) {
        bit_iter = tbl->in[i++];

        if (!bit_iter) {
            break;
        }

        addr_masked = node->addr->addr & netmask_tbl[bit_iter];

        key = addr_masked & (tbl->hash_size - 1);
        match = tbl->net_table[bit_iter - 1][key];

        while (match) {
            if (addr_compare(pool, match->addr, node->addr)) {
                return(match);
            }

            match = match->next;
        }
    }

    return(NULL);
}

network_node_t *
network_search_tbl_from_str(apr_pool_t *pool,
                            network_tbl_t *tbl,
                            const char *addrstr)
{
    network_node_t *node;
    network_node_t *matched;

    if (tbl == NULL || addrstr == NULL || pool == NULL) {
        return(NULL);
    }

    if (!(node = network_node_str_init(pool, addrstr))) {
        return(NULL);
    }

    matched = network_search_node(pool, tbl, node);

    return(matched);
}

network_node_t *
network_search_tbl_from_addr(apr_pool_t *pool,
                             network_tbl_t *tbl, uint32_t addr, uint8_t prefix)
{
    network_node_t *node;
    addr_t         *addrn;

    node = apr_palloc(pool, sizeof(network_node_t));
    addrn = apr_palloc(pool, sizeof(addr_t));
    addrn->addr = addr;
    addrn->mask = netmask_tbl[prefix];
    addrn->bitlen = prefix;
    addrn->broadcast = addr | (0xFFFFFFFF & ~addrn->mask);
    node->addr = addrn;


    network_node_t *match = network_search_node(pool, tbl, node);
    return(match);
}
