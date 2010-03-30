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
    0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF };

static uint32_t hash_addr(uint32_t a)
{
   a = (a+0x7ed55d16) + (a<<12);
   a = (a^0xc761c23c) ^ (a>>19);
   a = (a+0x165667b1) + (a<<5);
   a = (a+0xd3a2646c) ^ (a<<9);
   a = (a+0xfd7046c5) + (a<<3);
   a = (a^0xb55a4f09) ^ (a>>16);
   return a;
}

network_tbl_t *
network_tbl_init(apr_pool_t *pool, uint32_t size)
{
    network_tbl_t *tbl = NULL;

    tbl = apr_pcalloc(pool, sizeof(network_tbl_t));

    if (tbl == NULL)
	return NULL;

    if (tbl->net_table == NULL)
	return NULL;

    tbl->hash_size = size;
    return tbl;
}

network_node_t *
network_node_str_init(apr_pool_t *pool, const char *addrstr)
{
    addr_t *addr         = NULL;
    network_node_t *node = NULL;

    if (!(node = apr_pcalloc(pool, sizeof(network_node_t))))
	return NULL;

    if (!(addr = addr_from_string(pool, addrstr)))
	return NULL;

    node->addr = addr;
    node->key  = hash_addr(addr->addr);
    node->next = NULL;

    return node;
}

int 
network_add_node(apr_pool_t *pool, 
	network_tbl_t *tbl,
	network_node_t *node)
{
    network_node_t *node_slot = NULL;
    uint32_t        key_short = 0;

    if (tbl == NULL || node == NULL || pool == NULL)
	return -1;

    if (tbl->net_table[node->addr->bitlen] == NULL)
    {
	network_node_t **hash_entry;

	hash_entry = apr_pcalloc(pool,
	       sizeof(network_node_t *) * tbl->hash_size);	

	if (hash_entry == NULL)
	    return -1;

	tbl->net_table[node->addr->bitlen] = hash_entry; 
    }

    key_short = node->key % tbl->hash_size;

    node_slot = tbl->net_table[node->addr->bitlen][key_short];

    if (node_slot != NULL)
	node->next = node_slot;

    tbl->net_table[node->addr->bitlen][key_short] = node;

    return 0;
}

network_node_t *
network_add_node_from_str(apr_pool_t *pool,
       	network_tbl_t *tbl, 
	const char *addrstr)
{
    network_node_t *node = NULL;

    if (tbl == NULL || addrstr == NULL || pool == NULL)
	return NULL;

    if (!(node = network_node_str_init(pool, addrstr)))
	return NULL;

    if (network_add_node(pool, tbl, node))
	return NULL;

    return node;
}

network_node_t *
network_search_node(apr_pool_t *pool,
	network_tbl_t *tbl,
	network_node_t *node)
{
    int bit_iter;

    for(bit_iter = 0; bit_iter <= 32; bit_iter++)
    {
	uint32_t key;
	uint32_t addr_masked;
	network_node_t *match;

	if (tbl->net_table[bit_iter] == NULL)
	    continue;

	addr_masked = node->addr->addr & netmask_tbl[bit_iter];

	key = hash_addr(addr_masked) % tbl->hash_size;
	match = tbl->net_table[bit_iter][key];

	while(match)
	{
	    if (addr_compare(pool, match->addr, node->addr))
		return match;

	    match = match->next;
	}
    }

    return NULL;
}

network_node_t *
network_search_tbl_from_str(apr_pool_t *pool,
	network_tbl_t *tbl,
	const char *addrstr)
{
    network_node_t *node = NULL;
    network_node_t *matched = NULL;

    if (tbl == NULL || addrstr == NULL || pool == NULL)
	return NULL;

    if (!(node = network_node_str_init(pool, addrstr)))
	return NULL;

    matched = network_search_node(pool, tbl, node);

    return matched;
}

#if 0
static void
print_hash(network_tbl_t *tbl)
{
    int i;

    for (i = 0; i <= 32; i++)
    {
	int x;
	network_node_t **head = NULL;

	printf("bitlen: %d\n", i);

	head = tbl->net_table[i];

	if (head == NULL) 
	    continue;

	for (x = 0; x < tbl->hash_size; x++)
	{
	    network_node_t *node;

	    node = head[x];

	    while(node)
	    {
		printf("\tptr=%p addr=%u bitlen=%u\n", node, node->addr->addr, node->addr->bitlen);

		node = node->next;
	    }

	}
    }
}
int main(int argc, char **argv)
{
    apr_pool_t *pool;
    network_tbl_t *table;

    apr_initialize();
    apr_pool_create(&pool, NULL);

    table = network_tbl_init(pool, 10);
    
    network_add_node_from_str(pool, table, "5.5.5.5");
    network_add_node_from_str(pool, table, "5.5.5.6");
    network_add_node_from_str(pool, table, "5.5.5.7");
    network_add_node_from_str(pool, table, "5.5.5.8");
    network_add_node_from_str(pool, table, "5.5.5.9");
    network_add_node_from_str(pool, table, "5.5.5.9");
    network_add_node_from_str(pool, table, "192.168.0.0/24");
    network_add_node_from_str(pool, table, "192.168.1.0/31");
    //network_add_node_from_str(pool, table, "0.0.0.0/0");
    print_hash(table);

    printf("%p\n", network_search_tbl_from_str(pool, table, argv[1]));

    apr_pool_destroy(pool);
    apr_terminate();

    return 0;
}
#endif







