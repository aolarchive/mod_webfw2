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


static void 
add_networks(apr_pool_t *pool, network_tbl_t *table)
{
    int count = 0;
    char *networks[] = {
	/* 192.168.0.0 - 192.168.0.255 */
	"192.168.0.1/24",
	/* 192.168.1.0 - 192.168.1.127 */
	"192.168.1.0/25",
	/* 192.168.1.130 - 192.168.1.131 */
	"192.168.1.130/31",
	"192.168.2.3/32",
	"192.168.2.5/32",
	"192.168.2.7/32",
	/* 192.168.3.32 - 192.168.3.63 */
	"192.168.3.32/27", NULL };

    while(1)
    {
	network_node_t *node;

	if (networks[count] == NULL)
	    break;

	node = network_add_node_from_str(pool, 
		table, networks[count]);


	printf("add_network():\n"
	       "addr      = %s\n" 
	       "nodeptr   = %p\n"  
	       "key       = %u\n"
               "iaddr     = %u\n"
	       "mask      = %lX\n"  
	       "broadcast = %u\n"
               "bitlen    = %d\n\n",
	       networks[count], node, node->key,
	       node->addr->addr, node->addr->mask,
	       node->addr->broadcast, node->addr->bitlen);

	count++;
    }

}

static void
print_hash(network_tbl_t *tbl)
{
    int i;

    printf("hash table:\n");
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
                printf("\tbucket=%d ptr=%p addr=%u bitlen=%u\n", 
			x, node, node->addr->addr, 
			node->addr->bitlen);
                node = node->next;
            }
        }
    }
    printf("\n");
}

static void 
print_node(network_node_t *node)
{
    uint32_t addr;
    uint32_t a, b;

    if (node == NULL)
	printf("  NULL");

    addr = htonl(node->addr->addr);

    printf("  ptr:     %p\n", node);
    printf("  network: %s/%d\n", 
	    inet_ntoa(*(struct in_addr *)&addr),
	    node->addr->bitlen);

    a = htonl(node->addr->addr);
    b = htonl(node->addr->broadcast);

    printf("  %s-", inet_ntoa(*(struct in_addr *)&a));
    printf("%s\n",  inet_ntoa(*(struct in_addr *)&b));
}

static void
test(apr_pool_t *pool, network_tbl_t *table)
{
    char *should_match[] = {
	/* should match 192.168.0.0/24 */
	"192.168.0.5/32",
	"192.168.0.75/32",
	"192.168.0.30/31",
	"192.168.0.0/24",
	/* should match 192.168.1.0/25 */
	"192.168.1.10/32",
	"192.168.1.16/30",
	"192.168.1.0/25",
	/* should match 192.168.1.130/31 */
	"192.168.1.130/32",
	"192.168.1.131/32",
	"192.168.1.130/31",
	/* these 32's should match */
	"192.168.2.3/32",
	"192.168.2.5/32",
	"192.168.2.7/32",
	/* should match 192.168.3.32/27 */
	"192.168.3.32/32",
	"192.168.3.34/30",
	"192.168.3.32/27", NULL};

    char *shouldnt_match[] = {
	/* check against 192.168.1.0/25 */
	"192.168.1.128/32",
	/* check against 192.168.3.32/27 */
	"192.168.3.30/31", 
	/* random checks */
	"0.0.0.0/0",
	"5.5.5.0/24",
	"9.9.9.0/23", NULL};

    int count = 0;

    printf(">>>> Checking things that SHOULD match\n");

    while(1)
    {
	network_node_t *matched;

	if (should_match[count] == NULL)
	    break;

	printf("Checking addr %s\n", should_match[count]);

	matched = network_search_tbl_from_str(pool, 
		table, should_match[count]);

	if (matched == NULL) {
	    printf("  !!! %s should have matched something!!\n",
		    should_match[count]);
	} else {
	    printf("  node matched!\n");
	    print_node(matched);
	}
	count++;
    }
	
    printf("\n");

    printf(">>>> Checking things that SHOULDN'T match\n");
    count = 0;

    while(1)
    {
	network_node_t *matched;

	if (shouldnt_match[count] == NULL)
	    break;

	printf("Checking addr %s\n", shouldnt_match[count]);

	matched = network_search_tbl_from_str(pool,
		table, shouldnt_match[count]);

	if (matched != NULL)
	{
	    network_node_t *derr;

	    derr = network_node_str_init(pool, shouldnt_match[count]);
	    
	    printf("  !!! %s should NOT have matched anything!!\n",
		    shouldnt_match[count]);
	    printf("\n");
	    printf("  THIS NODE\n");
	    print_node(derr);
	    printf("\n");
	    printf("  MATCHED THIS NODE\n");
	    print_node(matched);
	    printf("\n");
	} else {
	    printf("  %s wasn't found, GOOD!\n",
		    shouldnt_match[count]);
	}

	count++;
    }

    printf("\n");
}




int 
main(int argc, char **argv)
{
    apr_pool_t *pool;
    network_tbl_t *table;


    apr_initialize();
    apr_pool_create(&pool, NULL);

    table = network_tbl_init(pool, 8);

    add_networks(pool, table);
    print_hash(table);

    test(pool, table);

    return 0;
}

