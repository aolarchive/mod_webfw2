#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "apr.h"
#include "apr_pools.h"
#include "addr.h"
#include "network_tbl.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_network_io.h"
#include "patricia.h"

char *networks[] = {
        //"0.0.0.0/0",                                                                                                  
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
        "192.168.3.32/27", 

	NULL };

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
        /* checks against 192.168.0.1/24 */
        "192.168.0.0/23",
        /* check against 192.168.1.0/25 */
        "192.168.1.128/32",
        /* check against 192.168.3.32/27 */
        "192.168.3.30/31", 
        /* random checks */
        "0.0.0.0/0",
        "5.5.5.0/24",
        "192.168.0.0/16",
        "192.168.1.0/24",
        "192.168.3.31/26",
        "9.9.9.0/23", NULL};

static void 
add_patricia_networks(apr_pool_t *pool, patricia_tree_t **rtree)
{
    int count = 0;

    while(1)
    {
	if (networks[count] == NULL)
	    break;

	make_and_lookup(pool, *rtree, networks[count]);
	count++;
    }
}

static void
add_tbl_networks(apr_pool_t *pool, network_tbl_t *table)
{
    int count = 0;

    while(1)
    {
	if (networks[count] == NULL)
	    break;

	network_add_node_from_str(pool, table, 
		networks[count]);

	count++;
    }
}

void
test_tbl_good(apr_pool_t *pool, network_tbl_t *table)
{
    int count = 0;

    while(1)
    {
	network_node_t *m = NULL;

	if (should_match[count] == NULL)
	    break;

	m = network_search_tbl_from_str(pool, 
		table, should_match[count]);

	count++;
    }

}

void
test_tbl_bad(apr_pool_t *pool, network_tbl_t *table)
{
    int count = 0;

    while(1)
    {
	network_node_t *m = NULL;

	if (shouldnt_match[count] == NULL)
	    break;

	m = network_search_tbl_from_str(pool,
		table, shouldnt_match[count]);

	//printf("%d: %p\n", count, m);
	count++;
    }

    //printf("\n");
}


void
test_patricia_good(apr_pool_t *pool, patricia_tree_t *tree)
{
    int count = 0;

    while(1)
    {
	patricia_node_t *m = NULL;

	if (should_match[count] == NULL)
	    break;

	m = try_search_best(pool, tree, should_match[count]);
	count++;
    }
}

void
test_patricia_bad(apr_pool_t *pool, patricia_tree_t *tree)
{
    int count = 0;
    
    while(1)
    {
	patricia_node_t *m = NULL;

	if (shouldnt_match[count] == NULL)
	    break;

	m = try_search_best(pool, tree, shouldnt_match[count]);

	//printf("%d: %p\n", count, m);
	count++;
    }
    //printf("\n");
}


int 
main(int argc, char **argv)
{
    apr_pool_t *patricia_pool;
    apr_pool_t *tbl_pool;
    patricia_tree_t *pat_tree;
    network_tbl_t *table;
    clock_t t0, t1;
    int i;

    int num = atoi(argv[1]);
    
    apr_initialize();
    apr_pool_create(&patricia_pool, NULL);
    apr_pool_create(&tbl_pool, NULL);
    pat_tree = New_Patricia(patricia_pool, 32);
    table    = network_tbl_init(tbl_pool, 2048);

    add_patricia_networks(patricia_pool, &pat_tree);
    add_tbl_networks(tbl_pool, table);

    t0 = clock();
    for(i = 0; i < num; i++)
    {
	apr_pool_t *t;
	apr_pool_create(&t, tbl_pool);
        test_tbl_good(t, table);
	apr_pool_destroy(t);
    }
    t1 = clock();

    printf("addr table method for POSITIVE matches processed in %g seconds.\n",
            (double)(t1-t0)/(double)CLOCKS_PER_SEC);


    t0 = clock();
    for(i = 0; i < num; i++)
    {
	apr_pool_t *t;

	apr_pool_create(&t, tbl_pool);
        test_tbl_bad(t, table);
	apr_pool_destroy(t);
    }
    t1 = clock();

    printf("addr table method for NEGATIVE matches processed in %g seconds.\n",
            (double)(t1-t0)/(double)CLOCKS_PER_SEC);


    t0 = clock();
    for(i = 0; i < num; i++)
    {
	apr_pool_t *t;
	apr_pool_create(&t, patricia_pool);
	test_patricia_good(t, pat_tree);
	apr_pool_destroy(t);

    }
    t1 = clock();

    printf("Patricia tree method for POSITIVE matches processed in %g seconds.\n",
	    (double)(t1-t0)/(double)CLOCKS_PER_SEC);

    t0 = clock();
    for (i = 0; i < num; i++)
    {
	apr_pool_t *t;
	apr_pool_create(&t, patricia_pool);
	test_patricia_bad(t, pat_tree);
	apr_pool_destroy(t);

    }
    t1 = clock();

    printf("Patricia tree method for NEGATIVE matches processed in %g seconds.\n",
	    (double)(t1-t0)/(double)CLOCKS_PER_SEC);

    printf("\n");
    apr_pool_destroy(patricia_pool);
    apr_pool_destroy(tbl_pool);
    apr_terminate();


    return 0;
}
