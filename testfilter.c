#include <stdio.h>
#include <stdlib.h>
#include "apr.h"
#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_tables.h"
#include "filter.h"

int
main(int argc, char **argv)
{
    filter_t *filter;
    apr_pool_t     *root_pool;

    if (argc <= 1) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(0);
    }

    apr_initialize();
    apr_pool_create(&root_pool, NULL);

    filter = filter_parse_config(root_pool, argv[1]);

    printf("Filter passed? %s\n", filter ? "yes" : "no");

    apr_pool_destroy(root_pool);
    apr_terminate();
    return 0;
}
