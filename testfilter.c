#include <stdio.h>
#include <stdlib.h>
#include "apr.h"
#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_tables.h"
#include "filter.h"

void print_ip(prefix_t *prefix, void *data)
{
    char buf[100];
    prefix_toa2x(prefix, buf, 1);
    printf("  %c%s\n", (data == 0?'+':'-'), buf);
}


void print_filter(filter_t *filter)
{
    char *flows[] = {"", "src_addr", "dst_addr", "chad_ord", "string", "or", "and", "not_src_addr", "not_dst_addr", "not_string"};
    filter_rule_t  *rule = filter->head;


    while (rule) {
        printf("Name:         %s\n", rule->name);
        printf("Action:       %d\n", rule->action);
        printf("Code:         %d\n", rule->status_code);
        printf("Log:          %d\n", rule->log);
        if (rule->src_addrs) {
            printf("Src Addrs:\n");
            patricia_process(rule->src_addrs, print_ip);
        }
        if (rule->dst_addrs) {
            printf("Dst Addrs:\n");
            patricia_process(rule->dst_addrs, print_ip);
        }
        if (rule->strings) {
            printf("String Regex: %d\n", rule->strings_have_regex);
            printf("Strings:\n");
            apr_hash_index_t *hi;
            for (hi = apr_hash_first(filter->pool, rule->strings); hi; hi = apr_hash_next(hi)) {
                const void *   key;
                apr_ssize_t    klen;
                apr_hash_t    *string_hash;

                apr_hash_this(hi, &key, &klen, (void**)&string_hash);
                printf("   %.*s\n", klen, key);

                apr_hash_index_t *hi2;
                for (hi2 = apr_hash_first(filter->pool, string_hash); hi2; hi2 = apr_hash_next(hi)) {
                    const void *   key2;
                    apr_ssize_t    klen2;

                    apr_hash_this(hi, &key2, &klen2, NULL);
                    printf("      %.*s\n", klen2, key2);
                }
            }
        }

        rule_flow_t * flow = rule->flow;
        if (flow) {
            printf("Flows:\n");
            while (flow) {
                printf("Type:         %d\n", flow->type);
                flow = flow->next;
            }
        }
        printf("\n");
        rule = rule->next;
    }
}

int
main(int argc, char **argv)
{
    filter_t       *filter;
    apr_pool_t     *root_pool;

    if (argc <= 1) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(0);
    }

    apr_initialize();
    apr_pool_create(&root_pool, NULL);

    filter = filter_parse_config(root_pool, argv[1], 1);

    printf("Filter passed? %s\n", filter ? "yes" : "no");

    /*if (filter)
        print_filter(filter);*/

    apr_pool_destroy(root_pool);
    apr_terminate();
    return 0;
}
