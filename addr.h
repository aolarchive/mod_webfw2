typedef struct _addr {
    uint8_t  bitlen;
    uint32_t addr;
    uint32_t mask;
    uint32_t broadcast;
} addr_t;

addr_t *addr_from_string(apr_pool_t *pool, const char *addrstr);
addr_t *addr_from_addr(apr_pool_t *pool, const uint32_t inaddr, const int bitlen);
int     addr_compare(apr_pool_t *pool, addr_t *haystack, addr_t *needle);
int     addr_compare_from_str(apr_pool_t *pool, const char *haystack, const char *needle);
