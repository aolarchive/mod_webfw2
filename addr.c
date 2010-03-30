#include <stdio.h>                                                                                                      
#include <signal.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <event.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define __FAVOR_BSD
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <unistd.h>
#include "apr.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "addr.h"

static uint32_t netmask_tbl[] = {
    0x00000000, 0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
    0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000, 0xFF800000,
    0xFFC00000, 0xFFE00000, 0xFFF00000, 0xFFF80000, 0xFFFC0000,
    0xFFFE0000, 0xFFFF0000, 0xFFFF8000, 0xFFFFC000, 0xFFFFE000,
    0xFFFFF000, 0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
    0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
    0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF };

addr_t *
addr_from_string(apr_pool_t *pool, const char *addrstr)
{
    char   *addrstr_copy;
    char   *tok;
    int     bitlen = 32;
    addr_t *addr   = NULL;
    char   *endptr = NULL;

    if (addrstr == NULL)
	return NULL;

    addrstr_copy = apr_pstrdup(pool, addrstr);

    if (!(addr = apr_pcalloc(pool, sizeof(addr_t))))
	return NULL;

    if (!(tok = strtok_r(addrstr_copy, "/", &endptr)))
	return NULL;

    addr->addr = ntohl(inet_addr(tok));

    if ((tok = strtok_r(NULL, "/", &endptr)))
    {
	bitlen = atoi(tok);
	addr->mask   = netmask_tbl[bitlen];
	addr->bitlen = bitlen;
    }
    else
    {
	addr->bitlen = 32;
	addr->mask   = 0xFFFFFFFF;
    }

    addr->broadcast = addr->addr | (0xFFFFFFFF & ~addr->mask);

    return addr;
}

addr_t *
addr_from_addr(apr_pool_t *pool, const uint32_t inaddr, const int bitlen)
{
    addr_t *addr;

    if (!(addr = apr_pcalloc(pool, sizeof(addr_t))))
	return NULL;

    addr->addr      = inaddr;
    addr->broadcast = inaddr;
    addr->bitlen    = bitlen;
    addr->mask      = netmask_tbl[bitlen];

    return addr;
}

int
addr_compare(apr_pool_t *pool, addr_t *haystack, addr_t *needle)
{
   if (!haystack || !needle)
      return 0; 

   if ((needle->addr >= haystack->addr) && 
	   needle->broadcast <= haystack->broadcast)
       return 1;

   return 0;
}

int
addr_compare_from_str(apr_pool_t *pool, 
	const char *haystack, const char *needle)
{
    addr_t *addr1 = NULL;
    addr_t *addr2 = NULL;

    if (!haystack || !needle)
	return 0;

    addr1 = addr_from_string(pool, haystack);

    if (addr1 == NULL)
	return -1;

    addr2 = addr_from_string(pool, needle);

    if (addr2 == NULL)
	return -1;

    return addr_compare(pool, addr1, addr2);
}

#ifdef TEST_ADDR
int main(int argc, char **argv)
{
    apr_pool_t *pool;

    apr_initialize();
    apr_pool_create(&pool, NULL);

    printf("%d\n",
	    addr_compare_from_str(pool, argv[1], argv[2]));

    apr_pool_destroy(pool);
    apr_terminate();
    return 0;
}
#endif
