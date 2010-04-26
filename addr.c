#include <stdio.h>                                                                                                      
#include <ctype.h>
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

static int
my_inet_pton(int af, const char *src, void *dst)
{
    if (af == AF_INET) {
        int             i,
                        c,
                        val;
        /* not thread safe */
        u_char          xp[4] = { 0, 0, 0, 0 };

        for (i = 0;; i++) {
            c = *src++;
            if (!isdigit(c))
                return (-1);
            val = 0;
            do {
                val = val * 10 + c - '0';
                if (val > 255)
                    return (0);
                c = *src++;
            } while (c && isdigit(c));
            xp[i] = val;
            if (c == '\0')
                break;
            if (c != '.')
                return (0);
            if (i >= 3)
                return (0);
        }
        memcpy(dst, xp, 4);
        return (1);
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
}

#define MAXLINE 16 

addr_t *
addr_from_string(apr_pool_t *pool, const char *addrstr)
{
    int     bitlen;
    addr_t *addr;
    char *cp;
    char save[MAXLINE];

    if (addrstr == NULL)
	return NULL;

    if (!(addr = apr_palloc(pool, sizeof(addr_t)))) 
	return NULL;

    bitlen = 32;

    if ((cp = strchr(addrstr, '/')) != NULL) {
        bitlen = atoi(cp + 1);
        memcpy(save, addrstr, cp - addrstr);
        save[cp - addrstr] = '\0';
    } 

    my_inet_pton(AF_INET, save, &addr->addr);
    addr->addr      = ntohl(addr->addr);
    addr->mask      = netmask_tbl[bitlen];
    addr->bitlen    = bitlen;
    addr->addr      = addr->addr & addr->mask;
    addr->broadcast = addr->addr | (0xFFFFFFFF & ~addr->mask);

    return addr;
}

addr_t *
addr_from_addr(apr_pool_t *pool, const uint32_t inaddr, const int bitlen)
{
    addr_t *addr;

    if (!(addr = apr_palloc(pool, sizeof(addr_t))))
	return NULL;

    addr->broadcast = inaddr;
    addr->bitlen    = bitlen;
    addr->mask      = netmask_tbl[bitlen];
    addr->addr      = inaddr & addr->mask;

    return addr;
}

int
addr_compare(apr_pool_t *pool, addr_t *haystack, addr_t *needle)
{
   if (!haystack || !needle)
      return 0; 

   if (needle->addr >= haystack->addr && 
	   needle->broadcast <= haystack->broadcast)
   {
       return 1;
   }

   return 0;
}

int
addr_compare_from_str(apr_pool_t *pool, 
	const char *haystack, const char *needle)
{
    addr_t *addr1;
    addr_t *addr2;

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
