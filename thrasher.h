typedef enum {
    TYPE_THRESHOLD_v1 = 0,  
    TYPE_REMOVE,
    TYPE_INJECT,
    TYPE_THRESHOLD_v2,
    TYPE_THRESHOLD_v3,
    TYPE_THRESHOLD_v4,
} thrasher_pkt_type;

typedef struct thrasher_v1_data {
	char *host;
	char *uri;
	uint32_t addr;
	uint16_t hlen;
	uint16_t urilen;
} thrasher_v1_data_t;

typedef struct thrasher_v2_data {
	uint16_t addr;
} thrasher_v2_data_t;

typedef struct thrasher_v3_data {
	char *host;
	char *uri;
	uint32_t addr;
	uint16_t hlen;
	uint16_t urilen;
	uint32_t ident;
} thrasher_v3_data_t;

typedef struct thrasher_v4_data {
	char *host;
	char *uri;
	uint32_t addr;
	uint16_t hlen;
	uint16_t urilen;
	uint32_t ident;
	char *reason;
} thrasher_v4_data_t;

typedef struct thrasher_pkt {
  unsigned char *packet;
  apr_size_t len;
  void *thrasher_data;
  int  (*thrasher_recv_cb)(struct thrasher_pkt *pkt, apr_socket_t *sock);
} thrasher_pkt_t;
	
int thrasher_query(request_rec *, 
        webfw2_config_t *,
        webfw2_filter_t *,  
        thrasher_pkt_type, 
        const char *, 
        uint32_t, 
        char*);

apr_socket_t *thrasher_connect(apr_pool_t *pool, webfw2_config_t *config);
int thrasher_is_connected(apr_socket_t *sock);
int thrasher_should_retry(webfw2_config_t *, webfw2_filter_t *);

