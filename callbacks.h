void *webfw2_srcaddr_cb(apr_pool_t *, void *, const void **);
void *webfw2_dstaddr_cb(apr_pool_t *, void *, const void **);
void *webfw2_env_cb(apr_pool_t *, void *, const void **);
void *webfw2_note_cb(apr_pool_t *, void *, const void **);
void *webfw2_header_cb(apr_pool_t *, void *, const void **);
void webfw2_register_callbacks(apr_pool_t *, webfw2_config_t *, webfw2_filter_t *);
