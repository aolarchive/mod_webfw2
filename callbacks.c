#include <stdio.h>
#include "mod_webfw2.h"
#include "callbacks.h"

void           *
webfw2_srcaddr_cb(apr_pool_t * pool, void *fc_data, const void **usrdata)
{
    if (!usrdata)
        return NULL;

    return (void *) usrdata[1];
}

void           *
webfw2_dstaddr_cb(apr_pool_t * pool, void *fc_data, const void **userdata)
{
    if (!userdata)
        return NULL;

    return (void *) userdata[2];
}

void           *
webfw2_env_cb(apr_pool_t * pool, void *fc_data, const void **userdata)
{
    request_rec    *rec;
    char           *data;

    if (!userdata || !fc_data)
        return NULL;

    rec = (request_rec *) userdata[0];
    data = (char *) apr_table_get(rec->subprocess_env, (char *) fc_data);

    return data ? data : "__wf2-NULL__";
}

void           *
webfw2_note_cb(apr_pool_t * pool, void *fc_data, const void **userdata)
{
    request_rec    *rec;
    char           *data;
    if (!userdata || !fc_data)
        return NULL;

    rec = (request_rec *) userdata[0];

    data = (char *) apr_table_get(rec->notes, (char *) fc_data);

    return data ? data : "__wf2-NULL__";
}

void           *
webfw2_header_cb(apr_pool_t * pool, void *fc_data, const void **userdata)
{
    request_rec    *rec;
    char           *data;

    if (!userdata || !fc_data)
        return NULL;

    rec = (request_rec *) userdata[0];
    data = (char *) apr_table_get(rec->headers_in, (char *) fc_data);

    return data ? data : "__wf2-NULL__";
}

void
webfw2_register_callbacks(apr_pool_t * pool, webfw2_config_t * config,
                          webfw2_filter_t * filter)
{
    int             i;
    char          **list;

    filter_register_user_cb(filter->filter,
                            (void *) webfw2_srcaddr_cb, RULE_MATCH_SRCADDR,
                            NULL);

    filter_register_user_cb(filter->filter, (void *) webfw2_dstaddr_cb,
                            RULE_MATCH_DSTADDR, NULL);

    if (config->match_header) {
        list = (char **) config->match_header->elts;

        for (i = 0; i < config->match_header->nelts; i++)
            filter_register_user_cb(filter->filter,
                                    (void *) webfw2_header_cb,
                                    RULE_MATCH_STRING, list[i]);
    }

    if (config->match_note) {
        list = (char **) config->match_note->elts;

        for (i = 0; i < config->match_note->nelts; i++)
            filter_register_user_cb(filter->filter,
                                    (void *) webfw2_note_cb,
                                    RULE_MATCH_STRING, list[i]);
    }

    if (config->match_env) {
        list = (char **) config->match_env->elts;

        for (i = 0; i < config->match_env->nelts; i++)
            filter_register_user_cb(filter->filter, (void *) webfw2_env_cb,
                                    RULE_MATCH_STRING, list[i]);
    }
}
