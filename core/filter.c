#include "filter.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

#include <pcap.h>

/* -------------------------------------------------------------------------
 * Opaque filter structure — holds the compiled BPF bytecode.
 * ---------------------------------------------------------------------- */

struct cn_filter {
    struct bpf_program prog; /* Compiled BPF bytecode from pcap_compile(). */
};

/* =========================================================================
 * Public API
 * ====================================================================== */

cn_err_t cn_filter_compile(cn_filter_t **filter, struct pcap *handle,
                           const char *expr)
{
    if (filter == NULL || handle == NULL || expr == NULL) {
        return CN_ERR_INVAL;
    }

    size_t expr_len = strlen(expr);
    if (expr_len == 0 || expr_len >= CN_BPF_FILTER_MAX) {
        return CN_ERR_INVAL;
    }

    cn_filter_t *f = (cn_filter_t *)malloc(sizeof(*f));
    if (f == NULL) {
        return CN_ERR_NOMEM;
    }
    memset(f, 0, sizeof(*f));

    /*
     * pcap_compile: optimize=1, netmask=PCAP_NETMASK_UNKNOWN.
     * The netmask is used only for broadcast address matching in BPF;
     * PCAP_NETMASK_UNKNOWN is correct for the general case.
     */
    if (pcap_compile((pcap_t *)handle, &f->prog, expr,
                     1, PCAP_NETMASK_UNKNOWN) != 0) {
        CN_LOG_ERROR("pcap_compile(\"%s\"): %s", expr,
                     pcap_geterr((pcap_t *)handle));
        free(f);
        return CN_ERR_INVAL;
    }

    *filter = f;
    return CN_OK;
}

cn_err_t cn_filter_apply(const cn_filter_t *filter, struct pcap *handle)
{
    if (filter == NULL || handle == NULL) {
        return CN_ERR_INVAL;
    }

    if (pcap_setfilter((pcap_t *)handle,
                       (struct bpf_program *)&filter->prog) != 0) {
        CN_LOG_ERROR("pcap_setfilter: %s", pcap_geterr((pcap_t *)handle));
        return CN_ERR_IO;
    }

    return CN_OK;
}

void cn_filter_destroy(cn_filter_t **filter)
{
    if (filter == NULL || *filter == NULL) {
        return;
    }

    pcap_freecode(&(*filter)->prog);
    free(*filter);
    *filter = NULL;
}
