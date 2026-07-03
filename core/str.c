#include "str.h"

#include <string.h>

size_t cn_strlcpy(char *dst, const char *src, size_t dst_size)
{
    if (dst == NULL || src == NULL || dst_size == 0) {
        return 0;
    }

    size_t src_len  = strlen(src);
    size_t copy_len = (src_len < dst_size - 1u) ? src_len : dst_size - 1u;

    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';

    /* Return total src length so the caller can detect truncation:
     * truncation occurred when the return value >= dst_size. */
    return src_len;
}

size_t cn_strnlen(const char *str, size_t max_len)
{
    if (str == NULL || max_len == 0) {
        return 0;
    }

    size_t i;
    for (i = 0; i < max_len; i++) {
        if (str[i] == '\0') {
            return i;
        }
    }

    /* No NUL found within max_len bytes — string is at least max_len long. */
    return max_len;
}
