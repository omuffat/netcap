#ifndef CN_STR_H
#define CN_STR_H

#include <stddef.h>
#include "constants.h"

/**
 * @brief Copy at most dst_size - 1 characters from src to dst, always
 *        NUL-terminating the result.
 *
 * Safer replacement for strcpy/strncpy. dst is always NUL-terminated as long
 * as dst_size > 0. If src is longer than dst_size - 1 characters, the string
 * is silently truncated. Use the return value to detect truncation.
 *
 * @security dst and src must not overlap. dst_size must reflect the true
 *           allocated capacity of dst, validated by the caller against the
 *           relevant CN_*_MAX constant before this call.
 *
 * @param[out] dst       Destination buffer. Must not be NULL.
 * @param[in]  src       NUL-terminated source string. Must not be NULL.
 * @param[in]  dst_size  Total capacity of dst in bytes, including the NUL
 *                       terminator. Must be > 0.
 *
 * @return Total length of src in bytes (not the number of bytes written).
 *         If the return value >= dst_size, truncation occurred.
 */
size_t cn_strlcpy(char *dst, const char *src, size_t dst_size)
    __attribute__((warn_unused_result));

/**
 * @brief Return the length of str, capped at max_len.
 *
 * Scans at most max_len bytes. Useful for safely measuring lengths of
 * untrusted or externally sourced strings without risking an unbounded scan.
 *
 * @param[in] str      String to measure. Must not be NULL.
 * @param[in] max_len  Maximum number of bytes to scan. Must be > 0.
 *
 * @return Length of str if str is NUL-terminated within max_len bytes;
 *         max_len otherwise (indicating the string is too long or unterminated).
 */
size_t cn_strnlen(const char *str, size_t max_len);

#endif /* CN_STR_H */
