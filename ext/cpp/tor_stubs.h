#ifndef TOR_STUBS_H_DDXSMNXB
#define TOR_STUBS_H_DDXSMNXB

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <limits.h>

#if defined(__GNUC__) && __GNUC__ >= 3
#define PREDICT_LIKELY(exp) __builtin_expect(!!(exp), 1)
#define PREDICT_UNLIKELY(exp) __builtin_expect(!!(exp), 0)
#else
#define PREDICT_UNLIKELY(exp) (exp)
#define PREDICT_LIKELY(exp) (exp)
#endif

/** Expands to a syntactically valid empty statement.  */
#define STMT_NIL (void)0

/** Expands to a syntactically valid empty statement, explicitly (void)ing its
 *  * argument. */
#define STMT_VOID(a) while (0) { (void)(a); }

#ifdef __GNUC__
/** STMT_BEGIN and STMT_END are used to wrap blocks inside macros so that
 *  * the macro can be used as if it were a single C statement. */
#define STMT_BEGIN (void) ({
#define STMT_END })
#elif defined(sun) || defined(__sun__)
#define STMT_BEGIN if (1) {
#define STMT_END } else STMT_NIL
#else
#define STMT_BEGIN do {
#define STMT_END } while (0)
#endif

#ifndef SIZE_T_MAX
#define SIZE_T_MAX (-(size_t)1)
#endif

#ifndef SSIZE_T_MAX
#define SSIZE_T_MAX (-(size_t)1)
#endif

/** Any ssize_t larger than this amount is likely to be an underflow. */
#define SSIZE_T_CEILING ((ssize_t)(SSIZE_T_MAX-16))
/** Any size_t larger than this amount is likely to be an underflow. */
#define SIZE_T_CEILING  ((size_t)(SSIZE_T_MAX-16))

/** Like assert(3), but send assertion failures to the log as well as to
 *  * stderr. */
#define tor_assert(expr) STMT_BEGIN                                     \
      if (PREDICT_UNLIKELY(!(expr))) {                                    \
            fprintf(stderr,"%s:%d %s: Assertion %s failed; aborting.\n",      \
                              __FILE__, __LINE__, __func__, #expr);                 \
            abort();                                                          \
          } STMT_END

#define approx_time() time(NULL)

void * tor_malloc(size_t size);

#define tor_free(x) \
  do {              \
    free(x);        \
    (x) = 0;        \
  } while (0)

void _tor_free(void *x);

#define Q(x) #x
#define QUOTE(x) Q(x)

#define QUIET
#ifndef QUIET

#define log_notice(domain, msg, ...) \
  fprintf(stderr, "NOTICE:" QUOTE(domain)":" msg "\n", ##__VA_ARGS__)

#define log_info(domain, msg, ...) \
  fprintf(stderr, "INFO:" QUOTE(domain)":"msg "\n", ##__VA_ARGS__)

#define log_warn(domain, msg, ...) \
  fprintf(stderr, "WARN:" QUOTE(domain)":"msg "\n", ##__VA_ARGS__)

#else
#define log_notice(domain, msg, ...) ;
#define log_info(domain, msg, ...) ;
#define log_warn(domain, msg, ...) ;
#endif

uint64_t crypto_rand_uint64(uint64_t mod);

/** Encode the <b>srclen</b> bytes at <b>src</b> in a NUL-terminated,
 *  * uppercase hexadecimal string; store it in the <b>destlen</b>-byte buffer
 *   * <b>dest</b>.
 *    */
void base16_encode(char *dest, size_t destlen, const char *src, size_t srclen);

/** Helper: given a hex digit, return its value, or -1 if it isn't hex. */
int _hex_decode_digit(char c);

/** Helper: given a hex digit, return its value, or -1 if it isn't hex. */
int hex_decode_digit(char c);

/** Given a hexadecimal string of <b>srclen</b> bytes in <b>src</b>, decode it
 *  * and store the result in the <b>destlen</b>-byte buffer at <b>dest</b>.
 *   * Return 0 on success, -1 on failure. */
int base16_decode(char *dest, size_t destlen, const char *src, size_t srclen);

#ifdef __cplusplus
}
#endif
#endif /* end of include guard: TOR_STUBS_H_DDXSMNXB */

