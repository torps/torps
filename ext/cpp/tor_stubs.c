#include "tor_stubs.h"

void
_tor_free(void *x)
{
  tor_free(x);
}

void *
tor_malloc(size_t size)
{
 void *result;

 result = malloc(size);

 if (!result) {
   fprintf(stderr,"Out of memory on malloc()\n");
   exit(1);
 }

 return result;
}

static FILE *__rand_f;

uint64_t
crypto_rand_uint64(uint64_t mod)
{
  if (!__rand_f) {
    __rand_f = fopen("/dev/urandom","r");
  }
  
  if (!__rand_f) {
    perror("randgetter");
    assert(0);
  }

  uint64_t bytes;
  fgets((char *)&bytes,sizeof(uint64_t),__rand_f);

  return bytes % mod;
}

void base16_encode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  const char *end;
  char *cp;

  tor_assert(destlen >= srclen*2+1);
  tor_assert(destlen < SIZE_T_CEILING);

  cp = dest;
  end = src+srclen;
  while (src<end) {
      *cp++ = "0123456789ABCDEF"[ (*(const uint8_t*)src) >> 4 ];
      *cp++ = "0123456789ABCDEF"[ (*(const uint8_t*)src) & 0xf ];
      ++src;
    }
  *cp = '\0';
}

inline int
_hex_decode_digit(char c)
{
  switch (c) {
      case '0': return 0;
      case '1': return 1;
      case '2': return 2;
      case '3': return 3;
      case '4': return 4;
      case '5': return 5;
      case '6': return 6;
      case '7': return 7;
      case '8': return 8;
      case '9': return 9;
      case 'A': case 'a': return 10;
      case 'B': case 'b': return 11;
      case 'C': case 'c': return 12;
      case 'D': case 'd': return 13;
      case 'E': case 'e': return 14;
      case 'F': case 'f': return 15;
      default:
        return -1;
    }
}

int
hex_decode_digit(char c)
{
  return _hex_decode_digit(c);
}

int
base16_decode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  const char *end;

  int v1,v2;
  if ((srclen % 2) != 0)
    return -1;
  if (destlen < srclen/2 || destlen > SIZE_T_CEILING)
    return -1;
  end = src+srclen;
  while (src<end) {
      v1 = _hex_decode_digit(*src);
      v2 = _hex_decode_digit(*(src+1));
      if (v1<0||v2<0)
        return -1;
      *(uint8_t*)dest = (v1<<4)|v2;
      ++dest;
      src+=2;
    }
  return 0;
}
