#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define ASSERT_EQUALS(x,y) \
    do {   \
        if (!((x) == (y))) {   \
              fprintf(stderr, "\nASSERTION '"#x" == "#y"' failed. [%s:%d]\n",   \
                                __FILE__,__LINE__);   \
            }   \
        else {   \
              fprintf(stderr, ".");   \
            }   \
      } while (0)

#define ASSERT_STRING_EQUALS(x, y) ASSERT_EQUALS(strcmp((x),(y)),0)
#define ASSERT_OK ASSERT_EQUALS(1,1)



