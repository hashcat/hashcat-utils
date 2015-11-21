#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define __MSVCRT_VERSION__ 0x0700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include "utils.c"

#define LEN_MIN 1
#define LEN_MAX 4

/**
 * Name........: expander
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

void strrotl (char *s, int len)
{
  char *s1 = s;
  char *s2 = s;

  for (s2 += len - 1; s1 < s2; s2--)
  {
    *s1 ^= *s2;
    *s2 ^= *s1;
    *s1 ^= *s2;
  }
}

void strrotr (char *s, int len)
{
  char *s1 = s;
  char *s2 = s;

  for (s2++; s2 < s1 + len; s2++)
  {
    *s1 ^= *s2;
    *s2 ^= *s1;
    *s1 ^= *s2;
  }
}

int main (int argc, char *argv[])
{
  if (argc != 1)
  {
    fprintf (stderr, "usage: %s < infile > outfile\n", argv[0]);

    return (-1);
  }

  #ifdef _WINDOWS
  _setmode (_fileno (stdin), _O_BINARY);
  #endif

  char line_buf[BUFSIZ];

  int line_len;

  while ((line_len = fgetl (stdin, BUFSIZ, line_buf)) != -1)
  {
    if (line_len == 0) continue;

    int n;

    for (n = LEN_MIN; n <= LEN_MAX; n++)
    {
      if (n > line_len) break;

      char tmp2_buf[BUFSIZ];

      memcpy (tmp2_buf, line_buf, line_len);

      int i;

      /* rotate to the left */

      for (i = 0; i < n; i++)
      {
        int j;

        for (j = 0; j + n <= line_len; j += n)
        {
          int out_len = (int) strlen (tmp2_buf + j);

          if (out_len > n) out_len = n;

          char out_buf[BUFSIZ];

          memcpy (out_buf, tmp2_buf + j, out_len);

          out_buf[out_len] = 0;

          puts (out_buf);
        }

        strrotl (tmp2_buf, line_len);
      }

      /* rotate to the right */

      for (i = 0; i < n; i++)
      {
        int j;

        for (j = 0; j + n <= line_len; j += n)
        {
          int out_len = (int) strlen (tmp2_buf + j);

          if (out_len > n) out_len = n;

          char out_buf[BUFSIZ];

          memcpy (out_buf, tmp2_buf + j, out_len);

          out_buf[out_len] = 0;

          puts (out_buf);
        }

        strrotr (tmp2_buf, line_len);
      }
    }
  }

  return 0;
}
