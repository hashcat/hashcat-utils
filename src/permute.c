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

/**
 * Name........: permute
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 * Credits.....: This program is using the awesome "Countdown QuickPerm Algorithm" developed by Phillip Paul Fuchs
 */

#define LINE_SIZE  8192
#define OUT_SIZE   8192

typedef struct out
{
  FILE *fp;

  char  buf[OUT_SIZE];
  int   len;

} out_t;

static void out_flush (out_t *out)
{
  if (out->len == 0) return;

  fwrite (out->buf, 1, out->len, out->fp);

  out->len = 0;
}

static void out_push (out_t *out, const char *pw_buf, const int pw_len)
{
  char *ptr = out->buf + out->len;

  memcpy (ptr, pw_buf, pw_len);

  #if defined (_WIN)

  ptr[pw_len + 0] = '\r';
  ptr[pw_len + 1] = '\n';

  out->len += pw_len + 2;

  #else

  ptr[pw_len] = '\n';

  out->len += pw_len + 1;

  #endif

  if (out->len >= OUT_SIZE - 300)
  {
    out_flush (out);
  }
}

size_t next_permutation (char *word, int *p, int k)
{
  p[k]--;

  int j = k % 2 * p[k];

  char tmp = word[j];

  word[j] = word[k];

  word[k] = tmp;

  for (k = 1; p[k] == 0; k++) p[k] = k;

  return k;
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

  out_t out;

  out.fp  = stdout;
  out.len = 0;

  char line_buf[LINE_SIZE];

  int line_len;

  while ((line_len = fgetl (stdin, LINE_SIZE, line_buf)) != -1)
  {
    if (line_len == 0) continue;

    /* init permutation */

    int p[LINE_SIZE];

    int k;

    for (k = 0; k < line_len + 1; k++) p[k] = k;

    k = 1;

    /* run permutation */

    out_push (&out, line_buf, line_len);

    while ((k = next_permutation (line_buf, p, k)) != line_len)
    {
      out_push (&out, line_buf, line_len);
    }

    out_push (&out, line_buf, line_len);

    out_flush (&out);
  }

  return (0);
}
