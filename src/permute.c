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

  char line_buf[BUFSIZ];

  int line_len;

  while ((line_len = fgetl (stdin, BUFSIZ, line_buf)) != -1)
  {
    if (line_len == 0) continue;

    /* init permutation */

    int p[BUFSIZ];

    int k;

    for (k = 0; k < line_len + 1; k++) p[k] = k;

    k = 1;

    /* run permutation */

    puts (line_buf);

    while ((k = next_permutation (line_buf, p, k)) != line_len) puts (line_buf);

    puts (line_buf);
  }

  return (0);
}
