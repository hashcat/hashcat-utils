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
 * Name........: gate
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

int main (int argc, char *argv[])
{
  if (argc != 3)
  {
    fprintf (stderr, "usage: %s mod offset < infile > outfile\n", argv[0]);

    return (-1);
  }

  #ifdef _WINDOWS
  _setmode (_fileno (stdin), _O_BINARY);
  #endif

  const int mod = atoi (argv[1]);

  if (mod < 1)
  {
    fprintf (stderr, "mod < 1\n");

    return (-1);
  }

  const int offset = atoi (argv[2]);

  if (offset >= mod)
  {
    fprintf (stderr, "offset >= mod\n");

    return (-1);
  }

  int pos = 0;

  char line_buf[BUFSIZ];

  int line_len;

  while ((line_len = fgetl (stdin, BUFSIZ, line_buf)) != -1)
  {
    if (line_len == 0) continue;

    if (pos == mod) pos = 0;

    if ((pos++ % mod) != offset) continue;

    puts (line_buf);
  }

  return 0;
}
