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

#define TMPSIZ 0x100

/**
 * Name........: prepare
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

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

    /* build prepare buffer */

    char tmp_buf[TMPSIZ];

    memset (tmp_buf, 0, TMPSIZ);

    int p;

    for (p = 0; p < line_len; p++)
    {
      int chr = (int) line_buf[p];

      if (chr < 0) continue;
      if (chr >= TMPSIZ) continue;

      tmp_buf[chr]++;
    }

    /* output prepare buffer */

    int line_pos;

    int tmp_pos;

    for (tmp_pos = 0, line_pos = 0; tmp_pos < TMPSIZ; tmp_pos++)
    {
      int j;

      for (j = 0; j < tmp_buf[tmp_pos]; j++)
      {
        line_buf[line_pos] = (uint8_t)tmp_pos;

        line_pos++;
      }
    }

    puts (line_buf);
  }

  return 0;
}
