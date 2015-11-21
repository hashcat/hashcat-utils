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
 * Name........: strip-bsr
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 * Description.: strip all \r bytes
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

  char buf_i[BUFSIZ];
  char buf_o[BUFSIZ];

  while (!feof (stdin))
  {
    size_t len_i = fread (buf_i, 1, sizeof (buf_i), stdin);

    if (len_i <= 0) break;

    char *tmp_i = buf_i;
    char *tmp_o = buf_o;

    size_t i;

    for (i = 0; i < len_i; i++)
    {
      const char c = *tmp_i++;

      if (c == '\r') continue;

      *tmp_o++ = c;
    }

    size_t len_o = tmp_o - buf_o;

    fwrite (buf_o, 1, len_o, stdout);
  }

  return 0;
}
