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
#define LEN_MAX 64

/**
 * Name........: splitlen
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

int main (int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf (stderr, "usage: %s outdir < infile\n", argv[0]);

    return (-1);
  }

  #ifdef _WINDOWS
  _setmode (_fileno (stdin), _O_BINARY);
  #endif

  FILE *fps[LEN_MAX + 1];

  int i;

  for (i = LEN_MIN; i <= LEN_MAX; i++)
  {
    char name[BUFSIZ];

    snprintf (name, BUFSIZ, "%s/%02d", argv[1], i);

    fps[i] = fopen (name, "wb");

    if (fps[i] == NULL)
    {
      fprintf (stderr, "%s: %s\n", name, strerror (errno));

      return (-1);
    }
  }

  char line_buf[BUFSIZ];

  int line_len;

  while ((line_len = fgetl (stdin, BUFSIZ, line_buf)) != -1)
  {
    if (line_len < LEN_MIN) continue;
    if (line_len > LEN_MAX) continue;

    fputs (line_buf, fps[line_len]);

    fputc ('\n', fps[line_len]);
  }

  for (i = LEN_MIN; i < LEN_MAX; i++) fclose (fps[i]);

  return 0;
}
