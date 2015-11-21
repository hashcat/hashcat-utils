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
#include <search.h>
#include "utils.c"

/**
 * Name........: hcstatgen
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define CHARSIZ 0x100

#define PW_MIN  2
#define PW_MAX  64

#define HEX 0

/**
 * Outfile structure:
 *
 * - PW_MAX pw_pos
 *   - CHARSIZ root
 * - PW_MAX pw_pos
 *   - CHARSIZ key0
 *     - CHARSIZ key1
 */

static uint8_t hex_convert (uint8_t c)
{
  return (c & 15) + (c >> 6) * 9;
}

int main (int argc, char *argv[])
{
  uint32_t i, j;

  if (argc != 2)
  {
    fprintf (stderr, "usage: %s outfile < dictionary\n", argv[0]);

    return (-1);
  }

  char *outfile = argv[1];

  /* init data */

  const uint32_t root_cnt = PW_MAX * CHARSIZ;

  uint64_t *root_stats_buf = (uint64_t *) calloc (root_cnt, sizeof (uint64_t));

  uint64_t *root_stats_ptr = root_stats_buf;

  uint64_t *root_stats_buf_by_pos[PW_MAX];

  for (i = 0; i < PW_MAX; i++)
  {
    root_stats_buf_by_pos[i] = root_stats_ptr;

    root_stats_ptr += CHARSIZ;
  }

  const uint32_t markov_cnt = PW_MAX * CHARSIZ * CHARSIZ;

  uint64_t *markov_stats_buf = (uint64_t *) calloc (markov_cnt, sizeof (uint64_t));

  uint64_t *markov_stats_ptr = markov_stats_buf;

  uint64_t *markov_stats_buf_by_key[PW_MAX][CHARSIZ];

  for (i = 0; i < PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      markov_stats_buf_by_key[i][j] = markov_stats_ptr;

      markov_stats_ptr += CHARSIZ;
    }
  }

  /* parse dictionary */

  char tmp[BUFSIZ];

  printf ("Reading input...\n");

  if (HEX)
  {
    while (!feof (stdin))
    {
      char *line_buf = fgets (tmp, BUFSIZ, stdin);

      if (line_buf == NULL) continue;

      size_t line_len = super_chop (line_buf, strlen (line_buf));

      if (line_len < PW_MIN) continue;
      if (line_len > PW_MAX) continue;

      size_t line_pos;

      for (line_pos = 0; line_pos < line_len - 2; line_pos += 2)
      {
        uint8_t c0 = hex_convert (line_buf[line_pos + 1]) << 0
                   | hex_convert (line_buf[line_pos + 0]) << 4;
        uint8_t c1 = hex_convert (line_buf[line_pos + 3]) << 0
                   | hex_convert (line_buf[line_pos + 2]) << 4;

        root_stats_buf_by_pos[line_pos][c0]++;

        markov_stats_buf_by_key[line_pos][c0][c1]++;
      }

      uint8_t c0 = hex_convert (line_buf[line_pos + 1]) << 0
                 | hex_convert (line_buf[line_pos + 0]) << 4;

      root_stats_buf_by_pos[line_pos][c0]++;
    }
  }
  else
  {
    while (!feof (stdin))
    {
      char *line_buf = fgets (tmp, BUFSIZ, stdin);

      if (line_buf == NULL) continue;

      size_t line_len = super_chop (line_buf, strlen (line_buf));

      if (line_len < PW_MIN) continue;
      if (line_len > PW_MAX) continue;

      size_t line_pos;

      for (line_pos = 0; line_pos < line_len - 1; line_pos += 1)
      {
        uint8_t c0 = line_buf[line_pos + 0];
        uint8_t c1 = line_buf[line_pos + 1];

        root_stats_buf_by_pos[line_pos][c0]++;

        markov_stats_buf_by_key[line_pos][c0][c1]++;
      }

      uint8_t c0 = line_buf[line_pos + 0];

      root_stats_buf_by_pos[line_pos][c0]++;
    }
  }

  /* write results */

  printf ("Writing stats...\n");

  FILE *fd = fopen (outfile, "wb");

  if (fd == NULL)
  {
    fprintf (stderr, "%s: %s", outfile, strerror (errno));

    return (-1);
  }

  fwrite (root_stats_buf,   sizeof (uint64_t), root_cnt,   fd);
  fwrite (markov_stats_buf, sizeof (uint64_t), markov_cnt, fd);

  free (root_stats_buf);
  free (markov_stats_buf);

  fclose (fd);

  return 0;
}
