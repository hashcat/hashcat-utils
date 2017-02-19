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

#define CHR_MIN 0x20
#define CHR_MAX 0x7f

#define KEYS_CNT1 0xff
#define KEYS_CNT2 0xffff
#define KEYS_CNT3 0xffffff

/**
 * Name........: morph
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

typedef struct
{
  uint32_t key;
  uint32_t val;

} node;

int comp (const void *p1, const void *p2)
{
  node *b1 = (node *) p1;
  node *b2 = (node *) p2;

  return b2->val - b1->val;
}

uint32_t count_keys (const uint32_t *c, const uint32_t n)
{
  uint32_t v = 0;

  uint32_t i;

  for (i = 0; i < n; i++)
  {
    if (c[i] == 0) continue;

    v++;
  }

  return v;
}

void move_keys (const uint32_t *c, const uint32_t n, node *s)
{
  uint32_t i;

  for (i = 0; i < n; i++)
  {
    if (c[i] == 0) continue;

    s->key = i;
    s->val = c[i];

    s++;
  }
}

void output_rule (node *sort_buf, const uint32_t sort_cnt, const uint32_t pos, const uint32_t width, const uint32_t depth)
{
  uint32_t i;

  for (i = 0; i < sort_cnt; i++, sort_buf++)
  {
    if (i > depth) break;

    char *key = (char *) &sort_buf->key;

    switch (width)
    {
      case 1: printf ("i%X%c\n",
                pos + 0, key[0]
              );
              break;

      case 2: printf ("i%X%c i%X%c\n",
                pos + 0, key[0],
                pos + 1, key[1]
              );
              break;

      case 3: printf ("i%X%c i%X%c i%X%c\n",
                pos + 0, key[0],
                pos + 1, key[1],
                pos + 2, key[2]
              );
              break;
    }
  }
}

int main (int argc, char *argv[])
{
  if (argc != 6)
  {
    fprintf (stderr, "usage: %s dictionary depth width pos_min pos_max\n", argv[0]);

    return (-1);
  }

  const char *dictionary = argv[1];

  const int depth   = atoi (argv[2]);
  const int width   = atoi (argv[3]);
  const int pos_min = atoi (argv[4]);
  const int pos_max = atoi (argv[5]);

  if ((width < 1) || (width > 3))
  {
    fprintf (stderr, "invalid width\n");

    return (-1);
  }

  if ((pos_min < 1) || (pos_min > 15))
  {
    fprintf (stderr, "invalid pos_min\n");

    return (-1);
  }

  if ((pos_max < 1) || (pos_max > 15))
  {
    fprintf (stderr, "invalid pos_max\n");

    return (-1);
  }

  if ((width + pos_max - 1) > 15)
  {
    fprintf (stderr, "(width + pos_max - 1) > 15\n");

    return (-1);
  }

  /* who cares about RAM nowadays :-) */

  const size_t keys_size1 = KEYS_CNT1 * sizeof (uint32_t);
  const size_t keys_size2 = KEYS_CNT2 * sizeof (uint32_t);
  const size_t keys_size3 = KEYS_CNT3 * sizeof (uint32_t);

  uint32_t *keys_buf1 = (uint32_t *) malloc (keys_size1);
  uint32_t *keys_buf2 = (uint32_t *) malloc (keys_size2);
  uint32_t *keys_buf3 = (uint32_t *) malloc (keys_size3);

  int pos;

  for (pos = pos_min; pos < pos_max; pos++)
  {
    memset (keys_buf1, 0, keys_size1);
    memset (keys_buf2, 0, keys_size2);
    memset (keys_buf3, 0, keys_size3);

    FILE *fd = fopen (dictionary, "rb");

    if (fd == NULL)
    {
      fprintf (stderr, "%s: %s", dictionary, strerror (errno));

      free (keys_buf1);
      free (keys_buf2);
      free (keys_buf3);

      return (-1);
    }

    char line_buf[BUFSIZ];

    int line_len;

    while ((line_len = fgetl (fd, BUFSIZ, line_buf)) != -1)
    {
      if (line_len == 0) continue;

      unsigned char c = 0;

      uint32_t key = 0;

      if ((pos + 0) >= line_len) continue;

      c = line_buf[pos + 0];

      if (c < CHR_MIN) continue;
      if (c > CHR_MAX) continue;

      key |= c << 0;

      keys_buf1[key]++;

      if ((pos + 1) >= line_len) continue;

      c = line_buf[pos + 1];

      if (c < CHR_MIN) continue;
      if (c > CHR_MAX) continue;

      key |= c << 8;

      keys_buf2[key]++;

      if ((pos + 2) >= line_len) continue;

      c = line_buf[pos + 2];

      if (c < CHR_MIN) continue;
      if (c > CHR_MAX) continue;

      key |= c << 16;

      keys_buf3[key]++;
    }

    fclose (fd);

    const uint32_t sort_cnt1 = count_keys (keys_buf1, KEYS_CNT1);
    const uint32_t sort_cnt2 = count_keys (keys_buf2, KEYS_CNT2);
    const uint32_t sort_cnt3 = count_keys (keys_buf3, KEYS_CNT3);

    node *sort_buf1 = (node *) calloc (sort_cnt1, sizeof (node));
    node *sort_buf2 = (node *) calloc (sort_cnt2, sizeof (node));
    node *sort_buf3 = (node *) calloc (sort_cnt3, sizeof (node));

    move_keys (keys_buf1, KEYS_CNT1, sort_buf1);
    move_keys (keys_buf2, KEYS_CNT2, sort_buf2);
    move_keys (keys_buf3, KEYS_CNT3, sort_buf3);

    qsort (sort_buf1, sort_cnt1, sizeof (node), comp);
    qsort (sort_buf2, sort_cnt2, sizeof (node), comp);
    qsort (sort_buf3, sort_cnt3, sizeof (node), comp);

    if (width > 0) output_rule (sort_buf1, sort_cnt1, pos, 1, depth);
    if (width > 1) output_rule (sort_buf2, sort_cnt2, pos, 2, depth);
    if (width > 2) output_rule (sort_buf3, sort_cnt3, pos, 3, depth);

    free (sort_buf1);
    free (sort_buf2);
    free (sort_buf3);
  }

  free (keys_buf1);
  free (keys_buf2);
  free (keys_buf3);

  return 0;
}
