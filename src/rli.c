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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "utils.c"

#define STEPS 0x1000000

/**
 * Name........: rli
 * Autor.......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

typedef struct
{
  char *buf;

  uint len;
  uint pos;

} cache_t;

static int cmp_cache (const cache_t *c1, const cache_t *c2)
{
  return strcmp (c1->buf, c2->buf);
}

static int cmp_buf (const void *p1, const void *p2)
{
  cache_t *c1 = (cache_t *) p1;
  cache_t *c2 = (cache_t *) p2;

  return cmp_cache (c1, c2);
}

static int cmp_pos (const void *p1, const void *p2)
{
  cache_t *c1 = (cache_t *) p1;
  cache_t *c2 = (cache_t *) p2;

  return c1->pos - c2->pos;
}

int main (int argc, char *argv[])
{
  /* buffers */

  FILE *fd;

  uint avail = 0;
  uint count = 0;

  cache_t *cache = NULL;

  /* stats */

  uint removed = 0;

  /* arg */

  if (argc < 4)
  {
    fprintf (stderr, "usage: %s infile outfile removefiles...\n", argv[0]);

    return (-1);
  }

  char *infile  = argv[1];
  char *outfile = argv[2];

  /* cache */

  printf ("Caching %s...\n", infile);

  if ((fd = fopen (infile, "rb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", infile, strerror (errno));

    return (-1);
  }

  char line_buf[BUFSIZ];

  int line_len;

  while ((line_len = fgetl (fd, BUFSIZ, line_buf)) != -1)
  {
    if (count == avail)
    {
      avail += STEPS;

      cache = (cache_t *) realloc (cache, avail * sizeof (cache_t));

      if (cache == NULL)
      {
        fprintf (stderr, "Not enough memory\n");

        fclose (fd);

        return (-1);
      }

      memset (&cache[count], 0, STEPS * sizeof (cache_t));
    }

    char *new_buf = (char *) malloc (line_len + 1);

    if (new_buf == NULL)
    {
      fprintf (stderr, "Not enough memory\n");

      fclose (fd);

      return (-1);
    }

    memcpy (new_buf, line_buf, line_len);

    new_buf[line_len] = 0;

    cache[count].buf = new_buf;
    cache[count].len = line_len;
    cache[count].pos = count;

    if ((count > 0) && ((count % 1000000) == 0))
    {
      printf ("\rCached %u lines", count);

      fflush (stdout);
    }

    count++;
  }

  fclose (fd);

  printf ("\rCached %u lines\n", count);

  /* sort */

  printf ("\nSorting...\n\n");

  qsort (cache, count, sizeof (cache_t), cmp_buf);

  /* iterate through work */

  uint i;

  for (i = 3; i < (uint) argc; i++)
  {
    uint removed_sav = removed;

    char *removefile = argv[i];

    if (strcmp (removefile, infile) == 0)
    {
      fprintf (stderr, "Skipping check against infile %s\n\n", removefile);

      continue;
    }

    if (strcmp (removefile, outfile) == 0)
    {
      fprintf (stderr, "Skipping check against outfile %s\n\n", removefile);

      continue;
    }

    printf ("Checking %s against cache\n", removefile);

    if ((fd = fopen (removefile, "rb")) == NULL)
    {
      fprintf (stderr, "%s: %s\n", removefile, strerror (errno));

      return (-1);
    }

    uint target_count = 0;

    while ((line_len = fgetl (fd, BUFSIZ, line_buf)) != -1)
    {
      target_count++;

      if ((target_count % 1000000) == 0)
      {
        printf ("\rLines compared %u", target_count);

        fflush (stdout);
      }

      cache_t target;

      target.buf = line_buf;
      target.len = line_len;

      cache_t *found = (cache_t *) bsearch (&target, cache, count, sizeof (cache_t), cmp_buf);

      if (found == NULL) continue;

      /* already found before */

      if (found->len == 0) continue;

      found->len = 0;

      removed++;

      /* check possible duplicates */

      cache_t *min = &cache[0];
      cache_t *max = &cache[count - 1];

      cache_t *tmp;

      tmp = found;

      for (tmp--; tmp >= min; tmp--)
      {
        if (cmp_cache (tmp, &target)) break;

        tmp->len = 0;

        removed++;
      }

      tmp = found;

      for (tmp++; tmp <= max; tmp++)
      {
        if (cmp_cache (tmp, &target)) break;

        tmp->len = 0;

        removed++;
      }
    }

    fclose (fd);

    printf ("\rLines compared %u\n", target_count);

    printf ("Removed %u lines from cache\n\n", removed - removed_sav);
  }

  /* unsort */

  printf ("Sorting back to original positions...\n\n");

  qsort (cache, count, sizeof (cache_t), cmp_pos);

  /* save result */

  printf ("Finished!\n");

  printf ("Removed %u lines from cache\n", removed);

  printf ("Writing %u lines to %s\n", count - removed, outfile);

  if ((fd = fopen (outfile, "wb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", outfile, strerror (errno));

    return (-1);
  }

  for (i = 0; i < count; i++)
  {
    if (cache[i].len == 0) continue;

    fputs (cache[i].buf, fd);

    fputc ('\n', fd);
  }

  fclose (fd);

  return 0;
}
