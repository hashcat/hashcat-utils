#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

/**
 * Name........: Combined-Power Utility
 * Autor.......: Unix-Ninja
 */

/*
 * This utility is meant to created "unique combinations" of a given input file's lines.
 * Please note, this will NOT create permutations of the input.
 *
 */

typedef uint32_t bool;
typedef uint32_t u32;
typedef uint64_t u64;

#define false 0
#define true 1
#define LINE_SIZE 64
#define LINE_LIMIT 15 + 1  /* we add one to the limit for the null terminator */
#define MAX_LINES 63       /* this is the limit of using a single unsigned 64-bit integer */
                           /* exceeding this count will cause the counters to wrap */

int usage (char *progname)
{
  fprintf (stderr, "%s - utility to create \"unique combinations\" of given input\n", progname);
  fprintf (stderr, "\n");
  fprintf (stderr, "Usage: %s [options] file1\n", progname);
  fprintf (stderr, "\n");
  fprintf (stderr, "  Please note, you can not use more then 64 lines of input for this utility. In\n");
  fprintf (stderr, "  all honesty, you don't want to. 64 lines would generate approximately 187 EB\n");
  fprintf (stderr, "  (or 187,660,921,384 GB) worth of data (supposing each line was about 1 byte).\n");
  fprintf (stderr, "  If you are trying to generate that much data, you're probably doing it wrong.\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "=======\n");
  fprintf (stderr, "Options\n");
  fprintf (stderr, "=======\n");
  fprintf (stderr, "\n");
  fprintf (stderr, "    -h      display this message\n");
  fprintf (stderr, "    -s      use space separator in output\n");
  fprintf (stderr, "    -l      limit lines to 15 chars (useful for hashcat rules)\n");
  return (-1);
}

int main (int argc, char *argv[])
{
  bool op_space = false;
  bool op_limit = false;
  char *f1, *f2;

  f1 = f2 = "\0";
  u64 i;
  u32 lines;

  char *progname = argv[0];

  for (i = 1; i < (u64) argc; i++)
  {
    if (*(argv[i] + 0) == '-')
    {
      if (!strcmp (argv[i], "-h"))
      {
        return usage (progname);
      }
      else if (!strcmp (argv[i], "-l"))
      {
        op_limit = true;
      }
      else if (!strcmp (argv[i], "-s"))
      {
        op_space = true;
      }
    }
    else if (!strcmp (f1, "\0"))
    {
      f1 = argv[i];
    }
    else
    {
      return usage (progname);
    }
  }

  if (!strcmp (f1, "\0"))
  {
    return usage (progname);
  }

  FILE *fd1;

  if ((fd1 = fopen (f1, "rb")) == NULL)
  {
    fprintf (stderr, "%s: %s\n", f1, strerror (errno));
    return (-1);
  }

  lines = 0;
  char line[LINE_SIZE];

  while (fgets (line, LINE_SIZE, fd1))
  {
    if (strlen (line) > LINE_LIMIT && op_limit)
    {
      fprintf (stderr, "Line length exceeded in input. Skipping...\n");
      continue;
    }
    lines++;
  }

  rewind (fd1);

  /* we can't exceed the max line count. err if we do. */
  if (lines > MAX_LINES)
  {
    fprintf (stderr, "You can not exceed %d lines in your input file! Unable to continue.\n", MAX_LINES);
    return (-1);
  }

  /* allocate mem for buffer and check for success */
  char **buf = calloc (lines, sizeof (char *));

  if (buf == NULL)
  {
    fprintf (stderr, "Unable to allocate memory!");
    return (-1);
  }

  i = 0;

  while (fgets (line, LINE_SIZE, fd1))
  {
    /* skip empty lines and remove them from line count */
    if (line[0] == '\r' || line[0] == '\n')
    {
      lines--;
      continue;
    }
    /* skip long lines */
    if (strlen (line) > LINE_LIMIT && op_limit)
    {
      continue;
    }

    u32 length = strlen (line);

    // copy line...
    // but without newline char(s)
    if (line[length - 2] == '\r') length--;

    buf[i] = calloc (length, sizeof (char));

    if (buf[i] == NULL)
    {
      fprintf (stderr, "Unable to allocate memory!");
      return (-1);
    }

    strncpy ((char *) buf[i], line, length - 1);

    i++;
  }

  fclose (fd1);

  /* printf ("%d lines found.\n", lines); */

  /* find combinations */
  u64 j;
  u32 pad_size = op_limit ? 1 : 0;

  bool pad;
  char lb[LINE_LIMIT];

  for (i = 1; i < (((u64) 1u) << lines); i++)
  {
    pad = false;
    memset (lb, '\0', LINE_LIMIT);  /* initialize the line buffer */

    for (j = 0; j < lines; j++)
    {
      if (i & (((u64) 1u) << j))
      {
        if (op_limit)
        {
          if ((strlen ((char *) buf[j]) + strlen (lb) + pad_size) > (LINE_LIMIT - 1))
          {
            fprintf (stderr, "Line length exceeded in output. Skipping...\n");
            continue;
          }

          if (op_space && pad) strcat (lb, " ");

          strcat (lb, (char *) buf[j]);
        }
        else
        {
          if (op_space && pad) printf (" ");

          printf ("%s", (char *) buf[j]);
        }
        pad = true;
      }
    }

    /* print buffer if not empty */

    if (strlen (lb))
    {
      printf ("%s", lb);
    }

    printf ("\n");
  }

  return 0;
}
