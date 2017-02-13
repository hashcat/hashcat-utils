typedef unsigned int uint;

size_t super_chop (char *s, size_t len)
{
  char *p = s + len - 1;

  while (len)
  {
    if (*p != '\n') break;

    *p-- = 0;

    len--;
  }

  while (len)
  {
    if (*p != '\r') break;

    *p-- = 0;

    len--;
  }

  return len;
}

int fgetl (FILE *stream, size_t sz, char *buf)
{
  if (feof (stream)) return -1;

  char *s = fgets (buf, sz, stream);

  if (s == NULL) return -1;

  size_t len = strlen (s);

  len = super_chop (s, len);

  return len;
}

#ifndef strdup
char *strdup (const char *s)
{
  char *b = malloc (strlen (s) + 1);

  strcpy (b, s);

  return (b);
}
#endif

#ifdef _WINDOWS

uint get_random_num (const uint min, const uint max)
{
  if (min == max) return (min);

  const uint low = max - min;

  if (low == 0) return (0);

  uint64_t r = rand () % low;

  r += min;

  if (r > 0xffffffff)
  {
    exit (-1);
  }

  return (uint) r;
}

#else

uint get_random_num (const uint min, const uint max)
{
  if (min == max) return (min);

  const uint low = max - min;

  if (low == 0) return (0);

  uint data;

  FILE *fp = fopen("/dev/urandom", "rb");

  if (fp == NULL) exit (1);

  if ((fread (&data, 1, sizeof (uint), fp)) != sizeof (uint))
  {
    exit (-1);
  }

  fclose (fp);

  uint64_t r = data % low;

  r += min;

  if (r > 0xffffffff)
  {
    exit (-1);
  }

  return (uint) r;
}

#endif
