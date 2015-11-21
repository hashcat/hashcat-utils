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

uint get_random_num (const uint min, const uint max)
{
  if (min == max) return (min);

  return ((rand () % (max - min)) + min);
}
