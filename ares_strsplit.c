/* Copyright (C) 2018 by John Schember <john@nachtimwald.com>
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "ares_setup.h"
#include "ares_strsplit.h"
#include "ares.h"
#include "ares_private.h"

static int list_contains(char * const *list, size_t num_elem, const char *str, int insensitive)
{
  size_t len;
  size_t i;

  len = strlen(str);
  for (i=0; i<num_elem; i++)
  {
    if (insensitive)
    {
#ifdef WIN32
      if (strnicmp(list[i], str, len) == 0)
#else
      if (strncasecmp(list[i], str, len) == 0)
#endif
        return 1;
    }
    else
    {
      if (strncmp(list[i], str, len) == 0)
        return 1;
    }
  }

  return 0;
}

static int is_delim(char c, const char *delims, size_t num_delims)
{
  size_t i;

  for (i=0; i<num_delims; i++)
  {
    if (c == delims[i])
      return 1;
  }
  return 0;
}

char **ares_strsplit(const char *in, const char *delms, int make_set, size_t *num_elm)
{
  char *parsestr;
  char **temp;
  char **out;
  size_t cnt;
  size_t nelms;
  size_t in_len;
  size_t num_delims;
  size_t i;

  if (in == NULL || delms == NULL || num_elm == NULL)
    return NULL;
  *num_elm = 0;

  in_len = strlen(in);
  num_delims = strlen(delms);

  /* Figure out how many elements. */
  nelms = 1;
  for (i=0; i<in_len; i++)
  {
    if (is_delim(in[i], delms, num_delims))
    {
      nelms++;
    }
  }

  /* Copy of input so we can cut it up. */
  parsestr = ares_strdup(in);
  if (parsestr == NULL)
    return NULL;

  /* Temporary array to store locations of start of each element
   * within parsestr. */
  temp = ares_malloc(nelms * sizeof(*temp));
  if (temp == NULL)
  {
    ares_free(parsestr);
    return NULL;
  }
  temp[0] = parsestr;
  cnt = 1;
  for (i=0; i<in_len && cnt<nelms; i++)
  {
    if (!is_delim(parsestr[i], delms, num_delims))
      continue;

    /* Replace sep with NULL. */
    parsestr[i] = '\0';
    /* Add the pointer to the array of elements */
    temp[cnt] = parsestr+i+1;
    cnt++;
  }

  /* Find out how many actual elements (non-empty)
   * we have. This is a maximum because if make_set
   * is enabled we could have fewer that can be added. */
  *num_elm = 0;
  for (i=0; i<cnt; i++)
  {
    if (temp[i][0] != '\0')
      (*num_elm)++;
  }

  /* Check if there are actual elements. */
  if (*num_elm == 0)
  {
    ares_free(parsestr);
    ares_free(temp);
    return NULL;
  }

  /* Copy each element to our output array. */
  out = ares_malloc(*num_elm * sizeof(*out));
  if (out == NULL)
  {
    ares_free(parsestr);
    ares_free(temp);
    return NULL;
  }
  nelms = 0;
  for (i=0; i<cnt; i++)
  {
    if (temp[i][0] == '\0')
      continue;

    if (make_set && list_contains(out, nelms, temp[i], 1))
      continue;

    out[nelms] = ares_strdup(temp[i]);
    if (out[nelms] == NULL)
    {
      ares_free(parsestr);
      ares_free(temp);
      return NULL;
    }
    nelms++;
  }
  /* Get the true number of elements if make_set. */
  *num_elm = nelms;

  /* If there are no elements don't return an empty allocated
   * array. */
  if (*num_elm == 0)
  {
    ares_free(out);
    out = NULL;
  }

  ares_free(parsestr);
  ares_free(temp);
  return out;
}
