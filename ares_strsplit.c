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

char **ares_strsplit(const char *in, char delm, size_t *num_elm)
{
    char *parsestr;
    char **temp;
    char **out;
    size_t cnt;
    size_t nelms;
    size_t in_len;
    size_t i;

    if (in == NULL || num_elm == NULL)
        return NULL;
	*num_elm = 0;

    in_len = strlen(in);

	/* Figure out how many elements. */
    nelms = 1;
    for (i=0; i<in_len; i++)
    {
        if (in[i] == delm)
        {
            nelms++;
		}
    }

    /* Copy of input so we can cut it up. */
    parsestr = ares_malloc(in_len+1);
    memcpy(parsestr, in, in_len+1);
    parsestr[in_len] = '\0';

	/* Temporary array to store locations of start of each element
	 * within parsestr. */
    temp = ares_malloc(nelms * sizeof(*temp));
    temp[0] = parsestr;
    cnt = 1;
    for (i=0; i<in_len && cnt<nelms; i++)
    {
        if (parsestr[i] != delm)
            continue;

        /* Replace sep with NULL. */
        parsestr[i] = '\0';
        /* Add the pointer to the array of elements */
		temp[cnt] = parsestr+i+1;
		cnt++;
    }

	/* Find out how many actual elements (non-empty)
	 * we have. */
	*num_elm = 0;
    for (i=0; i<cnt; i++)
    {
    	if (temp[i] != '\0')
    		(*num_elm)++;
	}

	/* Check if there are actual elements. */
	if (*num_elm == 0)
	{
		free(parsestr);
		free(temp);
		return NULL;
	}

	/* Copy each element to our output array. */
    out = ares_malloc(*num_elm * sizeof(*out));
    nelms = 0;
    for (i=0; i<cnt; i++)
    {
    	if (temp[i] == '\0')
    		continue;
    	out[nelms] = ares_strdup(temp[i]);
    	nelms++;
	}

	free(parsestr);
	free(temp);
    return out;
}
