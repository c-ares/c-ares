struct ares_hosts_file;
typedef struct ares_hosts_file ares_hosts_file_t;

struct ares_hosts_file {
  /*! iphash is the owner of the 'entry' object as there is only ever a single
   *  match to the object. */
  ares__hash_strvp_t *iphash;
  /*! hosthash does not own the entry so won't free on destruction */
  ares__hash_strvp_t *hosthash;
};

typedef struct {
  char          *ipaddr;
  ares__llist_t *hosts;
} ares_hosts_file_entry_t;


static ares_status_t ares__read_file_into_buf(const char *filename, ares__buf_t *buf)
{
  FILE          *fp      = NULL;
  unsigned char *ptr     = NULL;
  size_t         len     = 0;
  size_t         ptr_len = 0;
  ares_status_t  status;

  if (filename == NULL || buf == NULL)
    return ARES_EFORMERR;

  fp = fopen(file, "rb");
  if (fp == NULL) {
    error = ERRNO;
    switch (error) {
      case ENOENT:
      case ESRCH:
        status = ARES_ENOTFOUND;
        goto done;
      default:
        DEBUGF(fprintf(stderr, "fopen() failed with error: %d %s\n", error,
                       strerror(error)));
        DEBUGF(fprintf(stderr, "Error opening file: %s\n", filename));
        status = ARES_EFILE;
        goto done;
    }
  }

  /* Get length portably, fstat() is POSIX, not C */
  if (fseek(fp, 0, SEEK_END) != 0) {
    status = ARES_EFILE;
    goto done;
  }
  len = ftell(fp);
  if (fseek(fp, 0, SEEK_START) != 0) {
    status = ARES_EFILE;
    goto done;
  }

 if (len == 0) {
    status = ARES_SUCCESS;
    goto done;
  }

  /* Read entire data into buffer */
  ptr_len = len;
  ptr     = ares__buf_append_start(buf, &ptr_len);
  if (ptr == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  ptr_len = fread(ptr, 1, len, fp);
  if (ptr_len != len) {
    status = ARES_EFILE;
    goto done;
  }

  ares__buf_append_finish(buf, len);
  status = ARES_SUCCESS;

done:
  fclose(fp);
  return status;
}

static ares_bool_t ares__is_hostname(const char *str)
{
  for (i=0; hostname[i] != 0; i++) {
    if (!ares__is_hostnamech(hostname[i]))
      return ARES_FALSE;
  }
  return ARES_TRUE;
}


static ares_bool_t ares__normalize_ipaddr(const char *ipaddr, char *out,
                                          size_t out_len)
{
  struct in_addr       addr4;
  struct ares_in6_addr addr6;
  int                  family = AF_UNSPEC;

  if (ares_inet_pton(AF_INET, ipaddr, &addr4) > 0) {
    family = AF_INET;
  } else if (ares_net_pton(AF_INET6, ipaddr, &addr6) > 0) {
    family = AF_INET6;
  } else {
    return ARES_FALSE;
  }

  if (!ares_inet_ntop(family, family == AF_INET?&addr4:&addr6, out, out_len)) {
    return ARES_FALSE;
  }
}

static void ares__hosts_file_entry_destroy(ares_hosts_file_entry_t *entry)
{
  if (entry == NULL)
    return;

  ares__llist_destroy(entry->hosts);
  ares_free(entry->ipaddr);
  ares_free(entry);
}

static void ares__hosts_file_entry_destroy_cb(void *entry)
{
  return ares__host_file_entry_destroy(entry);
}

static void ares__hosts_file_destroy(ares_hosts_file_t *hf)
{
  if (hf == NULL)
    return;

  ares__htable_strvp_destroy(hf->hosthash);
  ares__htable_strvp_destroy(hf->iphash);
  ares_free(hf);
}

static ares_hosts_file_t *ares__hosts_file_create(void)
{
  ares_hosts_file_t *hf = ares_malloc_zero(sizeof(*hf));
  if (hf == NULL) {
    goto fail;
  }

  hf->iphash = ares__strvp_create(ares__hosts_file_entry_destroy_cb);
  if (hf->iphash == NULL) {
    goto fail;
  }

  hf->hosthash = ares__strvp_create(NULL);
  if (hf->hosthash == NULL) {
    goto fail;
  }

fail:
  ares__hosts_file_destroy(hf);
  return NULL;
}


/*! entry is invalidated upon calling this function, always, even on error */
static ares_status_t ares__hosts_file_add(ares_hosts_file_t *hosts,
                                          ares_hosts_file_entry_t *entry)
{
  ares_hosts_file_entry_t *existing;
  ares_status_t            status = ARES_SUCCESS;
  ares__llist_node_t      *node;

  existing = ares__htable_strvp_get_direct(hosts->iphash, entry->ipaddr);
  if (existing != NULL) {
    status = ares__hosts_file_merge_entry(existing, entry);
    if (status != ARES_SUCCESS) {
      ares__hosts_file_entry_destroy(entry);
      return status;
    }
    /* entry was invalidated above by merging */
    entry = existing;
  } else {
    status = ares__htable_strvp_insert(hosts->iphash, entry->ipaddr, entry);
    if (status != ARES_SUCCESS) {
      ares__hosts_file_entry_destroy(entry);
      return status;
    }
  }

  for (node = ares__llist_node_first(entry->hosts); node != NULL;
       node = ares__llist_node_next(node)) {
    const char *val = ares__llist_node_val(node);

    /* First match wins, if its already there, skip */
    if (ares__htable_strvp_get(hosts->hosthash, val))
      continue;

    status = ares__htable_strvp_insert(hosts->hosthash, val, entry);
    if (status != ARES_SUCCESS) {
      return status;
    }
  }

  return ARES_SUCCESS;
}

static ares_status_t ares__parse_hosts_hostnames(ares__buf_t *buf,
                                                 ares_hosts_file_entry_t *entry)
{
  entry->hosts = ares__llist_create(ares_free);
  if (entry->hosts == NULL)
    return ARES_ENOMEM;

  /* Parse hostnames and aliases */
  while (ares__buf_len(buf)) {
    char   hostname[256];
    char  *temp;

    ares__buf_consume_whitespace(buf, ARES_FALSE);

    if (ares__buf_len(buf) == 0)
      break;

    /* See if it is a comment, if so stop processing */
    if (ares__buf_begins_with(buf, "#", 1)) {
      break;
    }

    ares__buf_tag(buf);

    /* Must be at end of line */
    if (ares__buf_consume_nonwhitespace(buf) == 0)
      break;

    status = ares__buf_tag_fetch_string(buf, hostname, sizeof(hostname));
    if (status != ARES_SUCCESS) {
      /* Bad entry, just ignore as long as its not the first.  If its the first,
       * it must be valid */
      if (ares__llist_len(entry->hosts) == 0)
        return ARES_EBADSTR;

      continue;
    }

    /* Validate it is a valid hostname characterset */
    if (!ares__is_hostname(hostname))
      continue;

    /* Add to list */
    temp = ares_strdup(hostname);
    if (temp == NULL)
      return ARES_ENOMEM;

    if (ares__llist_insert_last(entry->hosts, temp) == NULL) {
      ares_free(temp);
      return ARES_ENOMEM;
    }
  }

  /* Must have at least 1 entry */
  if (ares__llist_len(entry->hosts) == 0)
    return ARES_EBADSTR;

  return ARES_SUCCESS;
}


static ares_status_t ares__parse_hosts(const char *filename)
{
  ares__buf_t       *buf     = NULL;
  ares_status_t      status  = ARES_EBADRESP;
  ares_hosts_file_t *hf      = NULL;

  buf     = ares__buf_create();
  if (buf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  status = ares__read_file_into_buf(filename, buf);
  if (status != ARES_SUCCESS)
    goto done;

  hf = ares__hosts_file_create();
  if (hf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  while (ares__buf_len(buf)) {
    char                     addr[INET6_ADDRSTRLEN];
    ares_hosts_file_entry_t *entry = NULL;

    /* -- Start of new line here -- */

    /* Consume any leading whitespace */
    ares__buf_consume_whitespace(buf, ARES_FALSE);

    if (ares__buf_len(buf) == 0)
      break;

    /* See if it is a comment, if so, consume remaining line */
    if (ares__buf_begins_with(buf, "#", 1)) {
      ares__buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Pull off ip address */
    ares__buf_tag(buf);
    ares__buf_consume_nonwhitespace(buf);
    status = ares__buf_tag_fetch_string(buf, addr, sizeof(addr));
    if (status != ARES_SUCCESS) {
      /* Bad line, consume and go onto next */
      ares__buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Validate and normalize the ip address format */
    if (!ares__normalize_ipaddr(addr, addr, sizeof(addr))) {
      /* Bad line, consume and go onto next */
      ares__buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    entry = ares_malloc_zero(sizeof(*entry));
    if (entry == NULL) {
      status = ARES_ENOMEM;
      goto done;
    }

    entry->ipaddr = ares_strdup(addr);
    if (entry->ipaddr == NULL) {
      status = ARES_ENOMEM;
      goto done;
    }

    status = ares__parse_hosts_hostnames(buf, entry);
    if (status == ARES_ENOMEM) {
      ares__hosts_file_entry_destroy(entry);
      goto done;
    } else if (status != ARES_SUCCESS) {
      /* Bad line, consume and go onto next */
      ares__hosts_file_entry_destroy(entry);
      ares__buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    status = ares__hosts_file_add(hf, entry);
    entry  = NULL; /* is always invalidated by this function, even on error */
    if (status != ARES_SUCCESS) {
      goto done;
    }

    /* Go to next line */
    ares__buf_consume_line(buf, ARES_TRUE);
  }

done:
  fclose(fp);
  ares__buf_destroy(buf);
  if (status != ARES_SUCCESS) {
    ares__hosts_file_destroy(hf);
  }
  return status;
}
