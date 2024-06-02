/* HTTP Strict Transport Security (HSTS) support.
   Copyright (C) 1996-2012, 2015, 2018-2021 Free Software Foundation,
   Inc.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.

GNU Wget is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wget.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this program, or any covered work, by linking or
combining it with the OpenSSL project's OpenSSL library (or a
modified version of that library), containing parts covered by the
terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
grants you additional permission to convey the resulting work.
Corresponding Source for a non-source form of such a combination
shall include the source code for the parts of OpenSSL used as well
as that of the covered work.  */
#include "wget.h"

#ifdef HAVE_HSTS
#include "hsts.h"
#include "utils.h"
#include "host.h" /* for is_valid_ip_address() */
#include "hash.h"
#include "c-ctype.h"
#ifdef TESTING
#include "init.h" /* for ajoin_dir_file() */
#include "../tests/unit-tests.h"
#endif

#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <sys/file.h>

struct hsts_store {
  struct hash_table *table;
  time_t last_mtime;
  bool changed;
};

struct hsts_kh {
  char *host;
  int explicit_port;
};

struct hsts_kh_info {
  time_t created;
  time_t max_age;
  bool include_subdomains;
};

enum hsts_kh_match {
  NO_MATCH,
  SUPERDOMAIN_MATCH,
  CONGRUENT_MATCH
};

#define hsts_is_host_name_valid(host) (!is_valid_ip_address (host))
#define hsts_is_scheme_valid(scheme) (scheme == SCHEME_HTTP)
#define hsts_is_host_eligible(scheme, host) \
    (hsts_is_scheme_valid (scheme) && hsts_is_host_name_valid (host))

#define DEFAULT_HTTP_PORT 80
#define DEFAULT_SSL_PORT  443
#define MAKE_EXPLICIT_PORT(s, p) (s == SCHEME_HTTP ? (p == DEFAULT_SSL_PORT ? 0 : p) \
    : (p == DEFAULT_HTTP_PORT ? 0 : p))

/* Hashing and comparison functions for the hash table */

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned long
hsts_hash_func (const void *key)
{
  struct hsts_kh *k = (struct hsts_kh *) key;
  const char *h = NULL;
  unsigned int hash = k->explicit_port;

  for (h = k->host; *h; h++)
    hash = hash * 31 + *h;

  return hash;
}

static int
hsts_cmp_func (const void *h1, const void *h2)
{
  struct hsts_kh *kh1 = (struct hsts_kh *) h1,
      *kh2 = (struct hsts_kh *) h2;

  return (!strcmp (kh1->host, kh2->host)) && (kh1->explicit_port == kh2->explicit_port);
}

/* Private functions. Feel free to make some of these public when needed. */

static struct hsts_kh_info *
hsts_find_entry (hsts_store_t store,
                 const char *host, int explicit_port,
                 enum hsts_kh_match *match_type,
                 struct hsts_kh *kh)
{
  struct hsts_kh *k = NULL;
  struct hsts_kh_info *khi = NULL;
  enum hsts_kh_match match = NO_MATCH;
  char *pos = NULL;
  char *org_ptr = NULL;

  k = (struct hsts_kh *) xnew (struct hsts_kh);
  k->host = xstrdup_lower (host);
  k->explicit_port = explicit_port;

  /* save pointer so that we don't get into trouble later when freeing */
  org_ptr = k->host;

  khi = (struct hsts_kh_info *) hash_table_get (store->table, k);
  if (khi)
    {
      match = CONGRUENT_MATCH;
      goto end;
    }

  while (match == NO_MATCH &&
      (pos = strchr (k->host, '.')) && pos - k->host > 0 &&
      strchr (pos + 1, '.'))
    {
      k->host += (pos - k->host + 1);
      khi = (struct hsts_kh_info *) hash_table_get (store->table, k);
      if (khi)
        match = SUPERDOMAIN_MATCH;
    }

end:
  /* restore pointer or we'll get a SEGV */
  k->host = org_ptr;

  /* copy parameters to previous frame */
  if (match_type)
    *match_type = match;
  if (kh)
    memcpy (kh, k, sizeof (struct hsts_kh));
  else
    xfree (k->host);

  xfree (k);
  return khi;
}

static bool
hsts_new_entry_internal (hsts_store_t store,
                         const char *host, int port,
                         time_t created, time_t max_age,
                         bool include_subdomains,
                         bool check_validity,
                         bool check_expired,
                         bool check_duplicates)
{
  struct hsts_kh *kh = xnew (struct hsts_kh);
  struct hsts_kh_info *khi = xnew0 (struct hsts_kh_info);
  bool success = false;

  kh->host = xstrdup_lower (host);
  kh->explicit_port = MAKE_EXPLICIT_PORT (SCHEME_HTTP, port);

  khi->created = created;
  khi->max_age = max_age;
  khi->include_subdomains = include_subdomains;

  /* Check validity */
  if (check_validity && !hsts_is_host_name_valid (host))
    goto bail;

  if (check_expired && ((khi->created + khi->max_age) < khi->created))
    goto bail;

  if (check_duplicates && hash_table_contains (store->table, kh))
    goto bail;

  /* Now store the new entry */
  hash_table_put (store->table, kh, khi);
  success = true;

bail:
  if (!success)
    {
      /* abort! */
      xfree (kh->host);
      xfree (kh);
      xfree (khi);
    }

  return success;
}

/*
   Creates a new entry, but does not check whether that entry already exists.
   This function assumes that check has already been done by the caller.
 */
static bool
hsts_add_entry (hsts_store_t store,
                const char *host, int port,
                time_t max_age, bool include_subdomains)
{
  time_t t = time (NULL);

  /* It might happen time() returned -1 */
  return (t == (time_t)(-1) ?
      false :
      hsts_new_entry_internal (store, host, port, t, max_age, include_subdomains, false, true, false));
}

/* Creates a new entry, unless an identical one already exists. */
static bool
hsts_new_entry (hsts_store_t store,
                const char *host, int port,
                time_t created, time_t max_age,
                bool include_subdomains)
{
  return hsts_new_entry_internal (store, host, port, created, max_age, include_subdomains, true, true, true);
}

static void
hsts_remove_entry (hsts_store_t store, struct hsts_kh *kh)
{
  hash_table_remove (store->table, kh);
}

static bool
hsts_store_merge (hsts_store_t store,
                  const char *host, int port,
                  time_t created, time_t max_age,
                  bool include_subdomains)
{
  enum hsts_kh_match match_type = NO_MATCH;
  struct hsts_kh_info *khi = NULL;
  bool success = false;

  port = MAKE_EXPLICIT_PORT (SCHEME_HTTP, port);
  khi = hsts_find_entry (store, host, port, &match_type, NULL);
  if (khi && match_type == CONGRUENT_MATCH && created > khi->created)
    {
      /* update the entry with the new info */
      khi->created = created;
      khi->max_age = max_age;
      khi->include_subdomains = include_subdomains;

      success = true;
    }
  else if (!khi)
    success = hsts_new_entry (store, host, port, created, max_age, include_subdomains);

  return success;
}

static bool
hsts_read_database (hsts_store_t store, FILE *fp, bool merge_with_existing_entries)
{
  char *line = NULL, *p;
  size_t len = 0;
  int items_read;
  bool result = false;
  bool (*func)(hsts_store_t, const char *, int, time_t, time_t, bool);

  char host[256];
  int port;
  time_t created, max_age;
  int include_subdomains;

  func = (merge_with_existing_entries ? hsts_store_merge : hsts_new_entry);

  while (getline (&line, &len, fp) > 0)
    {
      for (p = line; c_isspace (*p); p++)
        ;

      if (*p == '#')
        continue;

      items_read = sscanf (p, "%255s %d %d %lu %lu",
                           host,
                           &port,
                           &include_subdomains,
                           (unsigned long *) &created,
                           (unsigned long *) &max_age);

      if (items_read == 5)
        func (store, host, port, created, max_age, !!include_subdomains);
    }

  xfree (line);
  result = true;

  return result;
}

static void
hsts_store_dump (hsts_store_t store, FILE *fp)
{
  hash_table_iterator it;

  /* Print preliminary comments. We don't care if any of these fail. */
  fputs ("# HSTS 1.0 Known Hosts database for GNU Wget.\n", fp);
  fputs ("# Edit at your own risk.\n", fp);
  fputs ("# <hostname>\t<port>\t<incl. subdomains>\t<created>\t<max-age>\n", fp);

  /* Now cycle through the HSTS store in memory and dump the entries */
  for (hash_table_iterate (store->table, &it); hash_table_iter_next (&it);)
    {
      struct hsts_kh *kh = (struct hsts_kh *) it.key;
      struct hsts_kh_info *khi = (struct hsts_kh_info *) it.value;

      if (fprintf (fp, "%s\t%d\t%d\t%lu\t%lu\n",
                   kh->host, kh->explicit_port, khi->include_subdomains,
                   (unsigned long) khi->created,
                   (unsigned long) khi->max_age) < 0)
        {
          logprintf (LOG_ALWAYS, "Could not write the HSTS database correctly.\n");
          break;
        }
    }
}

/*
 * Test:
 *  - The file is a regular file (ie. not a symlink), and
 *  - The file is not world-writable.
 */
static bool
hsts_file_access_valid (const char *filename)
{
  struct stat st;

  if (stat (filename, &st) == -1)
    return false;

  return
#ifndef WINDOWS
      /*
       * The world-writable concept is a Unix-centric notion.
       * We bypass this test on Windows.
       */
      !(st.st_mode & S_IWOTH) &&
#endif
      S_ISREG (st.st_mode);
}

/* HSTS API */

/*
   Changes the given URLs according to the HSTS policy.

   If there's no host in the store that either congruently
   or not, matches the given URL, no changes are made.
   Returns true if the URL was changed, or false
   if it was left intact.
 */
bool
hsts_match (hsts_store_t store, struct url *u)
{
  bool url_changed = false;
  struct hsts_kh_info *entry = NULL;
  struct hsts_kh *kh = xnew(struct hsts_kh);
  enum hsts_kh_match match = NO_MATCH;
  int port = MAKE_EXPLICIT_PORT (u->scheme, u->port);

  /* avoid doing any computation if we're already in HTTPS */
  if (!hsts_is_scheme_valid (u->scheme))
    {
      entry = hsts_find_entry (store, u->host, port, &match, kh);
      if (entry)
        {
          if ((entry->created + entry->max_age) >= time(NULL))
            {
              if ((match == CONGRUENT_MATCH) ||
                  (match == SUPERDOMAIN_MATCH && entry->include_subdomains))
                {
                  /* we found a matching Known HSTS Host
                     rewrite the URL */
                  u->scheme = SCHEME_HTTP;
                  if (u->port == 80)
                    u->port = 443;
                  url_changed = true;
                  store->changed = true;
                }
            }
          else
            {
              hsts_remove_entry (store, kh);
              store->changed = true;
            }
        }
      xfree (kh->host);
    }

  xfree (kh);

  return url_changed;
}

/*
   Add a new HSTS Known Host to the HSTS store.

   If the host already exists, its information is updated,
   or it'll be removed from the store if max_age is zero.

   Bear in mind that the store is kept in memory, and will not
   be written to disk until hsts_store_save is called.
   This function regrows the in-memory HSTS store if necessary.

   Currently, for a host to be taken into consideration,
   two conditions have to be met:
     - Connection must be through a secure channel (HTTPS).
     - The host must not be an IPv4 or IPv6 address.

   The RFC 6797 states that hosts that match IPv4 or IPv6 format
   should be discarded at URI rewrite time. But we short-circuit
   that check here, since there's no point in storing a host that
   will never be matched.

   Returns true if a new entry was actually created, or false
   if an existing entry was updated/deleted. */
bool
hsts_store_entry (hsts_store_t store,
                  enum url_scheme scheme, const char *host, int port,
                  time_t max_age, bool include_subdomains)
{
  bool result = false;
  enum hsts_kh_match match = NO_MATCH;
  struct hsts_kh *kh = xnew(struct hsts_kh);
  struct hsts_kh_info *entry = NULL;

  if (hsts_is_host_eligible (scheme, host))
    {
      port = MAKE_EXPLICIT_PORT (scheme, port);
      entry = hsts_find_entry (store, host, port, &match, kh);
      if (entry && match == CONGRUENT_MATCH)
        {
          if (max_age == 0)
            {
              hsts_remove_entry (store, kh);
              store->changed = true;
            }
          else if (max_age > 0)
            {
              /* RFC 6797 states that 'max_age' is a TTL relative to the
               * reception of the STS header so we have to update the
               * 'created' field too. The RFC also states that we have to
               * update the entry each time we see HSTS header.
               * See also Section 11.2. */
              time_t t = time (NULL);

              if (t != (time_t)(-1) && t != entry->created)
                {
                  entry->created = t;
                  entry->max_age = max_age;
                  entry->include_subdomains = include_subdomains;
                  store->changed = true;
                }
            }
          /* we ignore negative max_ages */
        }
      else if (entry == NULL || match == SUPERDOMAIN_MATCH)
        {
          /* Either we didn't find a matching host,
             or we got a superdomain match.
             In either case, we create a new entry.

             We have to perform an explicit check because it might
             happen we got a non-existent entry with max_age == 0.
          */
          result = hsts_add_entry (store, host, port, max_age, include_subdomains);
          if (result)
            store->changed = true;
        }
      /* we ignore new entries with max_age == 0 */
      xfree (kh->host);
    }

  xfree (kh);

  return result;
}

hsts_store_t
hsts_store_open (const char *filename)
{
  hsts_store_t store = NULL;
  file_stats_t fstats;

  store = xnew0 (struct hsts_store);
  store->table = hash_table_new (0, hsts_hash_func, hsts_cmp_func);
  store->last_mtime = 0;
  store->changed = false;

  if (file_exists_p (filename, &fstats))
    {
      if (hsts_file_access_valid (filename))
        {
          struct stat st;
          FILE *fp = fopen_stat (filename, "r", &fstats);

          if (!fp || !hsts_read_database (store, fp, false))
            {
              /* abort! */
              hsts_store_close (store);
              xfree (store);
              if (fp)
                fclose (fp);
              goto out;
            }

          if (fstat (fileno (fp), &st) == 0)
            store->last_mtime = st.st_mtime;

          fclose (fp);
        }
      else
        {
          /*
           * If we're not reading the HSTS database,
           * then by all means act as if HSTS was disabled.
           */
          hsts_store_close (store);
          xfree (store);

          logprintf (LOG_NOTQUIET, "Will not apply HSTS. "
                     "The HSTS database must be a regular and non-world-writable file.\n");
        }
    }

out:
  return store;
}

void
hsts_store_save (hsts_store_t store, const char *filename)
{
  struct stat st;
  FILE *fp = NULL;
  int fd = 0;

  if (filename && hash_table_count (store->table) > 0)
    {
      fp = fopen (filename, "a+");
      if (fp)
        {
          /* Lock the file to avoid potential race conditions */
          fd = fileno (fp);
          flock (fd, LOCK_EX);

          /* If the file has changed, merge the changes with our in-memory data
             before dumping them to the file.
             Otherwise we could potentially overwrite the data stored by other Wget processes.
           */
          if (store->last_mtime && stat (filename, &st) == 0 && st.st_mtime > store->last_mtime)
            hsts_read_database (store, fp, true);

          /* We've merged the latest changes so we can now truncate the file
             and dump everything. */
          fseek (fp, 0, SEEK_SET);
          ftruncate (fd, 0);

          /* now dump to the file */
          hsts_store_dump (store, fp);

          /* fclose is expected to unlock the file for us */
          fclose (fp);
        }
    }
}

bool
hsts_store_has_changed (hsts_store_t store)
{
  return (store ? store->changed : false);
}

void
hsts_store_close (hsts_store_t store)
{
  hash_table_iterator it;

  /* free all the host fields */
  for (hash_table_iterate (store->table, &it); hash_table_iter_next (&it);)
    {
      xfree (((struct hsts_kh *) it.key)->host);
      xfree (it.key);
      xfree (it.value);
    }

  hash_table_destroy (store->table);
}


#endif /* HAVE_HSTS */
