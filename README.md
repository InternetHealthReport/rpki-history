# RPKI History

An API to query historical RPKI data, more specifically, Validated ROA Payloads (VRPs).

We obtain VRP data from the [RPKI Views](https://www.rpkiviews.org/) project (the
dango.attn.jp vantage point) and store it in a compact form for fast access. From each
dump we extract the `output/rpki-client.csv` file, which contains just the VRPs, and
update our database.

A VRP entry consists of five fields:

```csv
ASN,IP Prefix,Max Length,Trust Anchor,Expires
AS13335,1.0.0.0/24,24,apnic,1753280249
```

We ignore the expiry time and only work on dump-time granularity. For each ingested dump
we compare the set of VRPs (in form of `asn, prefix, max_length, trust_anchor`) with the
previous dump. Each VRP has a `visible` time range, during which is was continuously
visible. Since most VRPs are stable, this allows us to update just the time range,
keeping the database size compact.

Data limitations:

* **High-frequency updates are invisible.** Currently, dumps are created roughly
every 20 minutes. If a VRP expires / is removed and potentially recreated between dumps,
this will not be reflected in the database.

* **Data is at dump-time granularity.** If a VRP expires / is removed
between dumps, the exact point in time is lost. For example, if there are two dumps at
time `A` and `C`, a VRP expires at time `B` (`A < B < C`), and a user queries for
timestamp `D` (`A < D < B`) then the query will not find the VRP, since its visibility
ended at `A`.

* **Queryable time range is limited.** Naturally, we are limited by the amount of
available data. Trying queries outside of the available time range will result in an
error (to distinguish from non-existent VRPs).

## Endpoints

### `/vrp`

Parameters:

* `prefix`: The prefix for which to return covering VRPs.
* `timestamp` (optional): The timestamp (in `%Y-%m-%dT%H:%M:%S` [assumes UTC] or unix
epoch format) for which to check the status. If omitted, use the latest available dump
time.

Returns the list of covering VRPs for the specified prefix at the specified time, or at
the latest dump time if no timestamp is specified.

`visible` refers to the timespan (containing the specified timestamp) during which the
VRP was *continuously* visible, i.e., present in the dumps. Thus, if a VRP is missing
from a dump, a new entry with a separate `visible` range is created. **This time is
unrelated to the validity time (`Not before`/`Not after`) of the ROA!**

```json
// /vrp?prefix=8.8.8.0/24
[
  {
    "prefix": "8.8.8.0/24",
    "asn": 15169,
    "max_length": 24,
    "trust_anchor": "arin",
    "visible": {
      "from": "2025-07-18T02:05:56+00:00",
      "to": "2025-07-18T03:50:04+00:00"
    }
  }
]
```

### `/status`

Parameters:

* `prefix`: The prefix to be checked.
* `asn`: The origin ASN of the prefix.
* `timestamp` (optional): The timestamp (in `%Y-%m-%dT%H:%M:%S` [assumes UTC] or unix
epoch format) for which to check the status. If omitted, use the latest available dump
time.

Returns the RPKI status for the specified prefix/ASN combination at the specified time,
or at the latest dump time if no timestamp is specified.

`status` is one of `[Valid, Invalid, NotFound]`.

`reason` (only for `Invalid` status) gives more detailed information about why the
status is Invalid. `code` is for automatic processing, while `description` provides a
human-readable explanation.

```json
// /status?prefix=8.8.8.0/24&asn=15169
{
  "status": "Valid"
}

// /status?prefix=8.8.8.0/25&asn=15169
{
  "status": "Invalid",
  "reason": {
    "code": "moreSpecific",
    "description": "Covering VRP with matching origin ASN found, but queried, prefix is more specific than maxLength attribute allows."
  }
}
```

### `/metadata`

Parameters: None

Returns the list of dumps contained in the database.

`timestamp` refers to the dump time (taken from the filename).

`[deleted|updated|new]_vrps` indicates the number of VRPs differing from the previous
dump. Note that `deleted` refers to a VRP that was present in the previous dump, but not
in the current one.

```json
[
  {
    "timestamp": "2025-07-18T03:32:24+00:00",
    "deleted_vrps": 9,
    "updated_vrps": 723093,
    "new_vrps": 16
  },
  // ...
]
```

## Backup/restore database

### Backup

```bash
docker exec <db-container> pg_dump --data-only -Fc > backup.dump
```

### Restore

Assumes fresh install or that `postgres_data` volume was deleted.

```bash
# Reinitialize database to create schema *and additional user*.
docker compose run --rm init-db
# Restore data
docker exec -i <db-container> pg_restore -d rpki_history < backup.dump
```
