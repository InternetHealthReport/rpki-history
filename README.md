# rpki-history

An API to query historical RPKI data

## Backup database

```bash
docker exec <db-container> pg_dump -Fc > backup.dump
```

## Restore database

Assumes database exists, but no schema/data.

```bash
docker exec -i <db-container> pg_restore -d rpki_history < backup.dump
```
