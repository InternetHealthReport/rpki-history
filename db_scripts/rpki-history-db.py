import argparse
import csv
import ipaddress
import logging
import os
import subprocess as sp
import sys
from collections import namedtuple
from datetime import datetime, timedelta, timezone

import psycopg
import psycopg.sql
import requests
from bs4 import BeautifulSoup
from psycopg.types.range import Range

vrp_tuple_fields = ['prefix', 'asn', 'max_length', 'trust_anchor']
VRP = namedtuple('VRP', vrp_tuple_fields)

URL_FMT = 'https://dango.attn.jp/rpkidata/%Y/%m/%d/'
FILE_FMT = 'rpki-%Y%m%dT%H%M%SZ.tgz'


class RPKIHistory:
    def __init__(self) -> None:
        self.db_host = os.environ['POSTGRES_HOST']
        self.db_dbname = os.environ['POSTGRES_DB']
        self.db_user = os.environ['POSTGRES_USER']
        with open('/run/secrets/postgres-pw', 'r') as f:
            self.db_password = f.read()
        # The URL of the newest file.
        self.new_file_url = str()
        # The content of the newest file (after download).
        self.new_file_content = bytes()
        # The datetime of the newest file.
        self.new_ts = None
        # The set of parsed VRPs from the newest file.
        self.new_vrps = set()
        # The datetime of the latest available data in the database.
        self.latest_ts = None
        # Map of VRP to (ID [database], visible time range [as psycopg Range]) tuple.
        self.latest_vrps = dict()

    def __enter__(self):
        self.conn = psycopg.connect(
            host=self.db_host,
            dbname=self.db_dbname,
            user=self.db_user,
            password=self.db_password
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self.conn.rollback()
        self.conn.close()

    @staticmethod
    def get_datetime_from_filename(fname: str) -> datetime:
        return datetime.strptime(fname, FILE_FMT).replace(tzinfo=timezone.utc)

    def get_new_file_url(self) -> None:
        """Get the URL of the newest available file."""
        curr_ts = datetime.now(tz=timezone.utc)
        folder_url = curr_ts.strftime(URL_FMT)
        r = requests.get(folder_url)
        # If we are just after midnight UTC, we should look at the previous day.
        if r.status_code == 404:
            curr_ts -= timedelta(hours=24)
            folder_url = curr_ts.strftime(URL_FMT)
            r = requests.get(folder_url)
            try:
                r.raise_for_status()
            except Exception as e:
                logging.error(f'Failed to get latest file: {e}')
                return

        soup = BeautifulSoup(r.text, features='html.parser')
        new_file = str()
        for link in soup.find_all('a'):
            href = link['href']
            if not href.startswith('rpki-'):
                continue

            file_ts = RPKIHistory.get_datetime_from_filename(href)
            if self.new_ts is None or file_ts > self.new_ts:
                self.new_ts = file_ts
                new_file = href

        if not new_file:
            logging.error(f'Failed to find valid file in folder: {folder_url}')
            return

        self.new_file_url = os.path.join(folder_url, new_file)

    def read_file(self) -> None:
        """Read the contents of the downloaded file and parse VRP entries."""
        logging.info('Reading file')
        base = os.path.basename(self.new_file_url).removesuffix('.tgz')
        member = f'{base}/output/rpki-client.csv'
        # Scripts runs in Alpine-based Docker container.
        ps = sp.run(['tar', 'x', '-z', '-O', '-f', '-', member],
                    input=self.new_file_content,
                    stdout=sp.PIPE,
                    check=True)

        for l in csv.DictReader(ps.stdout.decode().splitlines()):
            asn = int(l['ASN'].removeprefix('AS'))
            prefix = ipaddress.ip_network(l['IP Prefix'])
            trust_anchor = l['Trust Anchor']
            max_length = int(l['Max Length'])
            self.new_vrps.add(VRP(prefix, asn, max_length, trust_anchor))
        logging.info(f'Read {len(self.new_vrps)} unique VRPs from file')

    def fetch_and_read_file(self) -> None:
        """Download the file specified by new_file_url and parse its contents."""
        logging.info(f'Fetching file: {self.new_file_url}')
        r = requests.get(self.new_file_url)
        r.raise_for_status()
        self.new_file_content = r.content
        self.read_file()

    def fetch_and_read_new_file(self) -> bool:
        """Find the newest available file and process it if it is not already in the
        database.

        Return True if new data is available, False otherwise.
        """
        self.get_new_file_url()
        if not self.new_file_url or (self.latest_ts and self.new_ts <= self.latest_ts):
            return False
        self.fetch_and_read_file()
        return True

    def fetch_and_read_specific_file(self, ts: datetime) -> None:
        """Fetch and process the file with the specified timestamp."""
        self.new_ts = ts
        self.new_file_url = os.path.join(
            ts.strftime(URL_FMT),
            ts.strftime(FILE_FMT)
        )
        self.fetch_and_read_file()

    def init_db(self):
        """Initialize the database by creating the required tables and a read-only
        user.
        """
        db_ro_user = os.environ['POSTGRES_RO_USER']
        with open('/run/secrets/postgres-ro-pw', 'r') as f:
            db_ro_password = f.read()
        with self.conn.cursor() as c:
            c.execute("""
            CREATE TABLE IF NOT EXISTS vrps (
                id bigserial PRIMARY KEY,
                prefix cidr,
                asn bigint,
                max_length integer,
                trust_anchor text,
                visible tstzrange)
            """)
            c.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                id serial PRIMARY KEY,
                dump_time timestamp (0) with time zone,
                ingest_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
                deleted_vrps integer,
                updated_vrps integer,
                new_vrps integer)
            """)
            c.execute(psycopg.sql.SQL("""
            CREATE ROLE {}
            LOGIN
            PASSWORD {}
            """).format(
                psycopg.sql.Identifier(db_ro_user),
                psycopg.sql.Literal(db_ro_password)))
            c.execute("""
            GRANT SELECT ON vrps, metadata TO rpki_ro
            """)
        self.conn.commit()

    def get_latest_dump_ts(self, c: psycopg.Cursor) -> None:
        """Get the available dump time ranges from the database."""
        c.execute('SELECT dump_time FROM metadata ORDER BY dump_time DESC LIMIT 1')
        res = c.fetchone()
        if res is not None:
            self.latest_ts = res[0]
        logging.info(f'Latest dump timestamp: {self.latest_ts}')

    def rows_to_vrp(self, c: psycopg.Cursor) -> dict:
        """Transform the result set of the cursor to a map of VRP -> (id, visible)."""
        if c.description is None:
            return dict()
        # To be robust against changes in the database schema and/or reordering of
        # columns, use a index map.
        cn_idx = {column.name: idx for idx, column in enumerate(c.description)}
        return {
            VRP(
                *[e[cn_idx[column_name]]
                  for column_name in vrp_tuple_fields]
            ):
            (e[cn_idx['id']], e[cn_idx['visible']])
            for e in c.fetchall()
        }

    def get_latest_vrps(self, c: psycopg.Cursor) -> None:
        """Get the set of latest available VRPs from the database (if any)."""
        if self.latest_ts is None:
            return

        c.execute("""
            SELECT * FROM vrps
            WHERE visible @> %s
        """, (self.latest_ts, ))
        self.latest_vrps = self.rows_to_vrp(c)
        logging.info(f'Loaded {len(self.latest_vrps)} VRPs from database')

    def update_db(self, timestamp: datetime = None):
        """Update the database with data for the specified timestamp, or the newest data
        if available and no timestamp is specified.
        """
        with self.conn.cursor() as c:
            self.get_latest_dump_ts(c)

            # Fetch new VRPs.
            if timestamp:
                self.fetch_and_read_specific_file(timestamp)
            else:
                if not self.fetch_and_read_new_file():
                    logging.info('No new data available.')
                    return
            # Get latest VRPs from database.
            self.get_latest_vrps(c)

            # Compute differences.
            num_deleted_vrps = len(set(self.latest_vrps.keys()) - self.new_vrps)
            update_vrps = self.new_vrps.intersection(self.latest_vrps.keys())
            insert_vrps = self.new_vrps - self.latest_vrps.keys()

            # Insert metadata for this dump.
            c.execute("""
                INSERT INTO metadata (dump_time, deleted_vrps, updated_vrps, new_vrps)
                VALUES (%s, %s, %s, %s)
                """,
                      (self.new_ts, num_deleted_vrps, len(update_vrps), len(insert_vrps)))

            # Update visible ranges of existing VRPs.
            update_data = list()
            for vrp in update_vrps:
                vrp_id, visible_range = self.latest_vrps[vrp]
                update_data.append((Range(visible_range.lower, self.new_ts, bounds='[]'), vrp_id))
            logging.info(f'Updating {len(update_data)} VRPs')
            c.executemany("""
                UPDATE vrps
                SET visible = %s
                WHERE id = %s
            """, update_data)

            # Insert new VRPs.
            insert_data = [
                (vrp.prefix, vrp.asn, vrp.max_length, vrp.trust_anchor, Range(self.new_ts, self.new_ts, bounds='[]'))
                for vrp in insert_vrps
            ]
            logging.info(f'Inserting {len(insert_data)} new VRPs')
            c.executemany("""
                INSERT INTO vrps (prefix, asn, max_length, trust_anchor, visible)
                VALUES (%s, %s, %s, %s, %s)
            """, insert_data)
            self.conn.commit()


if __name__ == '__main__':
    handlers = [
        logging.StreamHandler(sys.stdout)
    ]
    if os.path.exists('/log'):
        handlers.append(logging.FileHandler('/log/rpki-history.log'))
    FORMAT = '%(asctime)s %(levelname)s %(message)s'
    logging.basicConfig(
        format=FORMAT,
        level=logging.INFO,
        handlers=handlers,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(f'Started: {sys.argv}')
    parser = argparse.ArgumentParser()
    parser.add_argument('command')
    parser.add_argument('-t', '--timestamp', help='fetch file for specific timestamp (YYYYMMDDThh:mm:ss)')
    args = parser.parse_args()
    rpki = RPKIHistory()
    command = args.command
    match command:
        case 'init':
            with rpki:
                rpki.init_db()
        case 'update':
            timestamp = None
            if args.timestamp:
                try:
                    timestamp = datetime.strptime(args.timestamp, '%Y%m%dT%H%M%S').replace(tzinfo=timezone.utc)
                except ValueError as e:
                    logging.error(f'Invalid timestamp specified: {args.timestamp} ({e})')
                    sys.exit(1)
            with rpki:
                rpki.update_db(timestamp)
        case _:
            logging.error(f'Invalid command specified: {command}')
            sys.exit(1)
    logging.info('Done')
    sys.exit(0)
