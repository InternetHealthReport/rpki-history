import ipaddress
import os
from datetime import datetime, timezone
from typing import Tuple

import falcon
import psycopg

db_host = os.environ['POSTGRES_HOST']
db_dbname = os.environ['POSTGRES_DB']
db_user = os.environ['POSTGRES_RO_USER']
with open('/run/secrets/postgres-ro-pw', 'r') as f:
    db_password = f.read()

# These are the column names which should be retrieved from the database.
vrp_dict_fields = ['prefix', 'asn', 'max_length', 'trust_anchor', 'visible']


def rows_to_vrp(c: psycopg.Cursor) -> list:
    """Convert the rows from the current result set of the cursor to a list of VRPs.

    Each VRP is in a dictionary containing fields specified by vrp_dict_fields.
    """
    if c.description is None:
        return list()
    # To be robust against changes in the database schema and/or reordering of columns,
    # use a index map.
    cn_idx = {column.name: idx for idx, column in enumerate(c.description)}
    ret = [{k: row[cn_idx[k]] for k in vrp_dict_fields} for row in c.fetchall()]
    return ret


def get_covering_vrps_for_prefix_at_time(c: psycopg.Cursor, prefix, timestamp: datetime) -> list:
    c.execute("""
        SELECT * FROM vrps
        WHERE prefix >>= %s
        AND visible @> %s
    """, (prefix, timestamp))
    return rows_to_vrp(c)


def get_rpki_status(c: psycopg.Cursor, prefix, timestamp: datetime, asn: int) -> dict:
    """Infer the RPKI status for the specified prefix/origin ASN combination at the
    specified timestamp.

    Return the result as a dictionary, ready for serialization.

    See: https://www.rfc-editor.org/rfc/rfc6811#section-2.1
    """
    vrps = get_covering_vrps_for_prefix_at_time(c, prefix, timestamp)
    if not vrps:
        return {'status': 'NotFound'}
    same_origin_asn_found = False
    for vrp in vrps:
        if vrp['asn'] == 0 or vrp['asn'] != asn:
            continue
        same_origin_asn_found = True
        if prefix.prefixlen <= vrp['max_length']:
            return {'status': 'Valid'}
    if same_origin_asn_found:
        return {
            'status': 'Invalid',
            'reason': {
                'code': 'moreSpecific',
                'description': 'Covering VRP with matching origin ASN found, but queried prefix is more specific '''
                'than maxLength attribute allows.'
            }
        }
    return {
        'status': 'Invalid',
        'reason': {
            'code': 'noMatchingOrigin',
            'description': 'No covering VRP with matching origin ASN found.'
        }
    }


def get_available_dump_time_range(c: psycopg.Cursor) -> Tuple[datetime, datetime] | Tuple[None, None]:
    """Get the latest dump time as datetime from the database."""
    c.execute('SELECT dump_time FROM metadata ORDER BY dump_time ASC LIMIT 1')
    res = c.fetchone()
    if res is None:
        return None, None
    earliest = res[0]
    c.execute('SELECT dump_time FROM metadata ORDER BY dump_time DESC LIMIT 1')
    res = c.fetchone()
    latest = res[0]
    return earliest, latest


def parse_timestamp(timestamp: str) -> datetime:
    """Parse a timestamp either in %Y-%m-%dT%H:%M:%S or unix epoch format and return the
    corresponding datetime.
    """
    try:
        return datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    try:
        return datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
    except ValueError:
        raise falcon.HTTPInvalidParam('Timestamp has to be in epoch or %Y-%m-%dT%H:%M:%S format.', 'timestamp')


class VRPResource:
    def __init__(self) -> None:
        self.conn = psycopg.connect(
            host=db_host,
            dbname=db_dbname,
            user=db_user,
            password=db_password
        )

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Return all covering VRPs for the requested prefix at the specified timestamp.

        If no timestamp is specified, return data for the latest available dump in the
        database.
        """
        if not req.has_param('prefix'):
            raise falcon.HTTPMissingParam('prefix')

        try:
            parsed_prefix = ipaddress.ip_network(req.get_param('prefix', required=True))
        except ValueError as e:
            raise falcon.HTTPInvalidParam(str(e), 'prefix')

        with self.conn.cursor() as c:
            earliest, latest = get_available_dump_time_range(c)
            if req.has_param('timestamp'):
                timestamp = parse_timestamp(req.get_param('timestamp', required=True))
                if earliest is None or timestamp < earliest or timestamp > latest:
                    raise falcon.HTTPNotFound(description='Requested timestamp is outside of available data.')
            else:
                timestamp = latest
                if timestamp is None:
                    raise falcon.HTTPInternalServerError(description='Failed to get latest dump time.')

            vrps = get_covering_vrps_for_prefix_at_time(c, parsed_prefix, timestamp)
            # Format for JSON serialization.
            for vrp in vrps:
                vrp['prefix'] = vrp['prefix'].compressed
                vrp['visible'] = {'from': vrp['visible'].lower.isoformat(),
                                  'to': vrp['visible'].upper.isoformat()}
            resp.media = vrps


class StatusResource:
    def __init__(self) -> None:
        self.conn = psycopg.connect(
            host=db_host,
            dbname=db_dbname,
            user=db_user,
            password=db_password
        )

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Return the RPKI status for the specified prefix and originating ASN."""
        required_params = ['prefix', 'asn']
        for param in required_params:
            if not req.has_param(param):
                raise falcon.HTTPMissingParam(param)

        try:
            parsed_prefix = ipaddress.ip_network(req.get_param('prefix', required=True))
        except ValueError as e:
            raise falcon.HTTPInvalidParam(str(e), 'prefix')

        asn = req.get_param_as_int('asn', required=True)

        with self.conn.cursor() as c:
            earliest, latest = get_available_dump_time_range(c)
            if req.has_param('timestamp'):
                timestamp = parse_timestamp(req.get_param('timestamp', required=True))
                if earliest is None or timestamp < earliest or timestamp > latest:
                    raise falcon.HTTPNotFound(description='Requested timestamp is outside of available data.')
            else:
                timestamp = latest
                if timestamp is None:
                    raise falcon.HTTPInternalServerError(description='Failed to get latest dump time.')

            resp.media = get_rpki_status(c, parsed_prefix, timestamp, asn)


class MetadataResource:
    def __init__(self) -> None:
        self.conn = psycopg.connect(
            host=db_host,
            dbname=db_dbname,
            user=db_user,
            password=db_password
        )

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Return a list of dump timestamps and associated metadata."""
        with self.conn.cursor() as c:
            c.execute("""
                SELECT dump_time, deleted_vrps, updated_vrps, new_vrps
                FROM metadata
                ORDER BY dump_time
                """)
            resp.media = [
                {
                    'timestamp': e[0].isoformat(),
                    'deleted_vrps': e[1],
                    'updated_vrps': e[2],
                    'new_vrps': e[3]
                } for e in c.fetchall()
            ]


application = falcon.App()
# Show a landing page with descriptions based on README.
application.add_static_route('/', '/app/html', fallback_filename='index.html')
application.add_route('/vrp', VRPResource())
application.add_route('/status', StatusResource())
application.add_route('/metadata', MetadataResource())
