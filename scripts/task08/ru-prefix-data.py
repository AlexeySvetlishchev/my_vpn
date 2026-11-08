#!/usr/bin/python3
"""Bounded, conservative RU IPv4 candidate from two HTTPS geolocation feeds."""
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import io
import ipaddress
import json
from email.utils import parsedate_to_datetime
from urllib.request import HTTPRedirectHandler, Request, build_opener

DBIP_HOST = 'download.db-ip.com'
IPDENY_URL = 'https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone'
EXCLUDED = tuple(ipaddress.ip_network(value) for value in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '137.22.146.0/24', '169.254.0.0/16', '172.16.0.0/12',
    '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
    '224.0.0.0/4', '240.0.0.0/4', '45.15.128.0/24',
    '10.203.253.0/24', '10.203.254.0/30'))


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError('source redirect refused')


def fetch(url, max_bytes, max_age_days):
    req = Request(url, headers={'User-Agent': 'vpn-task08-ru-prefixes/1.0',
                                'Accept': 'application/octet-stream,text/plain'})
    with build_opener(NoRedirect()).open(req, timeout=20) as response:
        if response.status != 200 or response.url != url:
            raise ValueError('unexpected source response or redirect')
        modified = parsedate_to_datetime(response.headers['Last-Modified'])
        age = (datetime.now(timezone.utc) - modified).total_seconds() / 86400
        if modified.tzinfo is None or not -1 <= age <= max_age_days:
            raise ValueError('source release age invalid')
        raw = response.read(max_bytes + 1)
    if not raw or len(raw) > max_bytes:
        raise ValueError('source size invalid')
    return raw, {'url': url, 'sha256': hashlib.sha256(raw).hexdigest(),
                 'last_modified': modified.isoformat(), 'bytes': len(raw)}


def dbip_url(month):
    if not (len(month) == 7 and month[4] == '-' and month[:4].isdigit() and
            month[5:].isdigit() and 1 <= int(month[5:]) <= 12):
        raise ValueError('invalid release month')
    return f'https://{DBIP_HOST}/free/dbip-country-lite-{month}.csv.gz'


def dbip_ru(raw):
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
        decoded = compressed.read(100_000_001)
        if len(decoded) > 100_000_000:
            raise ValueError('DB-IP decompressed size invalid')
        stream = io.StringIO(decoded.decode('utf-8'), newline='')
        csv.field_size_limit(64)
        reader = csv.reader(stream)
        intervals = []
        rows = 0
        for fields in reader:
            rows += 1
            if rows > 1_000_000 or len(fields) != 3:
                raise ValueError('DB-IP CSV shape invalid')
            if fields[2] != 'RU':
                continue
            if ':' in fields[0] or ':' in fields[1]:
                continue
            start = int(ipaddress.IPv4Address(fields[0]))
            end = int(ipaddress.IPv4Address(fields[1]))
            if start > end:
                raise ValueError('DB-IP inverted range')
            intervals.append((start, end))
    if not 100_000 <= rows <= 1_000_000 or not 3_000 <= len(intervals) <= 50_000:
        raise ValueError('DB-IP coverage invalid')
    return merge(intervals), {'rows': rows, 'ru_ranges': len(intervals)}


def ipdeny_ru(raw):
    lines = raw.decode('ascii').splitlines()
    if not 5_000 <= len(lines) <= 30_000:
        raise ValueError('IPdeny coverage invalid')
    networks = []
    for line in lines:
        if not line or line.strip() != line:
            raise ValueError('IPdeny line invalid')
        network = ipaddress.ip_network(line, strict=True)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError('IPdeny non-IPv4 entry')
        networks.append(network)
    return merge((int(n.network_address), int(n.broadcast_address)) for n in networks), {
        'ru_prefixes': len(networks)}


def merge(intervals):
    result = []
    for start, end in sorted(intervals):
        if result and start <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(result[-1][1], end))
        else:
            result.append((start, end))
    return result


def intersect(left, right):
    out = []
    i = j = 0
    while i < len(left) and j < len(right):
        start = max(left[i][0], right[j][0])
        end = min(left[i][1], right[j][1])
        if start <= end:
            out.append((start, end))
        if left[i][1] < right[j][1]:
            i += 1
        else:
            j += 1
    return merge(out)


def subtract(intervals, exclusions):
    result = []
    for start, end in intervals:
        pieces = [(start, end)]
        for low, high in exclusions:
            next_pieces = []
            for a, b in pieces:
                if high < a or low > b:
                    next_pieces.append((a, b))
                else:
                    if a < low:
                        next_pieces.append((a, low - 1))
                    if high < b:
                        next_pieces.append((high + 1, b))
            pieces = next_pieces
            if not pieces:
                break
        result.extend(pieces)
    return merge(result)


def cidrs(intervals):
    result = []
    for start, end in intervals:
        result.extend(ipaddress.summarize_address_range(ipaddress.IPv4Address(start),
                                                         ipaddress.IPv4Address(end)))
    return result


def validate_public(networks):
    for network in networks:
        if (not isinstance(network, ipaddress.IPv4Network) or
                not network.network_address.is_global or
                not network.broadcast_address.is_global or
                any(network.overlaps(item) for item in EXCLUDED)):
            raise ValueError('non-public or protected prefix: ' + str(network))


def addresses(intervals):
    return sum(end - start + 1 for start, end in intervals)


def candidate(dbip_raw, ipdeny_raw, dbip_meta, ipdeny_meta):
    a, a_stats = dbip_ru(dbip_raw)
    b, b_stats = ipdeny_ru(ipdeny_raw)
    common = intersect(a, b)
    raw_total = addresses(common)
    common = subtract(common, merge((int(n.network_address), int(n.broadcast_address))
                                    for n in EXCLUDED))
    networks = cidrs(common)
    validate_public(networks)
    total = addresses(common)
    if (not 4_000 <= len(networks) <= 30_000 or
            not 10_000_000 <= total <= 100_000_000 or
            total < addresses(a) * .55 or total < addresses(b) * .55):
        raise ValueError('intersection coverage invalid')
    return {'schema': 1, 'kind': 'conservative_ru_ipv4_intersection',
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'sources': {'dbip': {**dbip_meta, **a_stats},
                        'ipdeny': {**ipdeny_meta, **b_stats}},
            'prefixes': [str(n) for n in networks], 'address_count': total,
            'excluded_addresses': raw_total - total,
            'dbip_ru_addresses': addresses(a),
            'ipdeny_ru_addresses': addresses(b)}


def latest_dbip():
    now = datetime.now(timezone.utc)
    months = [f'{now.year:04d}-{now.month:02d}']
    prev_year = now.year - (now.month == 1)
    prev_month = 12 if now.month == 1 else now.month - 1
    months.append(f'{prev_year:04d}-{prev_month:02d}')
    last_error = None
    for month in months:
        try:
            return fetch(dbip_url(month), 8_000_000, 45)
        except Exception as exc:
            last_error = exc
    raise ValueError('DB-IP current and previous release unavailable') from last_error


def build():
    dbip_raw, dbip_meta = latest_dbip()
    ipdeny_raw, ipdeny_meta = fetch(IPDENY_URL, 500_000, 5)
    return candidate(dbip_raw, ipdeny_raw, dbip_meta, ipdeny_meta)


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 1:
        raise SystemExit(2)
    try:
        data = build()
        print(json.dumps({'valid': True, 'prefixes': len(data['prefixes']),
                          'addresses': data['address_count'],
                          'dbip_sha256': data['sources']['dbip']['sha256'],
                          'ipdeny_sha256': data['sources']['ipdeny']['sha256']}))
    except Exception as exc:
        category = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(json.dumps({'valid': False, 'category': category}),
              file=sys.stderr)
        raise SystemExit(1)
