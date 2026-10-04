"""Offline, deterministic pattern redaction. Not anonymization or complete DLP."""
import math
import re
import sys


class RedactionError(ValueError):
    """Invalid or excessive input; messages do not echo input values."""


_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,3}(?![\w.-])")
# German IBANs only: DE + check digits + 18 digits.
_IBAN = re.compile(r"(?<![A-Za-z0-9])DE[0-9]{2}(?: ?[0-9]){18}(?![0-9])")
_SECRET = re.compile(r"(?i)(?<![A-Za-z0-9_-])(?:[A-Za-z0-9]+[_-])*(?:secret[_-]access[_-]key|api[_-]?key|access[_-]?token|token|password|secret)\b\s*[:=]\s*(?:\"(?P<double>[^\"\r\n]+)\"|'(?P<single>[^'\r\n]+)'|(?P<bare>[^\s,;\"']+))")
_SENSITIVE = {'apikey', 'accesstoken', 'token', 'password', 'secret', 'authorization', 'email', 'iban'}


def _valid_iban(value):
    compact = value.replace(' ', '')
    digits = ''.join(str(ord(char) - 55) if char.isalpha() else char for char in compact[4:] + compact[:4])
    return int(digits) % 97 == 1


def redact(text, *, max_bytes=65536):
    """Replace supported patterns; equal values share a marker within this call.

    Supports ASCII-style emails, checksum-valid German IBANs and simple
    credential assignments. Does not return a mapping to original values.
    """
    if type(text) is not str or type(max_bytes) is not int or max_bytes < 1:
        raise RedactionError('invalid text or byte limit')
    try:
        if len(text.encode('utf-8')) > max_bytes:
            raise RedactionError('input byte limit exceeded')
    except UnicodeError:
        raise RedactionError('invalid Unicode') from None
    spans = []
    for match in _SECRET.finditer(text):
        group = next(name for name in ('double', 'single', 'bare') if match.group(name) is not None)
        spans.append((*match.span(group), 'SECRET', match.group(group)))
    for pattern, kind in ((_EMAIL, 'EMAIL'), (_IBAN, 'IBAN')):
        for match in pattern.finditer(text):
            start, end = match.span()
            if kind == 'IBAN' and not _valid_iban(match.group()):
                continue
            if not any(start < b and end > a for a, b, _, _ in spans):
                spans.append((start, end, kind, match.group().replace(' ', '') if kind == 'IBAN' else match.group()))
    markers = {}
    counts = {}
    parts = []
    cursor = 0
    for start, end, kind, value in sorted(spans):
        key = (kind, value)
        if key not in markers:
            counts[kind] = counts.get(kind, 0) + 1
            markers[key] = f'[{kind}_{counts[kind]}]'
        parts.extend((text[cursor:start], markers[key]))
        cursor = end
    parts.append(text[cursor:])
    return ''.join(parts)


def redact_record(record):
    """Copy JSON data; mask sensitive keys and redact strings including keys.

    Marker numbering resets per string. Key collisions fail. Limits: depth 20,
    10,000 nodes, 65,536 aggregate UTF-8 string bytes, including masked values.
    """
    nodes = size = 0

    def check(value, depth=0):
        nonlocal nodes, size
        nodes += 1
        if depth > 20 or nodes > 10000:
            raise RedactionError('record resource limit exceeded')
        if type(value) is str:
            try:
                size += len(value.encode('utf-8'))
            except UnicodeError:
                raise RedactionError('invalid Unicode') from None
            if size > 65536:
                raise RedactionError('record byte limit exceeded')
        elif type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise RedactionError('record keys must be strings')
                check(key, depth + 1)
                check(item, depth + 1)
        elif type(value) is list:
            for item in value:
                check(item, depth + 1)
        elif type(value) is float and not math.isfinite(value):
            raise RedactionError('non-finite record value')
        elif type(value) not in (int, float, bool, type(None)):
            raise RedactionError('record must contain JSON values')

    def walk(value):
        if type(value) is str:
            return redact(value)
        if type(value) is list:
            return [walk(item) for item in value]
        if type(value) is dict:
            result = {}
            for key, item in value.items():
                safe_key = redact(key)
                if safe_key in result:
                    raise RedactionError('redacted key collision')
                normalized = key.casefold().replace('_', '').replace('-', '')
                result[safe_key] = '[REDACTED]' if normalized in _SENSITIVE else walk(item)
            return result
        return value

    check(record)
    return walk(record)


def main():
    """Read UTF-8 text from stdin; output redacted text. Exit 2 on invalid input."""
    try:
        raw = sys.stdin.buffer.read(65537)
        result = redact(raw.decode('utf-8'))
    except (RedactionError, UnicodeError):
        print('Invalid or excessive input.', file=sys.stderr)
        return 2
    sys.stdout.write(result)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
