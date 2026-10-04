"""Synthetic data only. The German IBAN is a checksum test example."""
import json
from redactor import redact, redact_record

print(redact('Contact alice@example.com; account DE89 3704 0044 0532 0130 00; token=synthetic-demo-only'))
print(json.dumps(redact_record({'email': 'alice@example.com', 'note': 'Invoice EUR 42.50', 'API-Key': 'synthetic-demo-only'}), indent=2))
