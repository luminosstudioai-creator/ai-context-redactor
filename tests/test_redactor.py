import copy
import unittest

from redactor import RedactionError, redact, redact_record


class RedactorTests(unittest.TestCase):
    def test_prefixed_environment_credentials(self):
        for key in ['OPENAI_API_KEY', 'GITHUB_TOKEN', 'MY_SECRET', 'service-access-token', 'AWS_SECRET_ACCESS_KEY']:
            with self.subTest(key=key):
                self.assertEqual(redact(key + '=synthetic-only'), key + '=[SECRET_1]')

    def test_long_nonmatching_identifier_has_bounded_runtime(self):
        import subprocess
        import sys
        # A subprocess timeout prevents a regressed regex from hanging the suite.
        result = subprocess.run([sys.executable, '-c', "from redactor import redact; assert redact('a-' * 32768) == 'a-' * 32768"], timeout=3, capture_output=True)
        self.assertEqual(result.returncode, 0)

    def test_long_secret_is_not_partially_redacted(self):
        secret = 'x' * 5000
        self.assertEqual(redact('token=' + secret), 'token=[SECRET_1]')

    def test_record_aggregate_budget(self):
        with self.assertRaises(RedactionError):
            redact_record(['x' * 40000, 'y' * 40000])

    def test_cli_redacts_and_rejects_excess_input(self):
        import subprocess
        import sys
        from pathlib import Path
        script = Path(__file__).resolve().parents[1] / 'redactor.py'
        for data, code, expected in [(b'alice@example.com', 0, b'[EMAIL_1]'), (b'x' * 65537, 2, b''), (b'\xff', 2, b'')]:
            run = subprocess.run([sys.executable, str(script)], input=data, capture_output=True)
            self.assertEqual(run.returncode, code)
            self.assertEqual(run.stdout, expected)

    def test_email_and_repeat_are_stable(self):
        self.assertEqual(redact('alice@example.com cc bob@example.org alice@example.com'),
                         '[EMAIL_1] cc [EMAIL_2] [EMAIL_1]')

    def test_valid_iban_with_spaces(self):
        self.assertEqual(redact('Pay DE89 3704 0044 0532 0130 00 today'), 'Pay [IBAN_1] today')

    def test_invalid_iban_not_claimed_as_redacted(self):
        value = 'DE89370400440532013001'
        self.assertEqual(redact(value), value)

    def test_secret_assignments(self):
        for value in ['api_key=synthetic-secret', 'token: "synthetic secret"', "password='synthetic secret'"]:
            with self.subTest(value=value):
                result = redact(value)
                self.assertNotIn('synthetic', result)
                self.assertIn('[SECRET_1]', result)

    def test_overlapping_secret_contains_email(self):
        self.assertEqual(redact('password="alice@example.com"'), 'password="[SECRET_1]"')

    def test_plain_business_values_survive(self):
        text = 'Invoice 4200, amount EUR 42.50, delivery 2026-10-05.'
        self.assertEqual(redact(text), text)

    def test_sensitive_record_keys_mask_entire_value(self):
        self.assertEqual(redact_record({'API-Key': {'nested': 'private'}, 'password': 123, 'count': 2}),
                         {'API-Key': '[REDACTED]', 'password': '[REDACTED]', 'count': 2})

    def test_nested_records_and_no_mutation(self):
        value = {'items': [{'note': 'alice@example.com', 'access_token': 'synthetic'}], 'ok': True, 'none': None}
        original = copy.deepcopy(value)
        result = redact_record(value)
        self.assertEqual(result['items'][0], {'note': '[EMAIL_1]', 'access_token': '[REDACTED]'})
        self.assertEqual(value, original)
        self.assertIsNot(result, value)

    def test_sensitive_keys_in_output_are_redacted(self):
        self.assertEqual(redact_record({'alice@example.com': 'business'}), {'[EMAIL_1]': 'business'})

    def test_key_collision_rejected(self):
        with self.assertRaises(RedactionError):
            redact_record({'alice@example.com': 1, '[EMAIL_1]': 2})

    def test_unicode_byte_limit_and_bad_unicode(self):
        for text in ['ü' * 10, '\ud800']:
            with self.assertRaises(RedactionError):
                redact(text, max_bytes=10)

    def test_resource_and_type_limits(self):
        for text, limit in [(None, 10), ('abc', 0), ('abc', True)]:
            with self.assertRaises(RedactionError):
                redact(text, max_bytes=limit)

    def test_nested_and_nonfinite_inputs_rejected(self):
        nested = []
        for _ in range(30):
            nested = [nested]
        for value in [nested, {'x': float('nan')}, {'x': float('inf')}, {'x': object()}]:
            with self.assertRaises(RedactionError):
                redact_record(value)

    def test_cyclic_record_rejected(self):
        value = []
        value.append(value)
        with self.assertRaises(RedactionError):
            redact_record(value)

    def test_error_does_not_echo_input(self):
        with self.assertRaises(RedactionError) as caught:
            redact('synthetic-private-text', max_bytes=1)
        self.assertNotIn('synthetic-private-text', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
