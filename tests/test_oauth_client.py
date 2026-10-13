import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).parents[1] / 'lambda' / 'benefit_orchestrator'))
import lambda_function as api


class OAuthClientTests(unittest.TestCase):
    def setUp(self):
        self.credentials = Mock()
        self.credentials.get.return_value = api.Credentials('client', 'secret')
        self.clock = Mock(return_value=100.0)
        self.opener = Mock()
        self.opener.return_value.__enter__ = Mock(return_value=io.BytesIO(json.dumps({
            'access_token': 'signed.token.value', 'token_type': 'Bearer', 'expires_in': 300,
        }).encode()))
        self.opener.return_value.__exit__ = Mock(return_value=False)
        self.provider = api.OAuthClientCredentialsProvider(
            'https://issuer.example/token', 'benefit-checks.assess', self.credentials,
            opener=self.opener, clock=self.clock)

    def test_exchange_and_cache(self):
        self.assertEqual('signed.token.value', self.provider.get())
        self.assertEqual('signed.token.value', self.provider.get())
        self.opener.assert_called_once()
        request = self.opener.call_args.args[0]
        self.assertEqual('grant_type=client_credentials&scope=benefit-checks.assess', request.data.decode())
        self.assertEqual('Basic Y2xpZW50OnNlY3JldA==', request.get_header('Authorization'))

    def test_invalidation_discards_token_and_cached_secret(self):
        self.provider.get()
        self.provider.invalidate()
        self.assertIsNone(self.provider._token)
        self.credentials.invalidate.assert_called_once()

    def test_expiry_refreshes_before_token_expires(self):
        self.provider.get()
        self.clock.return_value = 371
        self.opener.return_value.__enter__.return_value = io.BytesIO(json.dumps({
            'access_token': 'new.token', 'token_type': 'bearer', 'expires_in': 300}).encode())
        self.assertEqual('new.token', self.provider.get())
        self.assertEqual(2, self.opener.call_count)

    def test_exchange_failure_never_falls_back_to_basic(self):
        self.opener.side_effect = urllib.error.HTTPError('https://issuer.example/token', 401, 'denied', {}, None)
        with self.assertRaises(api.ProviderUnavailable):
            self.provider.get()

    def test_reject_invalid_responses(self):
        for value in [{}, {'access_token': 'x', 'expires_in': -1, 'token_type': 'Bearer'},
                      {'access_token': 'x\r\nInjected: value', 'expires_in': 300, 'token_type': 'Bearer'},
                      {'access_token': 'x', 'expires_in': 300, 'token_type': 'Basic'}]:
            self.opener.return_value.__enter__.return_value = io.BytesIO(json.dumps(value).encode())
            with self.assertRaises(api.ProviderUnavailable):
                self.provider.get()

    def test_require_https(self):
        with self.assertRaises(api.ConfigurationError):
            api.OAuthClientCredentialsProvider('http://issuer.example/token', 'scope', self.credentials)

    def test_assessment_uses_bearer_without_client_secret(self):
        response = Mock(status=201)
        response.read.return_value = b'{}'
        opener = Mock()
        opener.return_value.__enter__ = Mock(return_value=response)
        opener.return_value.__exit__ = Mock(return_value=False)
        client = api.BenefitCheckerClient('https://provider.example', self.credentials,
                                          opener=opener, token_provider=self.provider)
        self.assertEqual(201, client.assess({}, 'test').status)
        request = opener.call_args.args[0]
        self.assertEqual('Bearer signed.token.value', request.get_header('Authorization'))
        self.assertNotIn('secret', str(request.headers))

    def test_does_not_retry_authorisation_denial(self):
        client = api.BenefitCheckerClient('https://provider.example', self.credentials)
        client._send = Mock(return_value=api.ProviderResponse(403, {}))
        self.assertEqual(403, client.assess({}, 'test').status)
        client._send.assert_called_once()
