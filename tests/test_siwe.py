import json

import pytest
from dateutil.parser import isoparse
from eth_account import Account, messages
from humps import decamelize
from web3 import HTTPProvider

from siwe.siwe import SiweMessage, VerificationError

BASE_TESTS = "tests/siwe/test/"
with open(BASE_TESTS + "parsing_positive.json", "r") as f:
    parsing_positive = decamelize(json.load(fp=f))
with open(BASE_TESTS + "parsing_negative.json", "r") as f:
    parsing_negative = decamelize(json.load(fp=f))
with open(BASE_TESTS + "parsing_negative_objects.json", "r") as f:
    parsing_negative_objects = decamelize(json.load(fp=f))
with open(BASE_TESTS + "verification_negative.json", "r") as f:
    verification_negative = decamelize(json.load(fp=f))
with open(BASE_TESTS + "verification_positive.json", "r") as f:
    verification_positive = decamelize(json.load(fp=f))
with open(BASE_TESTS + "eip1271.json", "r") as f:
    verification_eip1271 = decamelize(json.load(fp=f))


class TestMessageParsing:
    @pytest.mark.parametrize("abnf", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_positive.items()],
    )
    def test_valid_message(self, abnf, test_name, test):
        siwe_message = SiweMessage(message=test["message"], abnf=abnf)
        for key, value in test["fields"].items():
            v = getattr(siwe_message, key)
            if not isinstance(v, int) and not isinstance(v, list):
                v = str(v)
            assert v == value

    @pytest.mark.parametrize("abnf", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_negative.items()],
    )
    def test_invalid_message(self, abnf, test_name, test):
        with pytest.raises(ValueError):
            SiweMessage(message=test, abnf=abnf)

    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_negative_objects.items()],
    )
    def test_invalid_object_message(self, test_name, test):
        with pytest.raises(ValueError):
            SiweMessage(message=test)


class TestMessageGeneration:
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_positive.items()],
    )
    def test_valid_message(self, test_name, test):
        siwe_message = SiweMessage(message=test["fields"])
        assert siwe_message.prepare_message() == test["message"]


class TestMessageVerification:
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in verification_positive.items()],
    )
    def test_valid_message(self, test_name, test):
        siwe_message = SiweMessage(message=test)
        timestamp = isoparse(test["time"]) if "time" in test else None
        siwe_message.verify(test["signature"], timestamp=timestamp)

    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in verification_eip1271.items()],
    )
    def test_eip1271_message(self, test_name, test):
        provider = HTTPProvider(endpoint_uri="https://cloudflare-eth.com")
        siwe_message = SiweMessage(message=test["message"])
        siwe_message.verify(test["signature"], provider=provider)

    @pytest.mark.parametrize(
        "provider", [HTTPProvider(endpoint_uri="https://cloudflare-eth.com"), None]
    )
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in verification_negative.items()],
    )
    def test_invalid_message(self, provider, test_name, test):
        if test_name in [
            "invalid expiration_time",
            "invalid not_before",
            "invalid issued_at",
        ]:
            with pytest.raises(ValueError):
                siwe_message = SiweMessage(message=test)
            return
        siwe_message = SiweMessage(message=test)
        domain_binding = test.get("domain_binding")
        match_nonce = test.get("match_nonce")
        timestamp = isoparse(test["time"]) if "time" in test else None
        with pytest.raises(VerificationError):
            siwe_message.verify(
                test.get("signature"),
                domain=domain_binding,
                nonce=match_nonce,
                timestamp=timestamp,
                provider=provider,
            )


class TestMessageRoundTrip:
    account = Account.create()

    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_positive.items()],
    )
    def test_message_round_trip(self, test_name, test):
        message = SiweMessage(test["fields"])
        message.address = self.account.address
        signature = self.account.sign_message(
            messages.encode_defunct(text=message.prepare_message())
        ).signature
        message.verify(signature)
