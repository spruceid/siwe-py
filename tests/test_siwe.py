import json
import os

import pytest
from eth_account import Account, messages
from humps import decamelize
from web3 import HTTPProvider
from pydantic import ValidationError

from siwe.siwe import SiweMessage, VerificationError, datetime_from_iso8601_string

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

try:
    endpoint_uri = os.environ["WEB3_PROVIDER_URI"]
except KeyError:
    endpoint_uri = "https://cloudflare-eth.com"


class TestMessageParsing:
    @pytest.mark.parametrize("abnf", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_positive.items()],
    )
    def test_valid_message(self, abnf, test_name, test):
        siwe_message = SiweMessage.from_message(message=test["message"], abnf=abnf)
        for key, value in test["fields"].items():
            v = getattr(siwe_message, key)
            if not (isinstance(v, int) or isinstance(v, list) or v is None):
                v = str(v)
            assert v == value

    @pytest.mark.parametrize("abnf", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_negative.items()],
    )
    def test_invalid_message(self, abnf, test_name, test):
        with pytest.raises(ValueError):
            SiweMessage.from_message(message=test, abnf=abnf)

    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_negative_objects.items()],
    )
    def test_invalid_object_message(self, test_name, test):
        with pytest.raises(ValidationError):
            SiweMessage(**test)


class TestMessageGeneration:
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_positive.items()],
    )
    def test_valid_message(self, test_name, test):
        siwe_message = SiweMessage(**test["fields"])
        assert siwe_message.prepare_message() == test["message"]


class TestMessageVerification:
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in verification_positive.items()],
    )
    def test_valid_message(self, test_name, test):
        siwe_message = SiweMessage(**test)
        timestamp = (
            datetime_from_iso8601_string(test["time"]) if "time" in test else None
        )
        siwe_message.verify(test["signature"], timestamp=timestamp)

    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in verification_eip1271.items()],
    )
    def test_eip1271_message(self, test_name, test):
        if test_name == "loopring":
            pytest.skip()
        provider = HTTPProvider(endpoint_uri=endpoint_uri)
        siwe_message = SiweMessage.from_message(message=test["message"])
        siwe_message.verify(test["signature"], provider=provider)

    @pytest.mark.parametrize(
        "provider", [HTTPProvider(endpoint_uri=endpoint_uri), None]
    )
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in verification_negative.items()],
    )
    def test_invalid_message(self, provider, test_name, test):
        if test_name in [
            "invalidexpiration_time",
            "invalidnot_before",
            "invalidissued_at",
        ]:
            with pytest.raises(ValidationError):
                siwe_message = SiweMessage(**test)
            return
        siwe_message = SiweMessage(**test)
        domain_binding = test.get("domain_binding")
        match_nonce = test.get("match_nonce")
        timestamp = (
            datetime_from_iso8601_string(test["time"]) if "time" in test else None
        )
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
        message = SiweMessage(**test["fields"])
        message.address = self.account.address
        signature = self.account.sign_message(
            messages.encode_defunct(text=message.prepare_message())
        ).signature
        message.verify(signature)

    def test_schema_generation(self):
        # NOTE: Needed so that FastAPI/OpenAPI json schema works
        SiweMessage.model_json_schema()
