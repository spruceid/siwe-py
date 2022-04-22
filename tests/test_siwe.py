import pytest
import json
from humps import decamelize
from eth_account import Account, messages
from dateutil.parser import isoparse


from siwe.siwe import SiweMessage, VerificationError

BASE_TESTS = "tests/siwe/test/"
with open(BASE_TESTS + "parsing_positive.json", "r") as f:
    parsing_positive = decamelize(json.load(fp=f))
with open(BASE_TESTS + "parsing_negative.json", "r") as f:
    parsing_negative = decamelize(json.load(fp=f))
with open(BASE_TESTS + "verification_negative.json", "r") as f:
    verification_negative = decamelize(json.load(fp=f))
with open(BASE_TESTS + "verification_positive.json", "r") as f:
    verification_positive = decamelize(json.load(fp=f))


class TestMessageParsing:
    @pytest.mark.parametrize("abnf", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_positive.items()],
    )
    def test_valid_message(self, abnf, test_name, test):
        siwe_message = SiweMessage(message=test["message"], abnf=abnf)
        assert test["fields"] == siwe_message

    @pytest.mark.parametrize("abnf", [True, False])
    @pytest.mark.parametrize(
        "test_name,test",
        [(test_name, test) for test_name, test in parsing_negative.items()],
    )
    def test_invalid_message(self, abnf, test_name, test):
        with pytest.raises(ValueError):
            SiweMessage(message=test, abnf=abnf)


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
        [(test_name, test) for test_name, test in verification_negative.items()],
    )
    def test_invalid_message(self, test_name, test):
        with pytest.raises((VerificationError, ValueError)):
            siwe_message = SiweMessage(message=test)
            domain_binding = test.get("domain_binding")
            match_nonce = test.get("match_nonce")
            timestamp = isoparse(test["time"]) if "time" in test else None
            siwe_message.verify(test["signature"],
                domain=domain_binding,
                nonce=match_nonce,
                timestamp=timestamp)


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
