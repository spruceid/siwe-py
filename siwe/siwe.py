import secrets
import string
from datetime import datetime
from enum import Enum
from typing import List, Optional, Union

import eth_utils
from dateutil.parser import isoparse
from dateutil.tz import UTC
from eth_account.messages import SignableMessage, _hash_eip191_message, encode_defunct
from pydantic import AnyUrl, BaseModel, Field
from web3 import HTTPProvider, Web3
from web3.exceptions import BadFunctionCallOutput

from .parsed import ABNFParsedMessage, RegExpParsedMessage

EIP1271_CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": " _message", "type": "bytes32"},
            {"internalType": "bytes", "name": " _signature", "type": "bytes"},
        ],
        "name": "isValidSignature",
        "outputs": [{"internalType": "bytes4", "name": "", "type": "bytes4"}],
        "stateMutability": "view",
        "type": "function",
    }
]
EIP1271_MAGICVALUE = "1626ba7e"


ALPHANUMERICS = string.ascii_letters + string.digits


def generate_nonce() -> str:
    return "".join(secrets.choice(ALPHANUMERICS) for _ in range(11))


class VerificationError(Exception):
    pass


class InvalidSignature(VerificationError):
    pass


class ExpiredMessage(VerificationError):
    pass


class NotYetValidMessage(VerificationError):
    pass


class DomainMismatch(VerificationError):
    pass


class NonceMismatch(VerificationError):
    pass


class MalformedSession(VerificationError):
    def __init__(self, missing_fields):
        self.missing_fields = missing_fields


class VersionEnum(str, Enum):
    one = "1"

    def __str__(self):
        return self


class CustomDateTime(str):
    """
    ISO-8601 datetime string, meant to enable transitivity of deserialisation and serialisation.
    """

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise TypeError("string required")
        cls.date = isoparse(v)
        return cls(v)


class Address(str):
    """
    EIP-55 compliant Ethereum address.
    """

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise TypeError("string required")
        if not Web3.isChecksumAddress(v):
            raise ValueError("Message `address` must be in EIP-55 format")
        return cls(v)


class SiweMessage(BaseModel):
    """
    A class meant to fully encompass a Sign-in with Ethereum (EIP-4361) message. Its utility strictly remains
    within formatting and compliance.
    """

    domain: str = Field(
        regex="^[^/?#]+$"
    )  # RFC 4501 dns authority that is requesting the signing.
    address: Address  # Ethereum address performing the signing conformant to capitalization encoded checksum specified in EIP-55 where applicable.
    uri: AnyUrl  # RFC 3986 URI referring to the resource that is the subject of the signing.
    version: VersionEnum  # Current version of the message.
    chain_id: int = Field(
        gt=0
    )  # EIP-155 Chain ID to which the session is bound, and the network where Contract Accounts must be resolved.
    issued_at: CustomDateTime  # ISO 8601 datetime string of the current time.
    nonce: str = Field(
        min_length=8
    )  # Randomized token used to prevent replay attacks, at least 8 alphanumeric characters. Use generate_nonce() to generate a secure nonce and store it for verification later.
    statement: Optional[str] = Field(
        None, regex="^[^\n]+$"
    )  # Human-readable ASCII assertion that the user will sign, and it must not contain `\n`.
    expiration_time: Optional[CustomDateTime] = Field(
        None
    )  # ISO 8601 datetime string that, if present, indicates when the signed authentication message is no longer valid.
    not_before: Optional[CustomDateTime] = Field(
        None
    )  # ISO 8601 datetime string that, if present, indicates when the signed authentication message will become valid.
    request_id: Optional[str] = Field(
        None
    )  # System-specific identifier that may be used to uniquely refer to the sign-in request.
    resources: Optional[List[AnyUrl]] = Field(
        None, min_items=1
    )  # List of information or references to information the user wishes to have resolved as part of authentication by the relying party. They are expressed as RFC 3986 URIs separated by `\n- `.

    def __init__(self, message: Union[str, dict], abnf: bool = True):
        if isinstance(message, str):
            if abnf:
                parsed_message = ABNFParsedMessage(message=message)
            else:
                parsed_message = RegExpParsedMessage(message=message)
            message_dict = parsed_message.__dict__
        elif isinstance(message, dict):
            message_dict = message
        else:
            raise TypeError
        # There is some redundancy in the checks when deserialising a message.
        super().__init__(**message_dict)

    def prepare_message(self) -> str:
        """
        Retrieve an EIP-4361 formatted message for signature. It is recommended to instead use
        sign_message() which will resolve to the correct method based on the [type] attribute
        of this object, in case of other formats being implemented.

        :return: EIP-4361 formatted message, ready for EIP-191 signing.
        """
        header = f"{self.domain} wants you to sign in with your Ethereum account:"

        uri_field = f"URI: {self.uri}"

        prefix = "\n".join([header, self.address])

        version_field = f"Version: {self.version}"

        chain_field = f"Chain ID: {self.chain_id or 1}"

        nonce_field = f"Nonce: {self.nonce}"

        suffix_array = [uri_field, version_field, chain_field, nonce_field]

        if self.issued_at is None:
            # TODO: Should we default to UTC or settle for local time? UX may be better for local
            self.issued_at = datetime.now().astimezone().isoformat()

        issued_at_field = f"Issued At: {self.issued_at}"
        suffix_array.append(issued_at_field)

        if self.expiration_time:
            expiration_time_field = f"Expiration Time: {self.expiration_time}"
            suffix_array.append(expiration_time_field)

        if self.not_before:
            not_before_field = f"Not Before: {self.not_before}"
            suffix_array.append(not_before_field)

        if self.request_id:
            request_id_field = f"Request ID: {self.request_id}"
            suffix_array.append(request_id_field)

        if self.resources:
            resources_field = "\n".join(
                ["Resources:"] + [f"- {resource}" for resource in self.resources]
            )
            suffix_array.append(resources_field)

        suffix = "\n".join(suffix_array)

        if self.statement:
            prefix = "\n\n".join([prefix, self.statement])
        else:
            prefix += "\n"

        return "\n\n".join([prefix, suffix])

    def verify(
        self,
        signature: str,
        *,
        domain: Optional[str] = None,
        nonce: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        provider: Optional[HTTPProvider] = None,
    ) -> None:
        """
        Verifies the integrity of fields of this SiweMessage object by matching its signature.

        :param signature: Signature to check against the current message.
        :param domain: Domain expected to be in the current message.
        :param nonce: Nonce expected to be in the current message.
        :param timestamp: Timestamp used to verify the expiry date and other dates fields. Uses the current time by
        default.
        :param provider: A Web3 provider able to perform a contract check, this is required if support for Smart
        Contract Wallets that implement EIP-1271 is needed. It is also configurable with the environment
        variable `WEB3_HTTP_PROVIDER_URI`
        :return: None if the message is valid and raises an exception otherwise
        """
        message = encode_defunct(text=self.prepare_message())
        w3 = Web3(provider=provider)

        if domain is not None and self.domain != domain:
            raise DomainMismatch
        if nonce is not None and self.nonce != nonce:
            raise NonceMismatch

        verification_time = datetime.now(UTC) if timestamp is None else timestamp
        if (
            self.expiration_time is not None
            and verification_time >= self.expiration_time.date
        ):
            raise ExpiredMessage
        if self.not_before is not None and verification_time <= self.not_before.date:
            raise NotYetValidMessage

        try:
            address = w3.eth.account.recover_message(message, signature=signature)
        except ValueError:
            address = None
        except eth_utils.exceptions.ValidationError:
            raise InvalidSignature

        if address != self.address:
            if provider is not None and not check_contract_wallet_signature(
                address=self.address, message=message, signature=signature, w3=w3
            ):
                raise InvalidSignature


def check_contract_wallet_signature(
    address: str, message: SignableMessage, signature: str, w3: Web3
) -> bool:
    """
    Calls the EIP-1271 method for Smart Contract wallets.

    :param address: The address of the contract
    :param message: The EIP-4361 formatted message
    :param signature: The EIP-1271 signature
    :param w3: A Web3 provider able to perform a contract check.
    :return: True if the signature is valid per EIP-1271.
    """
    contract = w3.eth.contract(address=address, abi=EIP1271_CONTRACT_ABI)
    hash_ = _hash_eip191_message(message)
    try:
        response = contract.caller.isValidSignature(hash_, bytes.fromhex(signature[2:]))
        return response.hex() == EIP1271_MAGICVALUE
    except BadFunctionCallOutput:
        return False
