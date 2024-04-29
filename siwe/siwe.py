"""Main module for SIWE messages construction and validation."""

import secrets
import string
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, List, Optional

import eth_utils
from eth_account.messages import SignableMessage, _hash_eip191_message, encode_defunct
from eth_typing import ChecksumAddress
from pydantic import (
    AnyUrl,
    BaseModel,
    BeforeValidator,
    Field,
    NonNegativeInt,
    TypeAdapter,
    field_validator,
)
from pydantic_core import core_schema
from typing_extensions import Annotated
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


_ALPHANUMERICS = string.ascii_letters + string.digits


def generate_nonce() -> str:
    """Generate a cryptographically sound nonce."""
    return "".join(secrets.choice(_ALPHANUMERICS) for _ in range(11))


class VerificationError(Exception):
    """Top-level validation and verification exception."""

    pass


class InvalidSignature(VerificationError):
    """The signature does not match the message."""

    pass


class ExpiredMessage(VerificationError):
    """The message is not valid any more."""

    pass


class NotYetValidMessage(VerificationError):
    """The message is not yet valid."""

    pass


class SchemeMismatch(VerificationError):
    """The message does not contain the expected scheme."""

    pass


class DomainMismatch(VerificationError):
    """The message does not contain the expected domain."""

    pass


class NonceMismatch(VerificationError):
    """The message does not contain the expected nonce."""

    pass


class MalformedSession(VerificationError):
    """A message could not be constructed as it is missing certain fields."""

    def __init__(self, missing_fields: Iterable[str]):
        """Construct the exception with the missing fields."""
        self.missing_fields = missing_fields


class VersionEnum(str, Enum):
    """EIP-4361 versions."""

    one = "1"

    def __str__(self):
        """EIP-4361 representation of the enum field."""
        return self.value


# NOTE: Do not override the original uri string, just do validation
# https://github.com/pydantic/pydantic/issues/7186#issuecomment-1874338146
AnyUrlTypeAdapter = TypeAdapter(AnyUrl)
AnyUrlStr = Annotated[
    str,
    BeforeValidator(lambda value: AnyUrlTypeAdapter.validate_python(value) and value),
]


def datetime_from_iso8601_string(val: str) -> datetime:
    """Convert an ISO-8601 Datetime string into a valid datetime object."""
    return datetime.fromisoformat(val.replace(".000Z", "Z").replace("Z", "+00:00"))


# NOTE: Do not override the original string, but ensure we do timestamp validation
class ISO8601Datetime(str):
    """A special field class used to denote ISO-8601 Datetime strings."""

    def __init__(self, val: str):
        """Validate ISO-8601 string."""
        # NOTE: `self` is already this class, we are just running our validation here
        datetime_from_iso8601_string(val)

    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        """Create valid pydantic schema object for this type."""
        return core_schema.no_info_after_validator_function(
            cls, core_schema.str_schema()
        )

    @classmethod
    def from_datetime(
        cls, dt: datetime, timespec: str = "milliseconds"
    ) -> "ISO8601Datetime":
        """Create an ISO-8601 formatted string from a datetime object."""
        # NOTE: Only a useful classmethod for creating these objects
        return ISO8601Datetime(
            dt.astimezone(tz=timezone.utc)
            .isoformat(timespec=timespec)
            .replace("+00:00", "Z")
        )

    @property
    def _datetime(self) -> datetime:
        return datetime_from_iso8601_string(self)


def utc_now() -> datetime:
    """Get the current datetime as UTC timezone."""
    return datetime.now(tz=timezone.utc)


class SiweMessage(BaseModel):
    """A Sign-in with Ethereum (EIP-4361) message."""

    scheme: Optional[str] = None
    """RFC 3986 URI scheme for the authority that is requesting the signing."""
    domain: str = Field(pattern="^[^/?#]+$")
    """RFC 4501 dns authority that is requesting the signing."""
    address: ChecksumAddress
    """Ethereum address performing the signing conformant to capitalization encoded
    checksum specified in EIP-55 where applicable.
    """
    uri: AnyUrlStr
    """RFC 3986 URI referring to the resource that is the subject of the signing."""
    version: VersionEnum
    """Current version of the message."""
    chain_id: NonNegativeInt
    """EIP-155 Chain ID to which the session is bound, and the network where Contract
    Accounts must be resolved.
    """
    issued_at: ISO8601Datetime
    """ISO 8601 datetime string of the current time."""
    nonce: str = Field(min_length=8)
    """Randomized token used to prevent replay attacks, at least 8 alphanumeric
    characters. Use generate_nonce() to generate a secure nonce and store it for
    verification later.
    """
    statement: Optional[str] = Field(None, pattern="^[^\n]+$")
    """Human-readable ASCII assertion that the user will sign, and it must not contain
    `\n`.
    """
    expiration_time: Optional[ISO8601Datetime] = None
    """ISO 8601 datetime string that, if present, indicates when the signed
    authentication message is no longer valid.
    """
    not_before: Optional[ISO8601Datetime] = None
    """ISO 8601 datetime string that, if present, indicates when the signed
    authentication message will become valid.
    """
    request_id: Optional[str] = None
    """System-specific identifier that may be used to uniquely refer to the sign-in
    request.
    """
    resources: Optional[List[AnyUrlStr]] = None
    """List of information or references to information the user wishes to have resolved
    as part of authentication by the relying party. They are expressed as RFC 3986 URIs
    separated by `\n- `.
    """

    @field_validator("address")
    @classmethod
    def address_is_checksum_address(cls, v: str) -> str:
        """Validate the address follows EIP-55 formatting."""
        if not Web3.is_checksum_address(v):
            raise ValueError("Message `address` must be in EIP-55 format")
        return v

    @classmethod
    def from_message(cls, message: str, abnf: bool = True) -> "SiweMessage":
        """Parse a message in its EIP-4361 format."""
        if abnf:
            parsed_message = ABNFParsedMessage(message=message)
        else:
            parsed_message = RegExpParsedMessage(message=message)

        # TODO There is some redundancy in the checks when deserialising a message.
        return cls(**parsed_message.__dict__)

    def prepare_message(self) -> str:
        """Serialize to the EIP-4361 format for signing.

        It can then be passed to an EIP-191 signing function.

        :return: EIP-4361 formatted message, ready for EIP-191 signing.
        """
        header = f"{self.domain} wants you to sign in with your Ethereum account:"
        if self.scheme:
            header = f"{self.scheme}://{header}"

        uri_field = f"URI: {self.uri}"

        prefix = "\n".join([header, self.address])

        version_field = f"Version: {self.version}"

        chain_field = f"Chain ID: {self.chain_id or 1}"

        nonce_field = f"Nonce: {self.nonce}"

        suffix_array = [uri_field, version_field, chain_field, nonce_field]

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
        scheme: Optional[str] = None,
        domain: Optional[str] = None,
        nonce: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        provider: Optional[HTTPProvider] = None,
    ) -> None:
        """Verify the validity of the message and its signature.

        :param signature: Signature to check against the current message.
        :param domain: Domain expected to be in the current message.
        :param nonce: Nonce expected to be in the current message.
        :param timestamp: Timestamp used to verify the expiry date and other dates
        fields. Uses the current time by default.
        :param provider: A Web3 provider able to perform a contract check, this is
        required if support for Smart Contract Wallets that implement EIP-1271 is
        needed. It is also configurable with the environment variable
        `WEB3_HTTP_PROVIDER_URI`
        :return: None if the message is valid and raises an exception otherwise
        """
        message = encode_defunct(text=self.prepare_message())
        w3 = Web3(provider=provider)

        if scheme is not None and self.scheme != scheme:
            raise SchemeMismatch()
        if domain is not None and self.domain != domain:
            raise DomainMismatch()
        if nonce is not None and self.nonce != nonce:
            raise NonceMismatch()

        verification_time = utc_now() if timestamp is None else timestamp
        if (
            self.expiration_time is not None
            and verification_time >= self.expiration_time._datetime
        ):
            raise ExpiredMessage()
        if (
            self.not_before is not None
            and verification_time <= self.not_before._datetime
        ):
            raise NotYetValidMessage()

        try:
            address = w3.eth.account.recover_message(message, signature=signature)
        except ValueError:
            address = None
        except eth_utils.exceptions.ValidationError:
            raise InvalidSignature from None

        if address != self.address and (
            provider is None
            or not check_contract_wallet_signature(
                address=self.address, message=message, signature=signature, w3=w3
            )
        ):
            raise InvalidSignature()


def check_contract_wallet_signature(
    address: ChecksumAddress, message: SignableMessage, signature: str, w3: Web3
) -> bool:
    """Call the EIP-1271 method for a Smart Contract wallet.

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
