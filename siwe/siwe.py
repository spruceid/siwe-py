import datetime
import secrets
from dateutil import parser
from enum import Enum
from typing import Optional, List, Union
import eth_utils

from web3 import Web3, HTTPProvider
import eth_account.messages

from .parsed import RegExpParsedMessage, ABNFParsedMessage


class SignatureType(Enum):
    """Types of signatures supported by this library"""

    PERSONAL_SIGNATURE = ("Personal signature",)  # EIP-191 signature scheme


class SiweError(Enum):
    """Messages thrown by operations defined by the SiweMessage class"""

    INVALID_SIGNATURE = (
        "Invalid signature.",
    )  # validate() cannot verify the signature.
    EXPIRED_MESSAGE = (
        "Expired message.",
    )  # expiration_time exists and is in the past.
    MALFORMED_SESSION = ("Malformed session.",)  # Missing required field.


class SiweMessage:
    """
    A class meant to fully encompass a Sign-in with Ethereum (EIP-4361) message. Its utility strictly remains
    within formatting and compliance.
    """

    domain: str  # RFC 4501 dns authority that is requesting the signing.

    address: str  # Ethereum address performing the signing conformant to capitalization encoded checksum specified
    # in EIP-55 where applicable.

    statement: Optional[
        str
    ] = None  # Human-readable ASCII assertion that the user will sign, and it must not
    # contain `\n`.

    uri: str  # RFC 3986 URI referring to the resource that is the subject of the signing.

    version: str  # Current version of the message.

    chain_id: str  # EIP-155 Chain ID to which the session is bound, and the network where Contract Accounts must be
    # resolved.

    nonce: str  # Randomized token used to prevent replay attacks, at least 8 alphanumeric characters.

    issued_at: str  # ISO 8601 datetime string of the current time.

    expiration_time: Optional[
        str
    ] = None  # ISO 8601 datetime string that, if present, indicates when the signed
    # authentication message is no longer valid.

    not_before: Optional[
        str
    ] = None  # ISO 8601 datetime string that, if present, indicates when the signed
    # authentication message will become valid.

    request_id: Optional[
        str
    ] = None  # System-specific identifier that may be used to uniquely refer to the sign-in
    # request.

    resources: Optional[
        List[str]
    ] = None  # List of information or references to information the user wishes to have
    # resolved as part of authentication by the relying party. They are expressed as RFC 3986 URIs separated by `\n- `.

    signature: Optional[str] = None  # Signature of the message signed by the wallet.

    signature_type: SignatureType = (
        SignatureType.PERSONAL_SIGNATURE
    )  # Type of sign message to be generated.

    def __init__(self, message: Union[str, dict] = None, abnf: bool = True):
        if isinstance(message, str):
            if abnf:
                for k, v in ABNFParsedMessage(message=message).__dict__.items():
                    setattr(self, k, v)
            else:
                for k, v in RegExpParsedMessage(message=message).__dict__.items():
                    setattr(self, k, v)
        elif isinstance(message, dict):
            for k, v in message.items():
                setattr(self, k, v)

    def to_message(self) -> str:
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

        if self.nonce is None:
            self.nonce = generate_nonce()

        chain_field = f"Chain ID: {self.chain_id or 1}"

        nonce_field = f"Nonce: {self.nonce}"

        suffix_array = [uri_field, version_field, chain_field, nonce_field]

        if self.issued_at is None:
            # TODO: Should we default to UTC or settle for local time? UX may be better for local
            self.issued_at = datetime.datetime.now().astimezone().isoformat()

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

        return "\n\n".join([prefix, suffix])

    def sign_message(self) -> str:
        """
        Parses all fields in the object and creates a sign message according to the type defined.

        :return: a message ready to be signed according to the type defined in the object.
        """
        if self.signature_type is SignatureType.PERSONAL_SIGNATURE:
            message = self.to_message()
        else:
            message = self.to_message()
        return message

    def validate(self, provider: Optional[HTTPProvider] = None) -> bool:
        """
        Validates the integrity of fields of this SiweMessage object by matching its signature.

        :param provider: A Web3 provider able to perform a contract check, this is required if support for Smart
        Contract Wallets that implement EIP-1271 is needed.
        :return: True if the message is valid and false otherwise
        """
        message = eth_account.messages.encode_defunct(text=self.sign_message())
        w3 = Web3(provider=provider)

        missing = []
        if message is None:
            missing.append("`message`")

        if self.signature is None:
            missing.append("``signature")

        if self.address is None:
            missing.append("`address`")

        if len(missing) > 0:
            # TODO: Add error context
            raise SiweError.MALFORMED_SESSION

        try:
            address = w3.eth.account.recover_message(message, signature=self.signature)
        except eth_utils.exceptions.ValidationError:
            return False

        # if address != self.address:
        #     if not check_contract_wallet_signature(message=self, provider=provider):
        #         # TODO: Add error context
        #         raise SiweError.INVALID_SIGNATURE

        parsed_message = SiweMessage(message=message)
        # TODO: Remove external date parsing dependency in favor of native libs
        if parsed_message.expiration_time and datetime.datetime.now() >= parser.parse(
            self.expiration_time
        ):
            # TODO: Add error context
            raise SiweError.EXPIRED_MESSAGE

        return True


def check_contract_wallet_signature(message: SiweMessage, provider: HTTPProvider):
    """
    Calls the EIP-1271 method for Smart Contract wallets,

    :param message: The EIP-4361 parsed message
    :param provider: A Web3 provider able to perform a contract check.
    :return: True if the signature is valid per EIP-1271.
    """
    raise NotImplementedError(
        "siwe does not yet support EIP-1271 method signature verification."
    )


def generate_nonce() -> str:
    return secrets.token_hex(12)
