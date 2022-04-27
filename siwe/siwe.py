from datetime import datetime
import string
import secrets
import rfc3987
from dateutil.parser import isoparse
from dateutil.tz import UTC
from typing import Optional, List, Union

import eth_utils
from web3 import Web3, HTTPProvider
import eth_account.messages

from .parsed import RegExpParsedMessage, ABNFParsedMessage


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
    ]  # Human-readable ASCII assertion that the user will sign, and it must not
    # contain `\n`.

    uri: str  # RFC 3986 URI referring to the resource that is the subject of the signing.

    version: str  # Current version of the message.

    chain_id: int  # EIP-155 Chain ID to which the session is bound, and the network where Contract Accounts must be
    # resolved.

    nonce: Optional[
        str
    ]  # Randomized token used to prevent replay attacks, at least 8 alphanumeric characters.

    issued_at: str  # ISO 8601 datetime string of the current time.

    expiration_time: Optional[
        str
    ]  # ISO 8601 datetime string that, if present, indicates when the signed
    # authentication message is no longer valid.

    not_before: Optional[
        str
    ]  # ISO 8601 datetime string that, if present, indicates when the signed
    # authentication message will become valid.

    request_id: Optional[
        str
    ]  # System-specific identifier that may be used to uniquely refer to the sign-in
    # request.

    resources: Optional[
        List[str]
    ]  # List of information or references to information the user wishes to have
    # resolved as part of authentication by the relying party. They are expressed as RFC 3986 URIs separated by `\n- `.

    __slots__ = (
        "domain",
        "address",
        "statement",
        "uri",
        "chain_id",
        "version",
        "nonce",
        "issued_at",
        "expiration_time",
        "not_before",
        "request_id",
        "resources",
    )

    def __init__(self, message: Union[str, dict] = None, abnf: bool = True):
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
        for key in self.__slots__:
            value = message_dict.get(key)

            if key == "chain_id" and value is not None and type(value) is not int:
                value = int(value)
            elif key == "issued_at" and value is not None:
                isoparse(value)
            elif key == "expiration_time" and value is not None:
                isoparse(value)
            elif key == "not_before" and value is not None:
                isoparse(value)
            elif key == "domain" and value == "":
                raise ValueError("Message `domain` must not be empty")
            elif key == "address" and value is not None:
                if not eth_utils.is_checksum_formatted_address(value):
                    raise ValueError("Message `address` must be in EIP-55 format")
            elif key == "uri" and value is not None:
                try:
                    rfc3987.parse(value, rule="URI")
                except ValueError:
                    raise ValueError("Invalid format for field `uri`")
            elif key == "resources" and value is not None:
                for url in value:
                    try:
                        rfc3987.parse(url, rule="URI")
                    except ValueError:
                        raise ValueError("Invalid format for field `resources`")

            setattr(self, key, value)

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

        if self.nonce is None:
            self.nonce = generate_nonce()

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

    def get_expiration_time(self) -> Optional[datetime]:
        return (
            isoparse(self.expiration_time) if self.expiration_time is not None else None
        )

    def get_not_before(self) -> Optional[datetime]:
        return isoparse(self.not_before) if self.not_before is not None else None

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
        Validates the integrity of fields of this SiweMessage object by matching its signature.

        :param provider: A Web3 provider able to perform a contract check, this is required if support for Smart
        Contract Wallets that implement EIP-1271 is needed.
        :return: True if the message is valid and false otherwise
        """
        message = eth_account.messages.encode_defunct(text=self.prepare_message())
        w3 = Web3(provider=provider)

        missing = []
        if message is None:
            missing.append("message")

        if self.address is None:
            missing.append("address")

        if len(missing) > 0:
            raise MalformedSession(missing)

        if domain is not None and self.domain != domain:
            raise DomainMismatch

        if nonce is not None and self.nonce != nonce:
            raise NonceMismatch

        verification_time = datetime.now(UTC) if timestamp is None else timestamp

        expiration_time = self.get_expiration_time()
        if expiration_time is not None and verification_time >= expiration_time:
            raise ExpiredMessage

        not_before = self.get_not_before()
        if not_before is not None and verification_time <= not_before:
            raise NotYetValidMessage

        try:
            address = w3.eth.account.recover_message(message, signature=signature)
        except eth_utils.exceptions.ValidationError:
            raise InvalidSignature

        if address != self.address:
            raise InvalidSignature
        #     if not check_contract_wallet_signature(message=self, provider=provider):
        #         # TODO: Add error context


def check_contract_wallet_signature(message: SiweMessage, *, provider: HTTPProvider):
    """
    Calls the EIP-1271 method for Smart Contract wallets,

    :param message: The EIP-4361 parsed message
    :param provider: A Web3 provider able to perform a contract check.
    :return: True if the signature is valid per EIP-1271.
    """
    raise NotImplementedError(
        "siwe does not yet support EIP-1271 method signature verification."
    )


alphanumerics = string.ascii_letters + string.digits


def generate_nonce() -> str:
    return "".join(secrets.choice(alphanumerics) for _ in range(11))
