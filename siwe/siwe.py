import secrets
import string
from datetime import datetime
from typing import List, Optional, Union

import eth_utils
import rfc3987
from dateutil.parser import isoparse
from dateutil.tz import UTC
from eth_account.messages import SignableMessage, _hash_eip191_message, encode_defunct
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


alphanumerics = string.ascii_letters + string.digits


def generate_nonce() -> str:
    return "".join(secrets.choice(alphanumerics) for _ in range(11))
