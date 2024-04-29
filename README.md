# Sign-In with Ethereum

This package provides a Python implementation of EIP-4361: Sign In With Ethereum.

## Installation

SIWE can be easily installed in any Python project with pip:

```bash
pip install siwe
```

## Usage

SIWE provides a `SiweMessage` class which implements EIP-4361.

### Parsing a SIWE Message

Parsing is done by initializing a `SiweMessage` object with an EIP-4361 formatted string:

```python
from siwe import SiweMessage
message = SiweMessage.from_message(message=eip_4361_string)
```

Or to initialize a `SiweMessage` as a `pydantic.BaseModel` right away:

```python
message = SiweMessage(domain="login.xyz", address="0x1234...", ...)
```

### Verifying and Authenticating a SIWE Message

Verification and authentication is performed via EIP-191, using the `address` field of the `SiweMessage` as the expected signer. The validate method checks message structural integrity, signature address validity, and time-based validity attributes.

```python
try:
    message.verify(signature="0x...")
    # You can also specify other checks (e.g. the nonce or domain expected).
except siwe.ValidationError:
    # Invalid
```

### Serialization of a SIWE Message

`SiweMessage` instances can also be serialized as their EIP-4361 string representations via the `prepare_message` method:

```python
print(message.prepare_message())
```

## Example

Parsing and verifying a `SiweMessage` is easy:

```python
try:
    message: SiweMessage = SiweMessage(message=eip_4361_string)
    message.verify(signature, nonce="abcdef", domain="example.com"):
except siwe.ValueError:
    # Invalid message
    print("Authentication attempt rejected.")
except siwe.ExpiredMessage:
    print("Authentication attempt rejected.")
except siwe.DomainMismatch:
    print("Authentication attempt rejected.")
except siwe.NonceMismatch:
    print("Authentication attempt rejected.")
except siwe.MalformedSession as e:
    # e.missing_fields contains the missing information needed for validation
    print("Authentication attempt rejected.")
except siwe.InvalidSignature:
    print("Authentication attempt rejected.")

# Message has been verified. Authentication complete. Continue with authorization/other.
```

## Testing

```bash
poetry install
git submodule update --init
poetry run pytest
```

## See Also

- [Sign-In with Ethereum: TypeScript](https://github.com/spruceid/siwe)
- [Example SIWE application: login.xyz](https://login.xyz)
- [EIP-4361 Specification Draft](https://eips.ethereum.org/EIPS/eip-4361)
- [EIP-191 Specification](https://eips.ethereum.org/EIPS/eip-191)

## Disclaimer

Our Python library for Sign-In with Ethereum has not yet undergone a formal
security audit. We welcome continued feedback on the usability, architecture,
and security of this implementation.
