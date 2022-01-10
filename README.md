# Sign-In with Ethereum

This package provides a Python implementation of EIP-4631: Sign In With Ethereum.

## Installation

SIWE can be easily installed in any Python project with pip:

``` toml
pip install siwe
```

## Usage

SIWE provides a `SiweMessage` class which implements EIP-4361.

### Parsing a SIWE Message

Parsing is done by initializing a `SiweMessage` object with an EIP-4361 formatted string:

``` python
message: SiweMessage = SiweMessage(message=eip_4361_string)
```

Alternatively, initialization of a `SiweMessage` object can be done with a dictionary containing expected attributes:

``` python
message: SiweMessage = SiweMessage(message={"domain": "login.xyz", "address": "0x1234...", ...})
```

### Verifying and Authenticating a SIWE Message

Verification and authentication is performed via EIP-191, using the `address` field of the `SiweMessage` as the expected signer. The validate method checks message structural integrity, signature address validity, and time-based validity attributes. 

``` python
if message.validate():
    # Valid
else:
    # Invalid
```

### Serialization of a SIWE Message

`SiweMessage` instances can also be serialized as their EIP-4361 string representations via the `sign_message` method:

``` python
print(message.sign_message())
```

## Example

Parsing and verifying a `SiweMessage` is easy:

``` python
message: SiweMessage = SiweMessage(message=eip_4361_string)

try:
    if not message.validate():
        # Authentication attempt rejected.
except SiweError.EXPIRED_MESSAGE:
    # Authentication attempt rejected.
except SiweError.MALFORMED_SESSION:
    # Authentication attempt rejected.
except SiweError.INVALID_SIGNATURE:
    # Authentication attempt rejected.
    
# Message has been validated. Authentication complete. Continue with authorization/other.
```

## TODOs

- Support for contract wallets.

## See Also

- [Sign-In with Ethereum: TypeScript](https://github.com/spruceid/siwe)
- [Example SIWE application: login.xyz](https://login.xyz)
- [EIP-4361 Specification Draft](https://eips.ethereum.org/EIPS/eip-4361)
- [EIP-191 Specification](https://eips.ethereum.org/EIPS/eip-191)
