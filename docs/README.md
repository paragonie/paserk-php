# PASERK (PHP Documentation)

PASERK is an extension to [PASETO](https://paseto.io) that provides 
key-wrapping and serialization.

To understand the motivation behind PASERK, please refer to the
[PASERK Specification](https://github.com/paseto-standard/paserk).

## What Is PASERK Anyway?

PASERKs are serialized keys for use with PASETO. PASERK is short for
"Platform-Agnostic SERialized Keys".

A serialized key in PASERK has the format:

    k[version].[type].[data]

Each PASERK version corresponds directly with the PASETO version a serialized
key is intended to be used with, and it **MUST NOT** be used for another version.

Each [PASERK type](https://github.com/paseto-standard/paserk/blob/master/types)
is a composition of one or more [PASERK operations](https://github.com/paseto-standard/paserk/blob/master/operations).

Please refer to the [PASERK specification](https://github.com/paseto-standard/paserk#paserk)
if you'd like to learn more about the types/operations.

This section merely focuses on how to use the PHP implementation.

## Working with PASERK Types in PHP

* Basic Key Serialization (do **NOT** store these in a PASETO footer)
  * [`local`](Types/Local.md)
  * [`public`](Types/PublicType.md)
  * [`secret`](Types/SecretType.md) 
* Canonical Key Identifiers
  * [`lid`](Types/Lid.md)
  * [`pid`](Types/Pid.md)
  * [`sid`](Types/Sid.md)
* Key Wrapping 
  * [`local-wrap`](Types/LocalWrap.md)
  * [`local-pw`](Types/LocalPW.md)
  * [`secret-wrap`](Types/SecretWrap.md)
  * [`secret-pw`](Types/SecretPW.md)
  * [`seal`](Types/Seal.md) (Asymmetric Encryption)

## What About the PASERK Operations?

We do not recommend interfacing directly with the PASERK Operations.

Use the [PASERK Types](#working-with-paserk-types-in-php) instead.
