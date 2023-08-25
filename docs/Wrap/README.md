# Wrap Implementations for LocalWrap and SecretWrap

The following prefixes have been implemented in the PHP library.

| Prefix | Key-Wrapping Protocol                            | Owner                                                   |
|--------|--------------------------------------------------|---------------------------------------------------------|
| `pie`  | [PASERK standard wrapping protocol](pie.md)      | [Paragon Initiative Enterprises](https://paragonie.com) |

See [this section of the PASERK specification for all registered prefixes](https://github.com/paseto-standard/paserk/blob/master/operations/Wrap.md#registered-prefixes),
whether they're implemented in the PHP library or not.

The following prefixes are implemented in other PHP libraries:

| Prefix     | PHP Library                                                                               |
|------------|-------------------------------------------------------------------------------------------|
 | `aws-kms`  | [paragonie/paserk-php-wrap-aws-kms](https://github.com/paragonie/paserk-php-wrap-aws-kms) |
