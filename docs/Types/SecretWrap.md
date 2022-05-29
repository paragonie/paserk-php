# PASERK Type: SecretWrap

Example code:

```php
<?php
use ParagonIE\Paserk\Types\SecretWrap;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;

// You first need a wrapping key
$wrappingKey = SymmetricKey::generate(new Version4());

// Next, you can initialize the wrapper
$wrapper = SecretWrap::initWithKey($wrappingKey);

// Finally, you can wrap/unwrap your asymmetric secret keys.
$tempKey = AsymmetricSecretKey::generate(new Version4());
$paserk = $wrapper->encode($tempKey);
var_dump($paserk);

$unwrap = $wrapper->decode($paserk);
var_dump(get_class($unwrap));
```

Example output:

```
string(190) "k4.secret-wrap.pie.qLi63IiwlxcmggIwyX-jCAxu-irkMXWzRHUxYDoqJqCPy3B81y2THFSKrpg1860DUWN53lkdcsBeEsQbwlxaSFkgSdtxLS7TBz5opmt6Z-Wn
jRcpAlo2NtUMjFLFArR0GdRh_uxGkp6hA5dxlXMcaJAvJnhLVbjCkJFeH71R67E"
string(41) "ParagonIE\Paseto\Keys\AsymmetricSecretKey"
```

## Class Definition: `SecretWrap`

### Constructor

```php
/**
 * SecretWrap constructor.
 * @param Wrap $wrap
 */
public function __construct(Wrap $wrap): SecretWrap;
```

The `SecretWrap` class expects a vendor-specific `Wrap` object to be provided to
its constructor. Currently, the only implementation is one provided by
[Paragon Initiative Enterprises](https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md).

### Static Methods

#### `initWithKey()`

```php
/**
 * @param SymmetricKey $key
 * @return static
 *
 * @throws InvalidVersionException
 */
public static function initWithKey(SymmetricKey $key): SecretWrap;
```

This initializes a `SecretWrap` with the default `Wrap` implementation (`pie`),
passing the provided `SymmetricKey` to the `Wrap` instance, and returns the
`SecretWrap` class.

### Class Methods

#### `decode()`

```php
/**
 * @throws PaserkException
 */
public function decode(string $paserk): KeyInterface;
```

Note: Although the return type declaration is `KeyInterface`, `SecretWrap` returns
an `AsymmetricSecretKey`.

#### `encode()`

```php
/**
 * @param KeyInterface $key
 * @return string
 *
 * @throws InvalidVersionException
 * @throws PaserkException
 */
public function encode(KeyInterface $key): string;
```

Note: Although the type declaration is `KeyInterface`, you **MUST** supply a
`AsymmetricSecretKey` to use `SecretWrap` serialization.

#### `id()`

```php
/**
 * @param KeyInterface $key
 * @return string
 *
 * @throws InvalidVersionException
 * @throws PaserkException
 * @throws \SodiumException
 */
public function id(KeyInterface $key): string;
```

See [Lid](Lid.md#encodelocal).

## Custom Wrap Protocols

See [this section](../Wrap) for all the supported Wrap implementations.

See [the PASERK specification](https://github.com/paseto-standard/paserk/tree/master/operations/Wrap)
for all the publicly specified custom wrapping protocols.
