# PASERK Type: LocalWrap

Example code:

```php
<?php
use ParagonIE\Paserk\Types\LocalWrap;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\SymmetricKey;

// You first need a wrapping key
$wrappingKey = SymmetricKey::generate(new Version4());

// Next, you can initialize the wrapper
$wrapper = LocalWrap::initWithKey($wrappingKey);

// Finally, you can wrap/unwrap your symmetric keys.
$tempKey = SymmetricKey::generate(new Version4());
$paserk = $wrapper->encode($tempKey);
var_dump($paserk);

$unwrap = $wrapper->decode($paserk);
var_dump(get_class($unwrap));
```

Example output:

```
string(146) "k4.local-wrap.pie.b66FQOk3Akt1IbmHT47GDOCtoEpVYmpMxuk7bdsmrbQgskP_zDZXZrYc5nVZrEq2kUWeb9Ni0fkay1A4pSJQ5Y9mLjlJNMfXxASozOgLw_BoD
bbMGl7q5TM8TSfGil-D"
string(34) "ParagonIE\Paseto\Keys\SymmetricKey"
```

## Class Definition: `LocalWrap`

### Constructor

```php
/**
 * LocalWrap constructor.
 * @param Wrap $wrap
 */
public function __construct(Wrap $wrap): LocalWrap;
```

The `LocalWrap` class expects a vendor-specific `Wrap` object to be provided to
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
public static function initWithKey(SymmetricKey $key): LocalWrap;
```

This initializes a `LocalWrap` with the default `Wrap` implementation (`pie`),
passing the provided `SymmetricKey` to the `Wrap` instance, and returns the
`LocalWrap` class.

### Class Methods

#### `decode()`

```php
/**
 * @throws PaserkException
 */
public function decode(string $paserk): KeyInterface;
```

Note: Although the return type declaration is `KeyInterface`, `LocalWrap` returns
a `SymmetricKey`.

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
`SymmetricKey` to use `LocalWrap` serialization.

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
