# PASERK Type: Local

Example code:

```php
<?php
use ParagonIE\Paserk\Types\Local;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\SymmetricKey;

// First, instantiate a `Local` object with a given PASETO version.
$encoder = new Local(new Version4);

// Now you can serialize/deserialize PASETO SymmetricKey objects.
$exampleKey = SymmetricKey::generate(new Version4());
$paserk = $encoder->encode($exampleKey);
var_dump($paserk);

// Later, you can get your SymmetricKey back using the same encoder:
$loaded = $encoder->decode($paserk);
var_dump(get_class($loaded));
```

Example output:

```
string(52) "k4.local.DRLpW2Actx5pn-tH7q8WVkSkRsEybLTe1yARIX64YZk"
string(34) "ParagonIE\Paseto\Keys\SymmetricKey"
```

## Class Definition: `Local`

### Constructor

```php
public function __construct(ProtocolInterface ...$versions): Local;
```

The `Local` class accepts multiple protocol versions as constructor arguments.
If not provided, it will default to only supporting Version 4.

### Class Methods

#### `decode()`

```php
/**
 * @param string $paserk
 * @return KeyInterface
 *
 * @throws PaserkException
 */
public function decode(string $paserk): KeyInterface;
```

Note: Although the return type declaration is `KeyInterface`, `Local` returns
a `SymmetricKey`.

#### `encode()`

```php
/**
 * @param KeyInterface $key
 * @return string
 *
 * @throws PaserkException
 */
public function encode(KeyInterface $key): string;
```

Note: Although the type declaration is `KeyInterface`, you **MUST** supply a
`SymmetricKey` to use `Local` serialization.

#### `id()`

```php
/**
 * Get the lid PASERK for the PASERK representation of this local key.
 *
 * @param KeyInterface $key
 * @return string
 * @throws PaserkException
 * @throws \SodiumException
 */
public function id(KeyInterface $key): string;
```

See [Lid](Lid.md#encodelocal).
