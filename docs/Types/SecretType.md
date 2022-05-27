# PASERK Type: Secret

Example code:

```php
<?php
use ParagonIE\Paserk\Types\SecretType;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;

// First, instantiate a `SecretType` object with a given PASETO version.
$encoder = new SecretType(new Version4());

// Now you can serialize/deserialize PASETO AsymmetricSecretKey objects.
$exampleSecretKey = AsymmetricSecretKey::generate(new Version4());
$paserk = $encoder->encode($exampleSecretKey);

var_dump($paserk);

// Later, you can get your AsymmetricSecretKey back using the same encoder:
$loaded = $encoder->decode($paserk);
var_dump(get_class($loaded));
```

Example output:

```
string(96) "k4.secret.RZ_s4OHGNOydu60xT3gHeFuNKFr-xRIurUMuDMVhcWwV9QDT35vAA0qox1r1A_W5JVvsKDmqpWdEp1m4VIEj0g"
string(41) "ParagonIE\Paseto\Keys\AsymmetricSecretKey"
```

## Class Definition: `SecretType`

### Constructor

```php
public function __construct(ProtocolInterface ...$versions): Local;
```

The `SecretType` class accepts multiple protocol versions as constructor arguments.
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

Note: Although the return type declaration is `KeyInterface`, `SecretType` returns
an `AsymmetricSecretKey`.

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
`AsymmetricSecretKey` to use `SecretType` serialization.

#### `id()`

```php
/**
 * Get the sid PASERK for the PASERK representation of this local key.
 *
 * @param KeyInterface $key
 * @return string
 * @throws PaserkException
 * @throws \SodiumException
 */
public function id(KeyInterface $key): string;
```

See [Sid](Sid.md#encodesecret).
