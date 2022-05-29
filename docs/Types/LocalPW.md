# PASERK Type: LocalPW

Example code:

```php
<?php
use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Types\LocalPW;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\SymmetricKey;

// First, initialize the wrapper with the password
$options = [
    'opslimit' => 2,
    'memlimit' => 67108864 
];
$wrapper = new LocalPW(new HiddenString('correct horse battery staple'), $options, new Version4());

// Finally, you can wrap/unwrap your symmetric keys.
$tempKey = SymmetricKey::generate(new Version4());
$paserk = $wrapper->encode($tempKey);
var_dump($paserk);

$unwrap = $wrapper->decode($paserk);
var_dump(get_class($unwrap));
```

Example output:

```
string(172) "k4.local-pw.gS6pSG9MkJfwbbuG6VCXZwAAAAAEAAAAAAAAAgAAAAHpE_dZQiM1u2Gt6t_NUtn8PxMA25xa8mnAQ0ntoHv0u6OBK6UJSj7Q56ng5v1YPPicLMGupDK
wT-XieLjL5aZ-LDbY9nucnKZeQpf3HK0W14XQ4qeXatu3"
string(34) "ParagonIE\Paseto\Keys\SymmetricKey"
```

## Class Definition: `LocalPW`

### Constructor

```php
/**
 * LocalPW constructor.
 *
 * @param HiddenString $password
 * @param array $options
 * @param ProtocolInterface ...$version
 * @throws InvalidVersionException
 */
public function __construct(
    HiddenString $password,
    array $options = [],
    ProtocolInterface ...$version
): LocalPW;
```

### Methods

#### `decode()`

```php
/**
 * @param string $paserk
 * @return KeyInterface
 * @throws PaserkException
 */
public function decode(string $paserk): KeyInterface;
```

Note: Although the return type declaration is `KeyInterface`, `LocalPW` returns
a `SymmetricKey`.

#### `encode()`

```php
/**
 * @param KeyInterface $key
 * @return string
 * @throws PaserkException
 */
public function encode(KeyInterface $key): string;
```

Note: Although the type declaration is `KeyInterface`, you **MUST** supply a
`SymmetricKey` to use `LocalPW` serialization.

#### `id()`

```php
/**
 * Get the lid PASERK for the PASERK representation of this local key.
 *
 * @param KeyInterface $key
 * @return string
 *
 * @throws PaserkException
 * @throws \SodiumException
 */
public function id(KeyInterface $key): string;
```

See [Lid](Lid.md#encodelocal).
