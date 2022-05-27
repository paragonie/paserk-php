# PASERK Type: SecretPW

Example code:

```php
<?php
use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Types\SecretPW;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;

// First, initialize the wrapper with the password
$options = [
    'opslimit' => 2,
    'memlimit' => 67108864 
];
$wrapper = new SecretPW(new HiddenString('correct horse battery staple'), $options, new Version4());

// Finally, you can wrap/unwrap your asymmetric secret keys.
$tempKey = AsymmetricSecretKey::generate(new Version4());
$paserk = $wrapper->encode($tempKey);
var_dump($paserk);

$unwrap = $wrapper->decode($paserk);
var_dump(get_class($unwrap));
```

Example output:

```
string(216) "k4.secret-pw.uWNbaWszbJckOIBB_U2YjAAAAAAEAAAAAAAAAgAAAAEAPP_AKKmd0EUSQDdsLiZqb2XFpSHXl79K0JwuKjQF8mlU6eMENiJdF7Ca6XpMb4QKoiH4ha
MTm5o6LqDlORZlWFZh8-hHVsVFtAjPlBh8C6s5oS9mxlSUEKXDNIlvh5Kx1lMcQBx5jK2JjLNu0rr3SugqX4XUvkY"
string(41) "ParagonIE\Paseto\Keys\AsymmetricSecretKey"
```

## Class Definition: `SecretPW`

### Constructor

```php
/**
 * SecretPW constructor.
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
): SecretPW;
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

Note: Although the return type declaration is `KeyInterface`, `SecretPW` returns
an `AsymmetricSecretKey`.

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
`AsymmetricSecretKey` to use `SecretPW` serialization.

#### `id()`

```php
/**
 * Get the sid PASERK for the PASERK representation of this secret key.
 *
 * @param KeyInterface $key
 * @return string
 *
 * @throws PaserkException
 * @throws \SodiumException
 */
public function id(KeyInterface $key): string;
```

See [Sid](Sid.md#encodesecret).
