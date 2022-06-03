# PASERK Type: Sid

Example code:

```php
<?php
use ParagonIE\Paserk\Types\Sid;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;

// Let's generate a Sid PASERK for v4
$exampleSecretKeyV4 = AsymmetricSecretKey::generate(new Version4());
$secretIdV4 = Sid::encodeSecret($exampleSecretKeyV4);
var_dump($secretIdV4);

// Now let's change the version to v3
$exampleSecretKeyV3 = new AsymmetricSecretKey($exampleSecretKeyV4->raw(), new Version3);
$secretIdV3 = Sid::encodeSecret($exampleSecretKeyV3);
var_dump($secretIdV3);

// This will always be bool(false)
var_dump($secretIdV3 === $secretIdV4);
```

Example output:

```
string(51) "k4.sid.Vt47YKER1_S7N2zj8CjpQMfoKdOu5l1vq_RctB9CYqhO"
string(51) "k3.sid.sESo8mlDN5bjjO-vnZ96QJ-jrgbg-YO35emyHC19V3bD"
bool(false)
```

## Class Definition: `Sid`

`Sid` is protocol-agnostic, since it's only concerned with the serialization
of keys and doesn't provide a deserialization interface.

### Static Methods

#### `encodeSecret()`

```php
/**
* @param AsymmetricSecretKey $sk
* @return string
* @throws PaserkException
* @throws SodiumException
*/
public static function encodeSecret(AsymmetricSecretKey $sk): string;
```

Passing an `AsymmetricSecretKey` to `Sid::encodeSecret()` will return a string containing
the encoded secret key.
