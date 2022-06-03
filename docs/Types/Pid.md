# PASERK Type: Pid

Example code:

```php
<?php
use ParagonIE\Paserk\Types\Pid;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;

// Let's generate a Pid PASERK for v4
$exampleSecretKeyV4 = AsymmetricSecretKey::generate(new Version4());
$examplePublicKeyV4 = $exampleSecretKeyV4->getPublicKey();
$publicIdV4 = Pid::encodePublic($examplePublicKeyV4);
var_dump($publicIdV4);

// Now let's change the version to v3
$exampleSecretKeyV3 = new AsymmetricSecretKey($exampleSecretKeyV4->raw(), new Version3);
$examplePublicKeyV3 = $exampleSecretKeyV2->getPublicKey();
$publicIdV3 = Pid::encodePublic($examplePublicKeyV3);
var_dump($publicIdV3);

// This will always be bool(false)
var_dump($publicIdV3 === $publicIdV4);
```

Example output:

```
string(51) "k4.pid.7YHEK_2Pbpe1pB3520MjzTe2sGcA0pV54SyIt2qMgAcq"
string(51) "k3.pid.Yh_AqamsJznJMNU6qZ2xZGSs9IyW3b12e7W-rR6wLYDw"
bool(false)
```

## Class Definition: `Pid`

`Pid` is protocol-agnostic, since it's only concerned with the serialization
of keys and doesn't provide a deserialization interface.

### Static Methods

#### `encodePublic()`

```php
/**
* @param AsymmetricPublicKey $sk
* @return string
* @throws PaserkException
* @throws SodiumException
*/
public static function encodePublic(AsymmetricPublicKey $sk): string;
```

Passing an `AsymmetricPublicKey` to `Pid::encodePublic()` will return a string containing
the encoded public key.
