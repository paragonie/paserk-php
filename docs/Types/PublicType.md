# PASERK Type: Public

Example code:

```php
<?php
use ParagonIE\Paserk\Types\PublicType;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;

// First, instantiate a `PublicType` object with a given PASETO version.
$encoder = new PublicType(new Version4());

// Now you can serialize/deserialize PASETO AsymmetricPublicKey objects.
$exampleSecretKey = AsymmetricSecretKey::generate(new Version4());
$examplePublicKey = $exampleSecretKey->getPublicKey();
$paserk = $encoder->encode($examplePublicKey);

var_dump($paserk);

// Later, you can get your AsymmetricPublicKey back using the same encoder:
$loaded = $encoder->decode($paserk);
var_dump(get_class($loaded));
```

Example output:

```
string(53) "k4.public._kbdHXizFdv0Vhw3PKaDyWuC-9B2-XHwTwqw0TCVfCw"
string(41) "ParagonIE\Paseto\Keys\AsymmetricPublicKey"
```

## Class Definition: `PublicType`


