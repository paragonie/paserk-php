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


