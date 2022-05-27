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


