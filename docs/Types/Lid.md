# PASERK Type: Lid

Example code:

```php
<?php
use ParagonIE\Paserk\Types\Lid;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\SymmetricKey;

// First, generate a random byte string
$random = random_bytes(32);

// Let's generate a lid PASERK for v4
$exampleKeyV4 = new SymmetricKey($random, new Version4());
$localIdV4 = Lid::encodeLocal($exampleKeyV4);
var_dump($localIdV4);

// Now let's change the version to v3
$exampleKeyV3 = new SymmetricKey($random, new Version3());
$localIdV3 = Lid::encodeLocal($exampleKeyV3);
var_dump($localIdV3);

// This will always be bool(false)
var_dump($localIdV3 === $localIdV4);
```

Example output:

```
string(51) "k4.lid.2N8TN2O2FN0TuhOHDMoDSlc_xW8Eu-NsmbDEu0NGn_e4"
string(51) "k3.lid.9gGwgwP0v1z-PS5_q2YrCUvzBIbgQZuuXZGXXPeTDtvC"
bool(false)
```

## Class Definition: `Lid`


