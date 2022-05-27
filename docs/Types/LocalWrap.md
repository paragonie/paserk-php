# PASERK Type: LocalWrap

Example code:

```php
<?php
use ParagonIE\Paserk\Types\LocalWrap;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\SymmetricKey;

// You first need a wrapping key
$wrappingKey = SymmetricKey::generate(new Version4());

// Next, you can initialize the wrapper
$wrapper = LocalWrap::initWithKey($wrappingKey);

// Finally, you can wrap/unwrap your symmetric keys.
$tempKey = SymmetricKey::generate(new Version4());
$paserk = $wrapper->encode($tempKey);
var_dump($paserk);

$unwrap = $wrapper->decode($paserk);
var_dump(get_class($unwrap));
```

Example output:

```
string(146) "k4.local-wrap.pie.b66FQOk3Akt1IbmHT47GDOCtoEpVYmpMxuk7bdsmrbQgskP_zDZXZrYc5nVZrEq2kUWeb9Ni0fkay1A4pSJQ5Y9mLjlJNMfXxASozOgLw_BoD
bbMGl7q5TM8TSfGil-D"
string(34) "ParagonIE\Paseto\Keys\SymmetricKey"
```

## Class Definition: `LocalWrap`


