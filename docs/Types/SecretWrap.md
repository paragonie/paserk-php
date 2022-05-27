# PASERK Type: SecretWrap

Example code:

```php
<?php
use ParagonIE\Paserk\Types\SecretWrap;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;

// You first need a wrapping key
$wrappingKey = SymmetricKey::generate(new Version4());

// Next, you can initialize the wrapper
$wrapper = SecretWrap::initWithKey($wrappingKey);

// Finally, you can wrap/unwrap your asymmetric secret keys.
$tempKey = AsymmetricSecretKey::generate(new Version4());
$paserk = $wrapper->encode($tempKey);
var_dump($paserk);

$unwrap = $wrapper->decode($paserk);
var_dump(get_class($unwrap));
```

Example output:

```
string(190) "k4.secret-wrap.pie.qLi63IiwlxcmggIwyX-jCAxu-irkMXWzRHUxYDoqJqCPy3B81y2THFSKrpg1860DUWN53lkdcsBeEsQbwlxaSFkgSdtxLS7TBz5opmt6Z-Wn
jRcpAlo2NtUMjFLFArR0GdRh_uxGkp6hA5dxlXMcaJAvJnhLVbjCkJFeH71R67E"
string(41) "ParagonIE\Paseto\Keys\AsymmetricSecretKey"
```

## Class Definition: `SecretWrap`


