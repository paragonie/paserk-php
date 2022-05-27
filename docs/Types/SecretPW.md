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


