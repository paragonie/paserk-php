# PASERK Type: LocalPW

Example code:

```php
<?php
use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Types\LocalPW;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\SymmetricKey;

// First, initialize the wrapper with the password
$options = [
    'opslimit' => 2,
    'memlimit' => 67108864 
];
$wrapper = new LocalPW(new HiddenString('correct horse battery staple'), $options, new Version4());

// Finally, you can wrap/unwrap your symmetric keys.
$tempKey = SymmetricKey::generate(new Version4());
$paserk = $wrapper->encode($tempKey);
var_dump($paserk);

$unwrap = $wrapper->decode($paserk);
var_dump(get_class($unwrap));
```

Example output:

```
string(172) "k4.local-pw.gS6pSG9MkJfwbbuG6VCXZwAAAAAEAAAAAAAAAgAAAAHpE_dZQiM1u2Gt6t_NUtn8PxMA25xa8mnAQ0ntoHv0u6OBK6UJSj7Q56ng5v1YPPicLMGupDK
wT-XieLjL5aZ-LDbY9nucnKZeQpf3HK0W14XQ4qeXatu3"
string(34) "ParagonIE\Paseto\Keys\SymmetricKey"
```

## Class Definition: `LocalPW`


