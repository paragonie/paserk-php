# PASERK Type: Seal

Example code:

```php
<?php
use ParagonIE\Paserk\Types\Seal;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paserk\Operations\Key\SealingSecretKey;
use ParagonIE\Paserk\Operations\Key\SealingPublicKey;
use ParagonIE\Paseto\Keys\SymmetricKey;

// First, you need a keypair for sealing.
//
// For some versions (i.e. v1), these are distinct from the PASETO keys,
// so generate them separately.
$sealingSecretKey = SealingSecretKey::generate(new Version4());
$sealingPublicKey = $sealingSecretKey->getPublicKey();

// Next, you will need to instantiate the sealer with the public key:
$sealer = new Seal($sealingPublicKey);

// Now you can encode your SymmetricKey objects.
$tempKey = SymmetricKey::generate(new Version4());
$paserk = $sealer->encode($tempKey);
var_dump($paserk);

// However, you cannot unseal them if you only have the public key!
try {
    $sealer->decode($paserk);
} catch (\ParagonIE\Paserk\PaserkException $ex) {
    var_dump($ex->getMessage());
}

// But, If you provide the Secret Key...
$unsealer = Seal::fromSecretKey($sealingSecretKey);
    // Alternative:
    // $unsealer = new Seal($sealingPublicKey, $sealingSecretKey);

// ...Then you can unseal them too:
$symmetric = $unsealer->decode($paserk);
var_dump(get_class($symmetric));
```

Example output:

```
string(136) "k4.seal.xM3fWakJQ-98b-3lYjCH2SWkaJndYiTCBZ8_MMh82J9JYTojNsf9a4P7b2ZmpP6eoRbNzbyx761evqqL3KL3dyGcW4Vy_jsCQLTnE6WthGwEg104-ziIxFR
2qj10FJ7L"
string(41) "No secret key was provided; cannot unseal"
string(34) "ParagonIE\Paseto\Keys\SymmetricKey"
```

## Class Definition: `Seal`


