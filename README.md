# PASERK (PHP)

[![Build Status](https://github.com/paragonie/paserk-php/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/paserk-php/actions)
[![Latest Stable Version](https://poser.pugx.org/paragonie/paserk/v/stable)](https://packagist.org/packages/paragonie/paserk)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/paserk/v/unstable)](https://packagist.org/packages/paragonie/paserk)
[![License](https://poser.pugx.org/paragonie/paserk/license)](https://packagist.org/packages/paragonie/paserk)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/paserk.svg)](https://packagist.org/packages/paragonie/paserk)

Platform Agnostic SERialized Keys. **Requires PHP 7.1 or newer.**

## PASERK Specification

The PASERK Specification can be found [in this repository](https://github.com/paseto-standard/paserk).

## Installing

```terminal
composer require paragonie/paserk
```

### PASERK Library Versions

* PASERK PHP Version 2
  * Requires PHP 8.1+
  * PASETO versions: `v3`, `v4`
    * This means only the corresponding `k3` and `k4` modes are implemented.
* [PASERK PHP Version 1](https://github.com/paragonie/paserk-php/tree/v1.x)
  * Requires PHP 7.1+
  * PASETO versions: `v1`, `v2`, `v3`, `v4`
    * This provides a stable reference implementation for the PASERK specification.

## Documentation

See [this directory](docs) for the documentation.

## Example: Public-key Encryption

### Wrapping

```php
<?php
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paserk\Operations\Key\SealingPublicKey;
use ParagonIE\Paserk\Types\Seal;

$version = new Version4();

// First, you need a sealing keypair.

// $sealingSecret = ParagonIE\Paserk\Operations\Key\SealingSecretKey::generate();
// $sealingPublic = $sealingSecret->getPublicKey();
// var_dump($sealingSecret->encode(), $sealingPublic->encode());

$sealingPublic = SealingPublicKey::fromEncodedString(
    "vdd1m2Eri8ggYYR5YtnmEninoiCxH1eguGNKe4pes3g",
    $version
);
$sealer = new Seal($sealingPublic);

// Generate a random one-time key, which will be encrypted with the public key:
$key = SymmetricKey::generate($version);

// Seal means "public key encryption":
$paserk = $sealer->encode($key);

// Now let's associate this PASERK with a PASETO that uses the local key:
$paseto = Builder::getLocal($key, $version)
    ->with('test', 'readme')
    ->withExpiration(
        (new DateTime('NOW'))
            ->add(new DateInterval('P01D'))
    )
    ->withFooterArray(['kid' => $sealer->id($key)])
    ->toString();

var_dump($paserk, $paseto);
```

### Unwrapping

```php
<?php
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paserk\Operations\Key\SealingSecretKey;
use ParagonIE\Paserk\Types\Lid;
use ParagonIE\Paserk\Types\Seal;
use ParagonIE\Paseto\Parser as PasetoParser;
use ParagonIE\Paseto\ProtocolCollection;

$version = new Version4();

// From previous example:
$paserk = "k4.seal.F2qE4x0JfqT7JYhOB7S12SikvLaRuEpxRkgxxHfh4hVpE1JfwIDnreuhs9v5gjoBl3WTVjdIz6NkwQdqRoS2EDc3yGvdf_Da4K1xUSJ8IVTn4HQeol5ruYwjQlA_Ph4N";
$paseto = "v4.local.hYG-BfpTTM3bb-xZ-q5-w77XGayS4WA8kA5R5ZL85u3nzgrWba5NdqgIouFn71CJyGAff1eloirzz3sWRdVXnDeSIYxXDIerNkbLI5ALn24JehhSLKrv8R2-yhfo_XZF9XEASXtwrOyMNjeEAan5kqO6Dg.eyJraWQiOiJrNC5saWQueDAycGJDRmhxU1Q4endnbEJyR3VqWE9LYU5kRkJjY1dsTFFRN0pzcGlZM18ifQ";

// Keys for unsealing:
$sealingSecret = SealingSecretKey::fromEncodedString(
    "j043XiZTuGLleB0kAy8f3Tz-lEePK_ynEWPp4OyB-lS913WbYSuLyCBhhHli2eYSeKeiILEfV6C4Y0p7il6zeA",
    $version
);
$sealingPublic = $sealingSecret->getPublicKey();

// Unwrap the sytmmetric key for `v4.local.` tokens.
$sealer = new Seal($sealingPublic, $sealingSecret);
$unwrapped = $sealer->decode($paserk);

// Parse the PASETO
$parsed = PasetoParser::getLocal($unwrapped, ProtocolCollection::v4())
    ->parse($paseto);

// Get the claims from the parsed and validated token:
var_dump($parsed->getClaims());
/*
array(2) {
  ["test"]=>
  string(6) "readme"
  ["exp"]=>
  string(25) "2038-01-19T03:14:08+00:00"
}
*/

// Observe the Key ID is the same as the value stored in the footer.
var_dump(Lid::encode($version, $paserk));
var_dump($parsed->getFooterArray()['kid']);
/*
string(51) "k4.lid.x02pbCFhqST8zwglBrGujXOKaNdFBccWlLQQ7JspiY3_"
string(51) "k4.lid.x02pbCFhqST8zwglBrGujXOKaNdFBccWlLQQ7JspiY3_"
*/
```

## PASERK Feature Coverage

- [x] [`lid`](https://github.com/paseto-standard/paserk/blob/master/types/lid.md) 
- [x] [`local`](https://github.com/paseto-standard/paserk/blob/master/types/local.md) 
- [x] [`seal`](https://github.com/paseto-standard/paserk/blob/master/types/seal.md)
- [x] [`local-wrap`](https://github.com/paseto-standard/paserk/blob/master/types/local-wrap.md)
    - [x] [`pie`](https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md)
- [x] [`local-pw`](https://github.com/paseto-standard/paserk/blob/master/types/local-pw.md)
    * (Requires ext-sodium for v2/v4 keys, due to Argon2id)
- [x] [`pid`](https://github.com/paseto-standard/paserk/blob/master/types/pid.md)
- [x] [`public`](https://github.com/paseto-standard/paserk/blob/master/types/public.md)
- [x] [`secret`](https://github.com/paseto-standard/paserk/blob/master/types/secret.md)
- [x] [`secret-wrap`](https://github.com/paseto-standard/paserk/blob/master/types/secret-wrap.md)
    - [x] [`pie`](https://github.com/paseto-standard/paserk/blob/master/operations/Wrap/pie.md)
- [x] [`secret-pw`](https://github.com/paseto-standard/paserk/blob/master/types/secret-pw.md)
    * (Requires ext-sodium for v2/v4 keys, due to Argon2id)
