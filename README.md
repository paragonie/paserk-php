# PASERK

[![Build Status](https://github.com/paragonie/paserk-php/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/paserk-php/actions)
[![Latest Stable Version](https://poser.pugx.org/paragonie/paserk-php/v/stable)](https://packagist.org/packages/paragonie/paserk)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/paserk-php/v/unstable)](https://packagist.org/packages/paragonie/paserk)
[![License](https://poser.pugx.org/paragonie/paserk-php/license)](https://packagist.org/packages/paragonie/paserk)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/paserk.svg)](https://packagist.org/packages/paragonie/paserk)

Platform Agnostic SERialized Keys. **Requires PHP 7.1 or newer.**

## PASERK Specification

The PASERK Specification can be found [in this repository](https://github.com/paseto-standard/paserk).

## Installing

```terminal
composer require paragonie/paserk
```

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

$key = SymmetricKey::generate($version);

$paserk = $sealer->encode($key);
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

$sealer = new Seal($sealingPublic, $sealingSecret);
$unwrapped = $sealer->decode($paserk);

$parsed = PasetoParser::getLocal($unwrapped, ProtocolCollection::v4())
    ->parse($paseto);

var_dump($parsed->getClaims());
/*
array(2) {
  ["test"]=>
  string(6) "readme"
  ["exp"]=>
  string(25) "2038-01-19T03:14:08+00:00"
}
*/

var_dump(Lid::encode($version, $paserk));
var_dump($parsed->getFooterArray()['kid']);
/*
string(51) "k4.lid.x02pbCFhqST8zwglBrGujXOKaNdFBccWlLQQ7JspiY3_"
string(51) "k4.lid.x02pbCFhqST8zwglBrGujXOKaNdFBccWlLQQ7JspiY3_"
*/
```
