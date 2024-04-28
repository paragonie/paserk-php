<?php
namespace ParagonIE\Paserk\Tests;

use DateTime;
use DateInterval;
use ParagonIE\Paserk\Operations\Key\{
    SealingPublicKey,
    SealingSecretKey
};
use ParagonIE\Paserk\Types\Seal;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\JsonToken;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Parser as PasetoParser;
use ParagonIE\Paseto\ProtocolCollection;
use PHPUnit\Framework\TestCase;

/**
 * @covers Seal
 */
class ReadmeTest extends TestCase
{
    public function testReamdeCodePaths()
    {
        $version = new Version4();
        $sealingPublic = SealingPublicKey::fromEncodedString(
            "vdd1m2Eri8ggYYR5YtnmEninoiCxH1eguGNKe4pes3g",
            $version
        );
        $sealer = new Seal($sealingPublic);

        // Generate a random one-time key, which will be encrypted with the public key:
        $key = SymmetricKey::generate($version);

        // Seal means "public key encryption":
        $paserk = $sealer->encode($key);
        $this->assertIsString($paserk);

        // Now let's associate this PASERK with a PASETO that uses the local key:
        $paseto = Builder::getLocal($key, $version)
            ->with('test', 'readme')
            ->withExpiration(
                (new DateTime('NOW'))
                    ->add(new DateInterval('P01D'))
            )
            ->withFooterArray(['kid' => $sealer->id($key)])
            ->toString();
        $this->assertIsString($paseto);

        // Keys for unsealing:
        $sealingSecret = SealingSecretKey::fromEncodedString(
            "j043XiZTuGLleB0kAy8f3Tz-lEePK_ynEWPp4OyB-lS913WbYSuLyCBhhHli2eYSeKeiILEfV6C4Y0p7il6zeA",
            $version
        );

        // Unwrap the sytmmetric key for `v4.local.` tokens.
        $sealer = new Seal($sealingPublic, $sealingSecret);
        /** @var SymmetricKey $unwrapped */
        $unwrapped = $sealer->decode($paserk);

        // Parse the PASETO
        $parsed = PasetoParser::getLocal($unwrapped, ProtocolCollection::v4())
            ->parse($paseto);
        $this->assertInstanceOf(JsonToken::class, $parsed);
    }
}
