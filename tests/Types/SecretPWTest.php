<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Types\SecretPW;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;

/**
 * Class SecretPWTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers SecretPW
 */
class SecretPWTest extends TestCase
{
    /** @var ProtocolInterface[] */
    protected $versions = [];

    public function setUp(): void
    {
        $this->versions = [
            new Version3(),
            new Version4()
        ];
    }

    public function testSecretPW()
    {
        $password = new HiddenString('correct horse battery staple');
        $testConfig = [
            'iterations' => 1000,
            'memlimit' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            'opslimit' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            'parallelism' => 1,
        ];

        foreach ($this->versions as $v) {
            $wrapper = new SecretPW($password, $testConfig, $v);
            $asym = AsymmetricSecretKey::generate($v);
            $wrapped = $wrapper->encode($asym);
            /** @var AsymmetricSecretKey $unwrap */
            $unwrap = $wrapper->decode($wrapped);
            $this->assertSame(
                $asym->encode(),
                $unwrap->encode()
            );
        }
    }
}
