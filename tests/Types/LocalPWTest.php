<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Types\LocalPW;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;

/**
 * Class LocalPWTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers LocalPW
 */
class LocalPWTest extends TestCase
{
    /** @var ProtocolInterface[] */
    protected array $versions = [];

    public function setUp(): void
    {
        $this->versions = [
            new Version3(),
            new Version4()
        ];
    }

    public function testLocalPW()
    {
        $password = new HiddenString('correct horse battery staple');
        $testConfig = [
            'iterations' => 1000,
            'memlimit' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            'opslimit' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            'parallelism' => 1,
        ];

        foreach ($this->versions as $v) {
            $wrapper = new LocalPW($password, $testConfig, $v);
            $sym = SymmetricKey::generate($v);
            $wrapped = $wrapper->encode($sym);
            /** @var SymmetricKey $unwrap */
            $unwrap = $wrapper->decode($wrapped);
            $this->assertSame(
                $sym->encode(),
                $unwrap->encode()
            );
        }
    }
}
