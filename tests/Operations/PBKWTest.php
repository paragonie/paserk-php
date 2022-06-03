<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Operations;

use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Operations\PBKW;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;

/**
 * Class PBKWTest
 * @package ParagonIE\Paserk\Tests\Operations
 *
 * @covers PBKW
 */
class PBKWTest extends TestCase
{
    /** @var ProtocolInterface[] */
    protected $versions = [];

    public function setUp(): void
    {
        $this->versions = [
            new Version3(),
            new Version4(),
        ];
    }

    /**
     * @throws PaserkException
     */
    public function testWrap()
    {
        $password = new HiddenString('correct horse battery staple');
        $testConfig = [
            'iterations' => 1000,
            'memlimit' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            'opslimit' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            'parallelism' => 1,
        ];

        foreach ($this->versions as $v) {
            $pbkw = PBKW::forVersion($v);

            $localKey = SymmetricKey::generate($v);
            $secretKey = AsymmetricSecretKey::generate($v);

            $lw = $pbkw->localPwWrap($localKey, $password, $testConfig);
            $lu = $pbkw->localPwUnwrap($lw, $password);
            $this->assertSame($lu->encode(), $localKey->encode());

            $sw = $pbkw->secretPwWrap($secretKey, $password, $testConfig);
            $su = $pbkw->secretPwUnwrap($sw, $password);
            $this->assertSame($su->encode(), $secretKey->encode());
        }
    }
}
