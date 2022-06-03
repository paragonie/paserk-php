<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;
use ParagonIE\Paserk\Types\SecretType;

/**
 * Class PublicTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers SecretType
 */
class SecretTest extends TestCase
{
    protected AsymmetricPublicKey $v3pk;
    protected AsymmetricPublicKey $v4pk;
    protected AsymmetricSecretKey $v3sk;
    protected AsymmetricSecretKey $v4sk;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->v3sk = AsymmetricSecretKey::generate(new Version3());
        $this->v3pk = $this->v3sk->getPublicKey();
        $this->v4sk = AsymmetricSecretKey::generate(new Version4());
        $this->v4pk = $this->v4sk->getPublicKey();
    }

    public function testEncodeDecode()
    {
        /** @var AsymmetricPublicKey $key */
        foreach ([$this->v3sk, $this->v4sk] as $key) {
            $secret = new SecretType($key->getProtocol());
            $encoded = $secret->encode($key);
            $decoded = $secret->decode($encoded);
            $this->assertSame(
                $key->encode(),
                $decoded->encode(),
                'Key encoding failed: ' . $encoded
            );
        }
    }
}
