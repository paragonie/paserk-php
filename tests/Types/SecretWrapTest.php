<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\Paserk\Types\SecretWrap;
use ParagonIE\Paserk\Types\Sid;
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;

/**
 * Class SecretWrapTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers SecretWrap
 */
class SecretWrapTest extends TestCase
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


    public function testWrap()
    {
        /** @var SymmetricKey $key */
        foreach ([$this->v3sk, $this->v4sk] as $key) {
            // Generate wrapping key
            $version = $key->getProtocol();
            $wk = SymmetricKey::generate($version);
            $sw = SecretWrap::initWithKey($wk);

            $id = $sw->id($key);
            $encoded = $sw->encode($key);
            $id2 = Sid::encode($version, $encoded);
            $this->assertSame($id2, $id, 'Local-wrap key IDs must be deterministic');

            /** @var AsymmetricSecretKey $decoded */
            $decoded = $sw->decode($encoded);
            $this->assertSame(
                $key->encode(),
                $decoded->encode(),
                'secret-wrap ' . $key->getProtocol()::header()
            );
        }
    }
}