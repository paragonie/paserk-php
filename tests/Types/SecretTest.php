<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\Paseto\Keys\Base\{
    AsymmetricPublicKey,
    AsymmetricSecretKey
};
use ParagonIE\Paseto\Keys\Version3\{
    AsymmetricPublicKey as V3AsymmetricPublicKey,
    AsymmetricSecretKey as V3AsymmetricSecretKey
};
use ParagonIE\Paseto\Keys\Version4\{
    AsymmetricPublicKey as V4AsymmetricPublicKey,
    AsymmetricSecretKey as V4AsymmetricSecretKey
};
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;
use ParagonIE\Paserk\Types\SecretType;
use Exception;

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
     * @throws Exception
     */
    public function setUp(): void
    {
        $this->v3sk = V3AsymmetricSecretKey::generate();
        $this->v3pk = $this->v3sk->getPublicKey();
        $this->v4sk = V4AsymmetricSecretKey::generate(new Version4());
        $this->v4pk = $this->v4sk->getPublicKey();
    }

    /**
     * @throws PaserkException
     * @throws InvalidVersionException
     * @throws PasetoException
     */
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
