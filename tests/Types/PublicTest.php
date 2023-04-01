<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use Exception;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Base\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;
use ParagonIE\Paserk\Types\PublicType;

/**
 * Class PublicTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers PublicType
 */
class PublicTest extends TestCase
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
        $this->v3sk = AsymmetricSecretKey::generate(new Version3());
        $this->v3pk = $this->v3sk->getPublicKey();
        $this->v4sk = AsymmetricSecretKey::generate(new Version4());
        $this->v4pk = $this->v4sk->getPublicKey();
    }

    /**
     * @throws InvalidVersionException
     * @throws PaserkException
     * @throws PasetoException
     */
    public function testEncodeDecode()
    {
        /** @var AsymmetricPublicKey $key */
        foreach ([$this->v3pk, $this->v4pk] as $key) {
            $public = new PublicType($key->getProtocol());
            $encoded = $public->encode($key);
            $decoded = $public->decode($encoded);
            $this->assertSame(
                $key->encode(),
                $decoded->encode(),
                'Key encoding failed: ' . $encoded
            );
        }
    }

    /**
     * @throws PaserkException
     * @throws PasetoException
     */
    public function testRejectSecret()
    {
        $public = new PublicType();
        $this->expectException(PaserkException::class);
        $public->encode($this->v3sk);
    }
}
