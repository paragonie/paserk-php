<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Types\Local;
use ParagonIE\Paserk\Types\PublicType;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;

/**
 * Class LocalTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers Local
 */
class LocalTest extends TestCase
{
    protected SymmetricKey $v3key;
    protected SymmetricKey $v4key;

    public function setUp(): void
    {
        $this->v3key = SymmetricKey::generate(new Version3());
        $this->v4key = SymmetricKey::generate(new Version4());
    }

    /**
     * @throws PaserkException
     * @throws InvalidVersionException
     */
    public function testEncode()
    {
        /** @var SymmetricKey $key */
        foreach ([$this->v3key, $this->v4key] as $key) {
            $local = new Local($key->getProtocol());
            $encoded = $local->encode($key);
            $decoded = $local->decode($encoded);
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
    public function testRejectPublic()
    {
        $keypair = AsymmetricSecretKey::generate(new Version4());

        $local = new Local();
        $public = new PublicType();
        $v4pub = $public->encode($keypair->getPublicKey());

        $this->expectException(PaserkException::class);
        $local->decode($v4pub);
    }
}
