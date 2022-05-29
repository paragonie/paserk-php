<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Types\Local;
use ParagonIE\Paserk\Types\PublicType;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
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
    protected $v1key;
    protected $v2key;
    protected $v3key;
    protected $v4key;

    public function setUp(): void
    {
        $this->v1key = SymmetricKey::generate(new Version1());
        $this->v2key = SymmetricKey::generate(new Version2());
        $this->v3key = SymmetricKey::generate(new Version3());
        $this->v4key = SymmetricKey::generate(new Version4());
    }

    /**
     * @throws PaserkException
     */
    public function testEncode()
    {
        /** @var SymmetricKey $key */
        foreach ([$this->v1key, $this->v2key, $this->v3key, $this->v4key] as $key) {
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

    public function testRejectPublic()
    {
        $keypair = AsymmetricSecretKey::generate(new Version4());

        $local = new Local();
        $public = new PublicType();
        $v2pub = $public->encode($keypair->getPublicKey());

        $this->expectException(PaserkException::class);
        $local->decode($v2pub);
    }
}
