<?php

declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
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
    /** @var AsymmetricPublicKey $v1pk */
    protected $v1pk;
    /** @var AsymmetricPublicKey $v2pk */
    protected $v2pk;
    /** @var AsymmetricPublicKey $v3pk */
    protected $v3pk;
    /** @var AsymmetricPublicKey $v4pk */
    protected $v4pk;
    /** @var AsymmetricSecretKey $v1sk */
    protected $v1sk;
    /** @var AsymmetricSecretKey $v2sk */
    protected $v2sk;
    /** @var AsymmetricSecretKey $v3sk */
    protected $v3sk;
    /** @var AsymmetricSecretKey $v4sk */
    protected $v4sk;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->v1sk = AsymmetricSecretKey::generate(new Version1());
        $this->v1pk = $this->v1sk->getPublicKey();
        $this->v2sk = AsymmetricSecretKey::generate(new Version2());
        $this->v2pk = $this->v2sk->getPublicKey();
        $this->v3sk = AsymmetricSecretKey::generate(new Version3());
        $this->v3pk = $this->v3sk->getPublicKey();
        $this->v4sk = AsymmetricSecretKey::generate(new Version4());
        $this->v4pk = $this->v4sk->getPublicKey();
    }

    public function testEncodeDecode()
    {
        $secret = new SecretType();
        /** @var AsymmetricPublicKey $key */
        foreach ([$this->v1sk, $this->v2sk, $this->v3sk, $this->v4sk] as $key) {
            $encoded = $secret->encode($key);
            $decoded = $secret->decode($encoded);
            if ($key->getProtocol() instanceof Version1) {
                // Compare raw -> compare PEM-encoded
                $this->assertSame(
                    $key->raw(),
                    $decoded->raw(),
                    'Key encoding failed: ' . $encoded
                );
            } else {
                $this->assertSame(
                    $key->encode(),
                    $decoded->encode(),
                    'Key encoding failed: ' . $encoded
                );
            }
        }
    }
}