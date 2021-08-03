<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use Exception;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\SecretType;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};

/**
 * @covers Secret
 */
class SecretTest extends KnownAnswers
{
    public function testV1()
    {
        $this->doJsonTest(new Version1(), 'k1.secret.json');
    }

    public function testV2()
    {
        $this->doJsonTest(new Version2(), 'k2.secret.json');
    }

    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.secret.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.secret.json');
    }

    /**
     * @throws Exception
     * @throws PaserkException
     */
    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            if ($version instanceof Version1) {
                $publickey = new AsymmetricSecretKey($test['key'], $version);
            } else {
                $publickey = new AsymmetricSecretKey(Hex::decode($test['key']), $version);
            }
            $this->assertSame($test['paserk'], (new SecretType())->encode($publickey), $test['name']);
        }
    }
}
