<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\Sid;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};

/**
 * @covers Sid
 */
class SidTest extends KnownAnswers
{
    public function testV1()
    {
        $this->doJsonTest(new Version1(), 'k1.sid.json');
    }

    public function testV2()
    {
        $this->doJsonTest(new Version2(), 'k2.sid.json');
    }

    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.sid.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.sid.json');
    }

    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            if ($version instanceof Version1) {
                $publickey = new AsymmetricSecretKey($test['key'], $version);
            } else {
                $publickey = new AsymmetricSecretKey(Hex::decode($test['key']), $version);
            }
            $this->assertSame($test['paserk'], Sid::encodeSecret($publickey), $test['name']);
        }
    }
}
