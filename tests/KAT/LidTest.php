<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\Lid;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};

/**
 * @covers Lid
 */
class LidTest extends KnownAnswers
{
    public function testV1()
    {
        $this->doJsonTest(new Version1(), 'k1.lid.json');
    }

    public function testV2()
    {
        $this->doJsonTest(new Version2(), 'k2.lid.json');
    }

    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.lid.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.lid.json');
    }

    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            $localkey = new SymmetricKey(Hex::decode($test['key']), $version);
            $this->assertSame($test['paserk'], Lid::encodeLocal($localkey), $test['name']);
        }
    }
}
