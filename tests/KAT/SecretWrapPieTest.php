<?php

namespace ParagonIE\Paserk\Tests\KAT;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\Operations\Wrap;
use ParagonIE\Paserk\Operations\Wrap\Pie;
use ParagonIE\Paserk\Types\SecretWrap;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;

/**
 * @covers SecretWrap
 */
class SecretWrapPieTest extends KnownAnswers
{
    public function testV1()
    {
        $this->doJsonTest(new Version1(), 'k1.secret-wrap.pie.json');
    }

    public function testV2()
    {
        $this->doJsonTest(new Version2(), 'k2.secret-wrap.pie.json');
    }

    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.secret-wrap.pie.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.secret-wrap.pie.json');
    }

    /**
     * @param ProtocolInterface $version
     * @param string $name
     * @param array $tests
     */
    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            $wrapkey = new SymmetricKey(Hex::decode($test['wrapping-key']), $version);
            $wrapper = (new SecretWrap(new Wrap(new Pie($wrapkey))));
            $unwrapped = $wrapper->decode($test['paserk']);

            if ($version instanceof Version1) {
                $this->assertSame($test['unwrapped'], $unwrapped->raw(), $test['name']);
            } else {
                $this->assertSame(
                    $test['unwrapped'],
                    Hex::encode($unwrapped->raw()),
                    $test['name']
                );
            }
        }
    }
}
