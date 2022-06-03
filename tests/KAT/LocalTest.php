<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\Local;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};

/**
 * @covers Local
 */
class LocalTest extends KnownAnswers
{
    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.local.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.local.json');
    }

    /**
     * @throws PaserkException
     */
    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        $local = new Local($version);
        foreach ($tests as $test) {
            if ($test['expect-fail']) {
                if (is_null($test['key'])) {
                    try {
                        $local->decode($test['paserk']);
                        $this->fail($test['name'] . ': ' . $test['comment']);
                    } catch (PaserkException $ex) {
                    }
                    continue;
                }

                $localkey = new SymmetricKey(Hex::decode($test['key']), $version);
                try {
                    $local->encode($localkey);
                    $this->fail($test['name'] . ': ' . $test['comment']);
                } catch (PaserkException $ex) {
                }

                continue;
            }
            $localkey = new SymmetricKey(Hex::decode($test['key']), $version);
            $this->assertSame($test['paserk'], $local->encode($localkey), $test['name']);
        }
    }
}
