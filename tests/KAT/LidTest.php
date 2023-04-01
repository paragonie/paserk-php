<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\Lid;
use ParagonIE\Paseto\Exception\{
    InvalidVersionException,
    PasetoException
};
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\ProtocolInterface;
use SodiumException;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};

/**
 * @covers Lid
 */
class LidTest extends KnownAnswers
{
    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.lid.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.lid.json');
    }

    /**
     * @throws SodiumException
     * @throws PaserkException
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            if ($test['expect-fail']) {
                try {
                    $localkey = new SymmetricKey(Hex::decode($test['key']), $version);
                    Lid::encodeLocal($localkey);
                    $this->fail($test['name'] . ': '. $test['comment']);
                } catch (PaserkException $ex) {
                    $this->assertInstanceOf(PaserkException::class, $ex);
                } catch (PasetoException $ex) {
                    $this->assertInstanceOf(PasetoException::class, $ex);
                }
                continue;
            } else {
                $localkey = new SymmetricKey(Hex::decode($test['key']), $version);
            }
            $this->assertSame($test['paserk'], Lid::encodeLocal($localkey), $test['name']);
        }
    }
}
