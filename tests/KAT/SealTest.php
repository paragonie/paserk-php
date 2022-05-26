<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use Exception;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\Seal;
use ParagonIE\Paserk\Operations\Key\{
    SealingSecretKey,
    SealingPublicKey
};
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;

/**
 * @covers Seal
 */
class SealTest extends KnownAnswers
{
    public function testV1()
    {
        $this->doJsonTest(new Version1(), 'k1.seal.json');
    }

    public function testV2()
    {
        $this->doJsonTest(new Version2(), 'k2.seal.json');
    }

    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.seal.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.seal.json');
    }

    /**
     * @throws Exception
     * @throws PaserkException
     */
    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            if ($version::header() === 'v1' || $version::header() === 'v3') {
                $sk = new SealingSecretKey($test['sealing-secret-key'], $version);
                $pk = new SealingPublicKey($test['sealing-public-key'], $version);
            } else {
                $sk = new SealingSecretKey(Hex::decode($test['sealing-secret-key']), $version);
                $pk = new SealingPublicKey(Hex::decode($test['sealing-public-key']), $version);
            }
            $processor = new Seal($pk, $sk);
            if ($test['expect-fail']) {
                try {
                    $processor->decode($test['paserk']);
                } catch (\Throwable $exception) {
                    continue;
                }
                $this->fail($name . ' > ' . $test['name'] . ': '. $test['comment']);
            }
            $unsealed = $processor->decode($test['paserk']);
            $this->assertSame(
                $test['unsealed'],
                Hex::encode($unsealed->raw()),
                $test['name']
            );
        }
    }
}
