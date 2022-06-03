<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use FG\ASN1\Exception\ParserException;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\Pid;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};

/**
 * @covers Pid
 */
class PidTest extends KnownAnswers
{
    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.pid.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.pid.json');
    }

    /**
     * @throws \Exception
     */
    protected function getPublicKey(ProtocolInterface $version, string $key): AsymmetricPublicKey
    {
        return new AsymmetricPublicKey(Hex::decode($key), $version);
    }

    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            if ($test['expect-fail']) {
                try {
                    $publickey = $this->getPublicKey($version, $test['key']);
                    Pid::encodePublic($publickey);
                    $this->fail($test['name'] . ': '. $test['comment']);
                } catch (ParserException | \RangeException | PasetoException | PaserkException $ex) {
                }
                continue;
            }
            $publickey = $this->getPublicKey($version, $test['key']);
            $this->assertSame($test['paserk'], Pid::encodePublic($publickey), $test['name']);
        }
    }
}
