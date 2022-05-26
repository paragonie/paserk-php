<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use FG\ASN1\Exception\ParserException;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\Sid;
use ParagonIE\Paseto\Exception\PasetoException;
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

    protected function getSecretKey(ProtocolInterface $version, string $key): AsymmetricSecretKey
    {
        if ($version instanceof Version1) {
            return new AsymmetricSecretKey($key, $version);
        }
        return new AsymmetricSecretKey(Hex::decode($key), $version);
    }

    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            if ($test['expect-fail']) {
                try {
                    $secretkey = $this->getSecretKey($version, $test['key']);
                    Sid::encodeSecret($secretkey);
                    $this->fail($test['name'] . ': '. $test['comment']);
                } catch (ParserException | \RangeException | PasetoException | PaserkException $ex) {
                }
                continue;
            }
            $secretkey = $this->getSecretKey($version, $test['key']);
            $this->assertSame($test['paserk'], Sid::encodeSecret($secretkey), $test['name']);
        }
    }
}
