<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use Exception;
use FG\ASN1\Exception\ParserException;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\Sid;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\ProtocolInterface;
use SodiumException;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};

/**
 * @covers Sid
 */
class SidTest extends KnownAnswers
{
    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.sid.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.sid.json');
    }

    /**
     * @param ProtocolInterface $version
     * @param string $key
     * @return AsymmetricSecretKey
     *
     * @throws Exception
     */
    protected function getSecretKey(ProtocolInterface $version, string $key): AsymmetricSecretKey
    {
        return new AsymmetricSecretKey(Hex::decode($key), $version);
    }

    /**
     * @param ProtocolInterface $version
     * @param string $name
     * @param array $tests
     *
     * @throws PaserkException
     * @throws InvalidVersionException
     * @throws SodiumException
     */
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
