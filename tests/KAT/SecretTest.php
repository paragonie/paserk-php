<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use Exception;
use FG\ASN1\Exception\ParserException;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paserk\Types\SecretType;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};

/**
 * @covers Secret
 */
class SecretTest extends KnownAnswers
{
    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.secret.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.secret.json');
    }

    protected function getSecretKey(ProtocolInterface $version, string $key): AsymmetricSecretKey
    {
        return new AsymmetricSecretKey(Hex::decode($key), $version);
    }

    /**
     * @throws Exception
     * @throws PaserkException
     */
    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            $secret = (new SecretType($version));
            if ($test['expect-fail']) {

                if (!empty($test['paserk'])) {
                    try {
                        $secret->decode($test['paserk']);
                        $this->fail($test['name'] . ': ' . $test['comment']);
                    } catch (ParserException | \RangeException | PasetoException | PaserkException $ex) {
                    }
                    continue;
                }

                try {
                    $secretkey = $this->getSecretKey($version, $test['key']);
                    $secret->encode($secretkey);
                    $this->fail($test['name'] . ': '. $test['comment']);
                } catch (ParserException | \RangeException | PasetoException | PaserkException $ex) {
                }
                continue;
            }
            $secretkey = $this->getSecretKey($version, $test['key']);
            $this->assertSame(
                $test['public-key'],
                Hex::encode($secretkey->getPublicKey()->raw())
            );
            $this->assertSame($test['paserk'], $secret->encode($secretkey), $test['name']);
        }
    }
}
