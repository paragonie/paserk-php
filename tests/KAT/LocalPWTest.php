<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Types\LocalPW;
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
 * @covers LocalPW
 */
class LocalPWTest extends KnownAnswers
{
    public function testV1()
    {
        $this->doJsonTest(new Version1(), 'k1.local-pw.json');
    }

    public function testV2()
    {
        $this->doJsonTest(new Version2(), 'k2.local-pw.json');
    }

    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.local-pw.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.local-pw.json');
    }

    /**
     * @param ProtocolInterface $version
     * @param string $name
     * @param array $tests
     *
     * @throws PaserkException
     */
    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            $wrapper = new LocalPW(
                new HiddenString($test['password']),
                $test['options'] ?? [],
                $version
            );
            if ($test['expect-fail']) {
                try {
                    $wrapper->decode($test['paserk']);
                } catch (\Throwable $exception) {
                    continue;
                }
                $this->fail($name . ' > ' . $test['name'] . ': '. $test['comment']);
            }
            if (empty($test['paserk'])) {
                var_dump($wrapper->encode(
                    new SymmetricKey(
                        Hex::decode($test['unwrapped']),
                        $version
                    )
                ));
                continue;
            }
            $unwrapped = $wrapper->decode($test['paserk']);
            $this->assertSame(
                $test['unwrapped'],
                Hex::encode($unwrapped->raw()),
                $test['name']
            );
        }
    }
}
