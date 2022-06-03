<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use Exception;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Types\SecretPW;
use ParagonIE\Paserk\Tests\KnownAnswers;
use Throwable;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;

/**
 * @covers SecretPW
 */
class SecretPWTest extends KnownAnswers
{
    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.secret-pw.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.secret-pw.json');
    }

    /**
     * @param ProtocolInterface $version
     * @param string $name
     * @param array $tests
     *
     * @throws Exception
     */
    protected function genericTest(ProtocolInterface $version, string $name, array $tests): void
    {
        foreach ($tests as $test) {
            $wrapper = new SecretPW(
                new HiddenString(Hex::encode($test['password'])),
                $test['options'] ?? [],
                $version
            );
            if ($test['expect-fail']) {
                try {
                    $wrapper->decode($test['paserk']);
                } catch (Throwable $exception) {
                    continue;
                }
                $this->fail($name . ' > ' . $test['name'] . ': '. $test['comment']);
            }
            $unwrapped = $wrapper->decode($test['paserk']);
            if ($version::header() === 'v1') {
                $this->assertSame(
                    $test['unwrapped'],
                    $unwrapped->raw(),
                    $test['name']
                );
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
