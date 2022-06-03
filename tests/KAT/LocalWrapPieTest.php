<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\KAT;

use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\Operations\Wrap;
use ParagonIE\Paserk\Operations\Wrap\Pie;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Types\LocalWrap;
use ParagonIE\Paserk\Tests\KnownAnswers;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use Throwable;

/**
 * @covers LocalWrap
 */
class LocalWrapPieTest extends KnownAnswers
{
    public function testV3()
    {
        $this->doJsonTest(new Version3(), 'k3.local-wrap.pie.json');
    }

    public function testV4()
    {
        $this->doJsonTest(new Version4(), 'k4.local-wrap.pie.json');
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
            $wrapkey = new SymmetricKey(Hex::decode($test['wrapping-key']), $version);
            $wrapper = (new LocalWrap(new Wrap(new Pie($wrapkey))));
            if ($test['expect-fail']) {
                try {
                    $wrapper->decode($test['paserk']);
                } catch (Throwable $exception) {
                    continue;
                }
                $this->fail($name . ' > ' . $test['name'] . ': '. $test['comment']);
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
