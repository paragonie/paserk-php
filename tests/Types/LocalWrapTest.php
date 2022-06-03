<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use Exception;
use ParagonIE\Paserk\{
    PaserkException,
    Types\Lid,
    Types\LocalWrap
};
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;
use SodiumException;

/**
 * Class LocalWrapTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers LocalWrap
 */
class LocalWrapTest extends TestCase
{
    protected SymmetricKey $v3key;
    protected SymmetricKey $v4key;

    /**
     * @throws Exception
     */
    public function setUp(): void
    {
        $this->v3key = SymmetricKey::generate(new Version3());
        $this->v4key = SymmetricKey::generate(new Version4());
    }

    /**
     * @throws PaserkException
     * @throws InvalidVersionException
     * @throws SodiumException
     */
    public function testWrap()
    {
        /** @var SymmetricKey $key */
        foreach ([$this->v3key, $this->v4key] as $key) {
            // Generate wrapping key
            $version = $key->getProtocol();
            $wk = SymmetricKey::generate($version);
            $lw = LocalWrap::initWithKey($wk);

            $id = $lw->id($key);
            $encoded = $lw->encode($key);
            $id2 = Lid::encode($version, $encoded);
            $this->assertSame($id2, $id, 'Local-wrap key IDs must be deterministic');

            /** @var SymmetricKey $decoded */
            $decoded = $lw->decode($encoded);
            $this->assertSame(
                $key->encode(),
                $decoded->encode(),
                'local-wrap ' . $key->getProtocol()::header()
            );
        }
    }
}
