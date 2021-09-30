<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\Paserk\Types\Lid;
use ParagonIE\Paserk\Types\LocalWrap;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;

/**
 * Class LocalWrapTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers LocalWrap
 */
class LocalWrapTest extends TestCase
{

    protected $v1key;
    protected $v2key;
    protected $v3key;
    protected $v4key;

    public function setUp(): void
    {
        $this->v1key = SymmetricKey::generate(new Version1());
        $this->v2key = SymmetricKey::generate(new Version2());
        $this->v3key = SymmetricKey::generate(new Version3());
        $this->v4key = SymmetricKey::generate(new Version4());
    }

    public function testWrap()
    {
        /** @var SymmetricKey $key */
        foreach ([$this->v1key, $this->v2key, $this->v3key, $this->v4key] as $key) {
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
