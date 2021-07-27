<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\Paserk\Operations\Key\SealingPublicKey;
use ParagonIE\Paserk\Operations\Key\SealingSecretKey;
use ParagonIE\Paserk\Types\Lid;
use ParagonIE\Paserk\Types\Seal;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version1;
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;

/**
 * Class SealTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers Seal
 */
class SealTest extends TestCase
{
    /** @var ProtocolInterface[] */
    protected $versions = [];

    public function setUp(): void
    {
        $this->versions = [
            new Version1(),
            new Version2(),
            new Version3(),
            new Version4()
        ];
    }

    public function testSeal()
    {
        foreach ($this->versions as $v) {
            $key = SymmetricKey::generate($v);
            $sk = SealingSecretKey::generate($v);
            /** @var SealingPublicKey $pk */
            $pk = $sk->getPublicKey();

            $sealer = new Seal($pk, $sk);
            $sealed = $sealer->encode($key);
            $lid1 = $sealer->id($key);
            $lid2 = Lid::encode($v, $sealed);
            $this->assertSame($lid1, $lid2, 'Key ID must be deterministic');

            $unseal = $sealer->decode($sealed);
            $this->assertSame(
                $unseal->encode(),
                $key->encode()
            );
        }
    }
}
