<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\EasyECC\Exception\NotImplementedException;
use ParagonIE\Paserk\Operations\Key\{
    SealingPublicKey,
    SealingSecretKey
};
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\Types\{
    Lid,
    Seal
};
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;
use SodiumException;

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
            new Version3(),
            new Version4()
        ];
    }

    /**
     * @throws NotImplementedException
     * @throws PaserkException
     * @throws SodiumException
     */
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

            $fromSK = Seal::fromSecretKey($sk);
            $unseal = $fromSK->decode($sealed);
            $this->assertSame(
                $unseal->encode(),
                $key->encode()
            );
        }
    }
}
