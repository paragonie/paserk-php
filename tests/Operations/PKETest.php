<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Operations;

use ParagonIE\Paserk\Operations\Key\SealingPublicKey;
use ParagonIE\Paserk\Operations\Key\SealingSecretKey;
use ParagonIE\Paserk\Operations\PKE;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;

/**
 * Class PKETest
 * @package ParagonIE\Paserk\Tests\Operations
 *
 * @covers PKE
 */
class PKETest extends TestCase
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

    public function testPKE()
    {
        foreach ($this->versions as $v) {
            $key = SymmetricKey::generate($v);
            $sk = SealingSecretKey::generate($v);
            /** @var SealingPublicKey $pk */
            $pk = $sk->getPublicKey();

            $pke = new PKE($v);
            $sealed = $pke->seal($key, $pk);
            $opened = $pke->unseal($sealed, $sk);
            $this->assertSame(
                $opened->encode(),
                $key->encode()
            );
        }
    }
}
