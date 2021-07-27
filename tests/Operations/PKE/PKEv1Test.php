<?php
declare(strict_types=1);

namespace ParagonIE\Paserk\Tests\Operations\PKE;

use ParagonIE\Paserk\Operations\Key\SealingPublicKey;
use ParagonIE\Paserk\Operations\Key\SealingSecretKey;
use ParagonIE\Paserk\Operations\PKE\PKEv1;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version1;
use PHPUnit\Framework\TestCase;

/**
 * Class PKEv1Test
 * @package ParagonIE\Paserk\Tests\Operations\PKE
 *
 * @covers PKEv1
 */
class PKEv1Test extends TestCase
{
    /** @var SealingSecretKey  */
    protected $v1sk;
    /** @var SealingPublicKey  */
    protected $v1pk;

    public function setUp(): void
    {
        $this->v1sk = SealingSecretKey::generate(new Version1());
        $this->v1pk = $this->v1sk->getPublicKey();
    }

    public function testSealUnseal()
    {
        $sym = SymmetricKey::generate(new Version1());
        $pkev1 = new PKEv1();

        $sealed = $pkev1->seal($sym, $this->v1pk);
        $unsealed =$pkev1->unseal($pkev1::header(), $sealed, $this->v1sk);
        $this->assertSame(
            $unsealed->encode(),
            $sym->encode()
        );
    }
}
