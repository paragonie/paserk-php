<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Wrap;

use ParagonIE\Paserk\Operations\Wrap\Pie;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version1;
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\Protocol\Version3;
use ParagonIE\Paseto\Protocol\Version4;
use PHPUnit\Framework\TestCase;

/**
 * Class PieTest
 * @package ParagonIE\Paserk\Tests\Wrap
 *
 * @covers Pie
 */
class PieTest extends TestCase
{
    protected $v1 = [];
    protected $v2 = [];
    protected $v3 = [];
    protected $v4 = [];

    public function setUp(): void
    {
        $v1sk = AsymmetricSecretKey::generate(new Version1());
        $v2sk = AsymmetricSecretKey::generate(new Version2());
        $v3sk = AsymmetricSecretKey::generate(new Version3());
        $v4sk = AsymmetricSecretKey::generate(new Version4());

        $v1sym = SymmetricKey::generate(new Version1());
        $v2sym = SymmetricKey::generate(new Version2());
        $v3sym = SymmetricKey::generate(new Version3());
        $v4sym = SymmetricKey::generate(new Version4());

        $v1wk = SymmetricKey::generate(new Version1());
        $v2wk = SymmetricKey::generate(new Version2());
        $v3wk = SymmetricKey::generate(new Version3());
        $v4wk = SymmetricKey::generate(new Version4());

        $this->v1 = ['header' => 'k1', 'wk' => $v1wk, 'sk' => $v1sk, 'sym' => $v1sym];
        $this->v2 = ['header' => 'k2', 'wk' => $v2wk, 'sk' => $v2sk, 'sym' => $v2sym];
        $this->v3 = ['header' => 'k3', 'wk' => $v3wk, 'sk' => $v3sk, 'sym' => $v3sym];
        $this->v4 = ['header' => 'k4', 'wk' => $v4wk, 'sk' => $v4sk, 'sym' => $v4sym];
    }

    public function testWrapUnwrap()
    {
        foreach ([$this->v1, $this->v2, $this->v3, $this->v4] as $vers) {
            $pie = new Pie($vers['wk']);

            /** @var SymmetricKey $sym */
            $sym = $vers['sym'];
            $header = $vers['header'] . '.local-wrap.pie.';
            $wrapped = $pie->wrapKey($header, $sym);
            /** @var SymmetricKey $unwrapSym */
            $unwrapSym = $pie->unwrapKey($header . $wrapped);
            $this->assertEquals($sym->encode(), $unwrapSym->encode());

            /** @var AsymmetricSecretKey $sk */
            $sk = $vers['sk'];
            $header = $vers['header'] . '.secret-wrap.pie.';
            $wrapped = $pie->wrapKey($header, $sk);
            /** @var AsymmetricSecretKey $unwrapSK */
            $unwrapSK = $pie->unwrapKey($header . $wrapped);
            $this->assertEquals($sk->encode(), $unwrapSK->encode());
        }
    }
}
