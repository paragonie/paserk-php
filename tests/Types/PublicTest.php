<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Tests\Types;

use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\{
    Version1,
    Version2,
    Version3,
    Version4
};
use PHPUnit\Framework\TestCase;
use ParagonIE\Paserk\Types\PublicType;

/**
 * Class PublicTest
 * @package ParagonIE\Paserk\Tests\Types
 *
 * @covers PublicType
 */
class PublicTest extends TestCase
{
    /** @var AsymmetricPublicKey $v1pk */
    protected $v1pk;
    /** @var AsymmetricPublicKey $v2pk */
    protected $v2pk;
    /** @var AsymmetricPublicKey $v3pk */
    protected $v3pk;
    /** @var AsymmetricPublicKey $v4pk */
    protected $v4pk;
    /** @var AsymmetricSecretKey $v1sk */
    protected $v1sk;
    /** @var AsymmetricSecretKey $v2sk */
    protected $v2sk;
    /** @var AsymmetricSecretKey $v3sk */
    protected $v3sk;
    /** @var AsymmetricSecretKey $v4sk */
    protected $v4sk;
    /** @var string $rsaPublicKey */
    protected $rsaPublicKey;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->v1sk = AsymmetricSecretKey::generate(new Version1());
        $this->v1pk = $this->v1sk->getPublicKey();
        $this->v2sk = AsymmetricSecretKey::generate(new Version2());
        $this->v2pk = $this->v2sk->getPublicKey();
        $this->v3sk = AsymmetricSecretKey::generate(new Version3());
        $this->v3pk = $this->v3sk->getPublicKey();
        $this->v4sk = AsymmetricSecretKey::generate(new Version4());
        $this->v4pk = $this->v4sk->getPublicKey();
        
        $this->rsaPublicKey = '-----BEGIN PUBLIC KEY-----' . "\n" .
            'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p5GHgwoGW' . "\n" .
            'wz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwx' . "\n" .
            'KheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1' . "\n" .
            'Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAA' . "\n" .
            'pVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6al' . "\n" .
            'UyhKC1+1w/FW6HWcp/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8' . "\n" .
            'owIDAQAB' . "\n" .
            '-----END PUBLIC KEY-----';
    }

    public function testEncodeDecode()
    {
        /** @var AsymmetricPublicKey $key */
        foreach ([$this->v1pk, $this->v2pk, $this->v3pk, $this->v4pk] as $key) {
            $public = new PublicType($key->getProtocol());
            $encoded = $public->encode($key);
            $decoded = $public->decode($encoded);
            if ($key->getProtocol() instanceof Version1) {
                // Compare raw -> compare PEM-encoded
                $this->assertSame(
                    $key->raw(),
                    $decoded->raw(),
                    'Key encoding failed: ' . $encoded
                );
            } else {
                $this->assertSame(
                    $key->encode(),
                    $decoded->encode(),
                    'Key encoding failed: ' . $encoded
                );
            }
        }
    }

    public function testEncodeDecodeV1()
    {
        $public = new PublicType();
        $encoded = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWX' .
            'SQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh_uN88JPIbwxKheDp4kxo4YMN5tr' .
            'PaF0e9G6Bj1N02HnanxFLW-gmLbgYO_SZYfWF_M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3Yb' .
            'xgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnA' .
            'wIMjeTJB_0AIELh0mE5vwdihOCbdV6alUyhKC1-1w_FW6HWcp_JG1kKC8DPIidZ78Bbqv9YF' .
            'zkAbNni5eSBOsXVBKG78Zsc8owIDAQAB';
        $this->assertSame($encoded, $public->encodeV1($this->rsaPublicKey));
        $this->assertSame($this->rsaPublicKey, $public->decodeV1($encoded)->raw());
    }

    public function testRejectSecret()
    {
        $public = new PublicType();
        $this->expectException(PaserkException::class);
        $public->encode($this->v1sk);
    }
}
