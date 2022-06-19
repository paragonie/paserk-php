<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\Key;

use ParagonIE\EasyECC\ECDSA\{
    PublicKey,
    SecretKey
};
use ParagonIE\EasyECC\Exception\NotImplementedException;
use ParagonIE\Paseto\Keys\{
    AsymmetricPublicKey,
    AsymmetricSecretKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Util;
use Exception;
use SodiumException;
use TypeError;
use function
    hash_equals,
    sodium_crypto_sign_keypair,
    sodium_crypto_sign_publickey_from_secretkey,
    sodium_crypto_sign_secretkey;

/**
 * Class SealingSecretKey
 * @package ParagonIE\Paserk\Operations\Key
 */
class SealingSecretKey extends AsymmetricSecretKey
{
    /**
     * @param ProtocolInterface|null $protocol
     * @return self
     *
     * @throws Exception
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public static function generate(ProtocolInterface $protocol = null): AsymmetricSecretKey
    {
        $protocol = $protocol ?? new Version4;
        if (hash_equals($protocol::header(), Version3::HEADER)) {
            return new self(
                Util::dos2unix(SecretKey::generate(Version3::CURVE)->exportPem()),
                $protocol
            );
        }
        return new self(
            sodium_crypto_sign_secretkey(
                sodium_crypto_sign_keypair()
            ),
            $protocol
        );
    }

    /**
     * @return AsymmetricSecretKey
     *
     * @throws Exception
     */
    public function toPasetoKey(): AsymmetricSecretKey
    {
        return new AsymmetricSecretKey(
            $this->key,
            $this->protocol
        );
    }

    /**
     * @return AsymmetricPublicKey
     *
     * @throws Exception
     * @throws TypeError
     */
    public function getPublicKey(): AsymmetricPublicKey
    {
        switch ($this->protocol::header()) {
            case Version3::HEADER:
                /** @var PublicKey $pk */
                $pk = SecretKey::importPem($this->key)->getPublicKey();
                return new SealingPublicKey(
                    $pk->exportPem(),
                    $this->protocol
                );
            default:
                return new SealingPublicKey(
                    sodium_crypto_sign_publickey_from_secretkey($this->key),
                    $this->protocol
                );
        }
    }
}
