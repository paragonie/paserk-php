<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\ConstraintTrait;
use ParagonIE\Paserk\Operations\Key\SealingPublicKey;
use ParagonIE\Paserk\Operations\Key\SealingSecretKey;
use ParagonIE\Paserk\Operations\PKE;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\PaserkTypeInterface;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\SymmetricKey;

/**
 * Class Seal
 * @package ParagonIE\Paserk\Types
 */
class Seal implements PaserkTypeInterface
{
    use ConstraintTrait;

    /** @var SealingPublicKey $pk */
    protected $pk;

    /** @var SealingSecretKey|null $sk */
    protected $sk = null;

    /** @var array<string, string> */
    protected $localCache = [];

    /**
     * Seal constructor.
     *
     * @param SealingPublicKey $pk
     * @param SealingSecretKey|null $sk
     */
    public function __construct(SealingPublicKey $pk, ?SealingSecretKey $sk = null)
    {
        $this->pk = $pk;
        if ($sk) {
            $this->sk = $sk;
        }
        $this->localCache = [];
    }

    /**
     * @param string $paserk
     * @return KeyInterface
     *
     * @throws PaserkException
     */
    public function decode(string $paserk): KeyInterface
    {
        if (is_null($this->sk)) {
            throw new PaserkException('No secret key was provided; cannot unseal');
        }
        $unsealed = (new PKE($this->sk->getProtocol()))
            ->unseal($paserk, $this->sk);
        $this->throwIfInvalidProtocol($unsealed->getProtocol());
        return $unsealed;
    }

    /**
     * @param KeyInterface $key
     * @return string
     *
     * @throws PaserkException
     */
    public function encode(KeyInterface $key): string
    {
        if (!($key instanceof SymmetricKey)) {
            throw new PaserkException('Only symmetric keys are allowed here');
        }
        $this->throwIfInvalidProtocol($key->getProtocol());
        $localId = (new Local())->encode($key);
        if (!array_key_exists($localId, $this->localCache)) {
            $pke = new PKE($this->pk->getProtocol());
            $this->localCache[$localId] = $pke->seal($key, $this->pk);
        }
        return $this->localCache[$localId];
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'seal';
    }

    /**
     * @param KeyInterface $key
     * @return string
     *
     * @throws PaserkException
     * @throws \SodiumException
     */
    public function id(KeyInterface $key): string
    {
        return Lid::encode(
            $key->getProtocol(),
            $this->encode($key)
        );
    }
}
