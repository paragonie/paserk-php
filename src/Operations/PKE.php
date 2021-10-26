<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations;

use ParagonIE\Paserk\Operations\PKE\{
    PKEv1,
    PKEv2,
    PKEv3,
    PKEv4
};
use ParagonIE\Paserk\Operations\Key\{
    SealingPublicKey,
    SealingSecretKey
};
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * Class PKE
 * @package ParagonIE\Paserk\Operations
 */
class PKE
{
    /** @var ProtocolInterface $version */
    protected $version;

    public function __construct(ProtocolInterface $version)
    {
        $this->version = $version;
    }

    /**
     * @param SymmetricKey $ptk     Symmetric key to seal with this public key
     * @param SealingPublicKey $pk  Wrapping key
     * @return string
     *
     * @throws PaserkException
     */
    public function seal(SymmetricKey $ptk, SealingPublicKey $pk): string
    {
        if (!hash_equals($ptk->getProtocol()::header(), $this->version::header())) {
            throw new PaserkException('Plaintext key is not intended for this version');
        }
        if (!hash_equals($pk->getProtocol()::header(), $this->version::header())) {
            throw new PaserkException('Wrapping key is not intended for this version');
        }

        $sealer = $this->getSealer();
        return $sealer::header() . $sealer->seal($ptk, $pk);
    }

    /**
     * @return PKEInterface
     * @throws PaserkException
     */
    public function getSealer(): PKEInterface
    {
        switch ($this->version::header()) {
            case 'v1':
                return new PKEv1();
            case 'v2':
                return new PKEv2();
            case 'v3':
                return new PKEv3();
            case 'v4':
                return new PKEv4();
            /*
            case 'v3':
                return $this->sealV3($ptk, $pk);
            */
            default:
                throw new PaserkException(
                    'Unknown version: ' . $this->version::header()
                );
        }
    }

    /**
     * @param string $paserk
     * @param SealingSecretKey $sk  Unwrapping key
     * @return SymmetricKey
     *
     * @throws PaserkException
     */
    public function unseal(string $paserk, SealingSecretKey $sk): SymmetricKey
    {
        if (!hash_equals($sk->getProtocol()::header(), $this->version::header())) {
            throw new PaserkException('Unwrapping key is not intended for this version');
        }
        $pieces = explode('.', $paserk);
        if (count($pieces) !== 3) {
            throw new PaserkException('Invalid PASERK');
        }
        $payload = array_pop($pieces);
        $header = implode('.', $pieces) . '.'; // Recreate header
        $sealer = $this->getSealer();
        return $sealer->unseal($header, $payload, $sk);
    }
}
