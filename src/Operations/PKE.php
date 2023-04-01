<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations;

use ParagonIE\Paserk\Operations\PKE\{
    PKEv3,
    PKEv4
};
use ParagonIE\Paserk\Operations\Key\{
    SealingPublicKey,
    SealingSecretKey
};
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\ProtocolInterface;
use function
    array_pop,
    count,
    explode,
    implode;

/**
 * Class PKE
 * @package ParagonIE\Paserk\Operations
 */
class PKE
{
    const DOMAIN_SEPARATION_ENCRYPT = "\x01";
    const DOMAIN_SEPARATION_AUTH = "\x02";

    protected ProtocolInterface $version;

    public function __construct(ProtocolInterface $version)
    {
        $this->version = $version;
    }

    /**
     * @return PKEInterface
     * @throws PaserkException
     */
    public function getSealer(): PKEInterface
    {
        return match ($this->version::header()) {
            'v3' => new PKEv3(),
            'v4' => new PKEv4(),
            default => throw new PaserkException(
                'Unknown version: ' . $this->version::header()
            ),
        };
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
        /// @SPEC DETAIL: Algorithm Lucidity enforcement.

        $sealer = $this->getSealer();
        return $sealer::header() . $sealer->seal($ptk, $pk);
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
        // Step 1:
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
