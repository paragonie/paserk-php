<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations;

use ParagonIE\Paserk\Operations\Key\{
    SealingPublicKey,
    SealingSecretKey
};
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * Class PKEInterface
 * @package ParagonIE\Paserk\Operations
 */
interface PKEInterface
{
    /**
     * @return string
     */
    public static function header(): string;

    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface;

    /**
     * @param SymmetricKey $ptk
     * @param SealingPublicKey $pk
     * @return string
     */
    public function seal(SymmetricKey $ptk, SealingPublicKey $pk): string;

    /**
     * @param string $header
     * @param string $encoded
     * @param SealingSecretKey $sk
     * @return SymmetricKey
     */
    public function unseal(string $header, string $encoded, SealingSecretKey $sk): SymmetricKey;
}
