<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\PKE;

use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolInterface;

/**
 * Class PKEv4
 * @package ParagonIE\Paserk\Operations\PKE
 */
class PKEv4 extends PKEv2
{
    /**
     * @return string
     */
    public static function header(): string
    {
        return 'k4.seal.';
    }

    /**
     * @return ProtocolInterface
     */
    public static function getProtocol(): ProtocolInterface
    {
        return new Version4();
    }
}
