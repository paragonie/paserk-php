<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\PKE;

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
}
