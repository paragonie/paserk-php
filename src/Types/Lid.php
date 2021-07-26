<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\Paserk\IdCommonTrait;
use ParagonIE\Paserk\IdInterface;

/**
 * Class Lid
 * @package ParagonIE\Paserk\Types
 */
class Lid implements IdInterface
{
    use IdCommonTrait;

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'lid';
    }
}
