<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations;

use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\Operations\PBKW\{
    PBKWv3,
    PBKWv4
};
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Keys\Base\{
    AsymmetricSecretKey as BaseAsymmetricSecretKey,
    SymmetricKey as BaseSymmetricKey
};
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\ProtocolInterface;
use TypeError;
use function
    array_pop,
    explode,
    hash_equals,
    implode;

/**
 * Class PBKW
 * @package ParagonIE\Paserk\Operations
 */
class PBKW
{
    const DOMAIN_SEPARATION_ENCRYPT = "\xff";
    const DOMAIN_SEPARATION_AUTH = "\xfe";

    protected PBKWInterface $wrapper;

    /**
     * PBKW constructor.
     * @param PBKWInterface $wrapper
     */
    public function __construct(PBKWInterface $wrapper)
    {
        $this->wrapper = $wrapper;
    }

    /**
     * @param ProtocolInterface $version
     * @return self
     * @throws PaserkException
     */
    public static function forVersion(ProtocolInterface $version): self
    {
        switch ($version::header()) {
            case 'v3':
                return new PBKW(new PBKWv3());
            case 'v4':
                return new PBKW(new PBKWv4());
        }
        throw new PaserkException('Unknown version');
    }

    /**
     * @param SymmetricKey $key
     * @param HiddenString $password
     * @param array $options
     * @return string
     */
    public function localPwWrap(
        BaseSymmetricKey $key,
        HiddenString $password,
        array $options = []
    ): string {
        return $this->wrapper::localHeader() .
            $this->wrapper->wrapWithPassword($key, $password, $options);
    }

    /**
     * @param string $paserk
     * @param HiddenString $password
     * @return SymmetricKey
     * @throws PaserkException
     */
    public function localPwUnwrap(
        string $paserk,
        HiddenString $password
    ): BaseSymmetricKey {
        $pieces = explode('.', $paserk);
        if (count($pieces) !== 3) {
            throw new PaserkException('Invalid wrapped key');
        }
        $payload = array_pop($pieces);

        $header = implode('.', $pieces) . '.';
        // Step 1: Algorithm lucidity
        $expect = $this->wrapper::localHeader();
        if (!hash_equals($expect, $header)) {
            throw new PaserkException('Invalid wrapped key');
        }

        $unwrapped = $this->wrapper->unwrapWithPassword(
            $header,
            $payload,
            $password
        );
        if (!($unwrapped instanceof BaseSymmetricKey)) {
            throw new TypeError();
        }
        return $unwrapped;
    }

    /**
     * @param AsymmetricSecretKey $sk
     * @param HiddenString $password
     * @param array $options
     * @return string
     */
    public function secretPwWrap(
        BaseAsymmetricSecretKey $sk,
        HiddenString $password,
        array $options
    ): string {
        return $this->wrapper::secretHeader() .
            $this->wrapper->wrapWithPassword($sk, $password, $options);
    }

    /**
     * @param string $paserk
     * @param HiddenString $password
     * @return AsymmetricSecretKey
     * @throws PaserkException
     */
    public function secretPwUnwrap(
        string $paserk,
        HiddenString $password
    ): BaseAsymmetricSecretKey {
        $pieces = explode('.', $paserk);
        if (count($pieces) !== 3) {
            throw new PaserkException('Invalid wrapped key');
        }
        $payload = array_pop($pieces);

        $header = implode('.', $pieces) . '.';
        // Step 1: Algorithm lucidity
        $expect = $this->wrapper::secretHeader();
        if (!hash_equals($expect, $header)) {
            throw new PaserkException('Invalid wrapped key');
        }

        $unwrapped = $this->wrapper->unwrapWithPassword(
            $header,
            $payload,
            $password
        );
        if (!($unwrapped instanceof BaseAsymmetricSecretKey)) {
            throw new TypeError();
        }
        return $unwrapped;
    }
}
