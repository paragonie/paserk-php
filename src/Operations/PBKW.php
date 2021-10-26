<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations;

use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paserk\Operations\PBKW\{
    PBKWv1,
    PBKWv2,
    PBKWv3,
    PBKWv4
};
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\ProtocolInterface;

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
    /** @var PBKWInterface $wrapper */
    protected $wrapper;

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
     * @return static
     * @throws PaserkException
     */
    public static function forVersion(ProtocolInterface $version): self
    {
        switch ($version::header()) {
            case 'v1':
                return new PBKW(new PBKWv1());
            case 'v2':
                return new PBKW(new PBKWv2());
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
        SymmetricKey $key,
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
    ): SymmetricKey {
        $pieces = explode('.', $paserk);
        if (count($pieces) !== 3) {
            throw new PaserkException('Invalid wrapped key');
        }
        $payload = array_pop($pieces);

        $header = implode('.', $pieces) . '.';
        $expect = $this->wrapper::localHeader();
        if (!hash_equals($expect, $header)) {
            throw new PaserkException('Invalid wrapped key');
        }

        $unwrapped = $this->wrapper->unwrapWithPassword(
            $header,
            $payload,
            $password
        );
        if (!($unwrapped instanceof SymmetricKey)) {
            throw new \TypeError();
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
        AsymmetricSecretKey $sk,
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
    ): AsymmetricSecretKey {
        $pieces = explode('.', $paserk);
        if (count($pieces) !== 3) {
            throw new PaserkException('Invalid wrapped key');
        }
        $payload = array_pop($pieces);

        $header = implode('.', $pieces) . '.';
        $expect = $this->wrapper::secretHeader();
        if (!hash_equals($expect, $header)) {
            throw new PaserkException('Invalid wrapped key');
        }

        $unwrapped = $this->wrapper->unwrapWithPassword(
            $header,
            $payload,
            $password
        );
        if (!($unwrapped instanceof AsymmetricSecretKey)) {
            throw new \TypeError();
        }
        return $unwrapped;
    }
}
