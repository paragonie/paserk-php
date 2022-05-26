<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Types;

use ParagonIE\HiddenString\HiddenString;
use ParagonIE\Paserk\ConstraintTrait;
use ParagonIE\Paserk\Operations\PBKW;
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paserk\PaserkTypeInterface;
use ParagonIE\Paserk\Util;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;

use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\ProtocolInterface;
use function
    array_key_exists,
    explode;

/**
 * Class SecretPW
 * @package ParagonIE\Paserk\Types
 */
class SecretPW implements PaserkTypeInterface
{
    use ConstraintTrait;

    /** @var array<string, string> */
    protected $localCache = [];

    /** @var array $options */
    protected $options;

    /** @var HiddenString $password */
    protected $password;

    /**
     * SecretPW constructor.
     * @param HiddenString $password
     * @param array $options
     *
     * @param ProtocolInterface ...$version
     * @throws InvalidVersionException
     */
    public function __construct(HiddenString $password, array $options = [], ProtocolInterface ...$version)
    {
        $this->password = $password;
        $this->options = $options;
        $this->localCache = [];
        if (count($version) > 0) {
            $this->collection = new ProtocolCollection(...$version);
        } else {
            $this->collection = ProtocolCollection::default();
        }
    }

    /**
     * @param string $paserk
     * @return KeyInterface
     *
     * @throws PaserkException
     */
    public function decode(string $paserk): KeyInterface
    {
        $pieces = explode('.', $paserk);
        $header = $pieces[0];
        $version = Util::getPasetoVersion($header);
        $this->throwIfInvalidProtocol($version);
        /// @SPEC DETAIL: Algorithm Lucidity

        $pbkw = PBKW::forVersion($version);

        return $pbkw->secretPwUnwrap($paserk, $this->password);
    }

    /**
     * @param KeyInterface $key
     * @return string
     * @throws PaserkException
     */
    public function encode(KeyInterface $key): string
    {
        if (!($key instanceof AsymmetricSecretKey)) {
            throw new PaserkException('Only asymmetric secret keys are allowed here');
        }
        $this->throwIfInvalidProtocol($key->getProtocol());
        /// @SPEC DETAIL: Algorithm Lucidity

        $secretId = (new SecretType())->encode($key);
        if (!array_key_exists($secretId, $this->localCache)) {
            $this->localCache[$secretId] = PBKW::forVersion($key->getProtocol())
                ->secretPwWrap($key, $this->password, $this->options);
        }
        return $this->localCache[$secretId];
    }

    /**
     * @return string
     */
    public static function getTypeLabel(): string
    {
        return 'secret-pw';
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
        return Sid::encode(
            $key->getProtocol(),
            $this->encode($key)
        );
    }
}
