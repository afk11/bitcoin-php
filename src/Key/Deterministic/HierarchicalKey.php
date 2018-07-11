<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Key\Deterministic;

use BitWasp\Bitcoin\Address\BaseAddressCreator;
use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Crypto\EcAdapter\Adapter\EcAdapterInterface;
use BitWasp\Bitcoin\Crypto\EcAdapter\Key\KeyInterface;
use BitWasp\Bitcoin\Key\KeyToScript\ScriptAndSignData;
use BitWasp\Bitcoin\Key\KeyToScript\ScriptDataFactory;
use BitWasp\Bitcoin\Network\NetworkInterface;
use BitWasp\Bitcoin\Serializer\Key\HierarchicalKey\Base58ExtendedKeySerializer;
use BitWasp\Bitcoin\Serializer\Key\HierarchicalKey\ExtendedKeySerializer;
use BitWasp\Bitcoin\Util\IntRange;
use BitWasp\Buffertools\BufferInterface;

/**
 * Class HierarchicalKey
 * @package BitWasp\Bitcoin\Key\Deterministic
 * @method HierarchicalKey withoutPrivateKey()
 */
class HierarchicalKey extends HdNode implements Bip32Serializable
{
    /**
     * @var int
     */
    private $sequence;
    /**
     * @var int
     */
    private $depth;

    /**
     * @var int
     */
    private $parentFingerprint;

    /**
     * @var ScriptDataFactory
     */
    private $scriptDataFactory;

    /**
     * @var ScriptAndSignData|null
     */
    private $scriptAndSignData;

    /**
     * @param EcAdapterInterface $ecAdapter
     * @param ScriptDataFactory $scriptDataFactory
     * @param int $depth
     * @param int $parentFingerprint
     * @param int $sequence
     * @param BufferInterface $chainCode
     * @param KeyInterface $key
     */
    public function __construct(EcAdapterInterface $ecAdapter, ScriptDataFactory $scriptDataFactory, int $depth, int $parentFingerprint, int $sequence, BufferInterface $chainCode, KeyInterface $key)
    {
        if ($depth < 0 || $depth > IntRange::U8_MAX) {
            throw new \InvalidArgumentException('Invalid depth for BIP32 key, must be in range [0 - 255] inclusive');
        }

        if ($parentFingerprint < 0 || $parentFingerprint > IntRange::U32_MAX) {
            throw new \InvalidArgumentException('Invalid fingerprint for BIP32 key, must be in range [0 - (2^31)-1] inclusive');
        }

        if ($sequence < 0 || $sequence > IntRange::U32_MAX) {
            throw new \InvalidArgumentException('Invalid sequence for BIP32 key, must be in range [0 - (2^31)-1] inclusive');
        }

        // slip132 params
        // $this->>path = $path;

        // bip32 params
        $this->parentFingerprint = $parentFingerprint;
        $this->scriptDataFactory = $scriptDataFactory;
        $this->depth = $depth;
        $this->sequence = $sequence;

        parent::__construct($ecAdapter, $chainCode, $key);
    }

    /**
     * Return the depth of this key. This is limited to 256 sequential derivations.
     *
     * @return int
     */
    public function getDepth(): int
    {
        return $this->depth;
    }

    /**
     * Get the sequence number for this address. Hardened keys are
     * created with sequence > 0x80000000. a sequence number lower
     * than this can be derived with the public key.
     *
     * @return int
     */
    public function getSequence(): int
    {
        return $this->sequence;
    }

    /**
     * Get the fingerprint of the parent key. For master keys, this is 00000000.
     *
     * @return int
     */
    public function getFingerprint(): int
    {
        if ($this->getDepth() === 0) {
            return 0;
        }

        return $this->parentFingerprint;
    }

    /**
     * Return the fingerprint to be used for child keys.
     * @return int
     */
    public function getChildFingerprint(): int
    {
        $pubKeyHash = $this->getPublicKey()->getPubKeyHash();
        return (int) $pubKeyHash->slice(0, 4)->getInt();
    }

    /**
     * @return ScriptDataFactory
     */
    public function getScriptDataFactory()
    {
        return $this->scriptDataFactory;
    }

    /**
     * @return \BitWasp\Bitcoin\Key\KeyToScript\ScriptAndSignData
     */
    public function getScriptAndSignData()
    {
        if (null === $this->scriptAndSignData) {
            $this->scriptAndSignData = $this->scriptDataFactory->convertKey($this->key);
        }

        return $this->scriptAndSignData;
    }

    /**
     * @param BaseAddressCreator $addressCreator
     * @return \BitWasp\Bitcoin\Address\Address
     */
    public function getAddress(BaseAddressCreator $addressCreator)
    {
        return $this->getScriptAndSignData()->getAddress($addressCreator);
    }

    protected function createChild(int $sequence, BufferInterface $chainCode, KeyInterface $key): HdNode
    {
        return new HierarchicalKey(
            $this->ecAdapter,
            $this->scriptDataFactory,
            $this->getDepth() + 1,
            $this->getChildFingerprint(),
            $sequence,
            $chainCode,
            $key
        );
    }

    /**
     * Serializes the instance according to whether it wraps a private or public key.
     * @param NetworkInterface $network
     * @return string
     */
    public function toExtendedKey(NetworkInterface $network = null): string
    {
        $network = $network ?: Bitcoin::getNetwork();

        $extendedSerializer = new Base58ExtendedKeySerializer(new ExtendedKeySerializer($this->ecAdapter));
        $extended = $extendedSerializer->serialize($network, $this);
        return $extended;
    }

    /**
     * Explicitly serialize as a private key. Throws an exception if
     * the key isn't private.
     *
     * @param NetworkInterface $network
     * @return string
     */
    public function toExtendedPrivateKey(NetworkInterface $network = null): string
    {
        if (!$this->isPrivate()) {
            throw new \LogicException('Cannot create extended private key from public');
        }

        return $this->toExtendedKey($network);
    }

    /**
     * Explicitly serialize as a public key. This will always work.
     *
     * @param NetworkInterface $network
     * @return string
     */
    public function toExtendedPublicKey(NetworkInterface $network = null): string
    {
        return $this->withoutPrivateKey()->toExtendedKey($network);
    }
}
