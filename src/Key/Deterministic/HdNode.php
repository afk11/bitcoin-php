<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Key\Deterministic;

use BitWasp\Bitcoin\Crypto\EcAdapter\Adapter\EcAdapterInterface;
use BitWasp\Bitcoin\Crypto\EcAdapter\Key\KeyInterface;
use BitWasp\Bitcoin\Crypto\EcAdapter\Key\PrivateKeyInterface;
use BitWasp\Bitcoin\Crypto\EcAdapter\Key\PublicKeyInterface;
use BitWasp\Bitcoin\Crypto\Hash;
use BitWasp\Bitcoin\Util\IntRange;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

abstract class HdNode
{
    /**
     * @var BufferInterface
     */
    protected $chainCode;

    /**
     * @var EcAdapterInterface
     */
    protected $ecAdapter;

    /**
     * @var KeyInterface
     */
    protected $key;

    public function __construct(EcAdapterInterface $ecAdapter, BufferInterface $chainCode, KeyInterface $key)
    {
        if ($chainCode->getSize() !== 32) {
            throw new \RuntimeException('Chaincode should be 32 bytes');
        }

        if (!$key->isCompressed()) {
            throw new \InvalidArgumentException('A HierarchicalKey must always be compressed');
        }

        $this->ecAdapter = $ecAdapter;
        $this->key = $key;
        $this->chainCode = $chainCode;
    }

    /**
     * Return the depth of this key. This is limited to 256 sequential derivations.
     *
     * @return int
     */
    abstract public function getDepth(): int;

    /**
     * Get the sequence number for this address. Hardened keys are
     * created with sequence > 0x80000000. a sequence number lower
     * than this can be derived with the public key.
     *
     * @return int
     */
    abstract public function getSequence(): int;

    /**
     * @param int $sequence
     * @param BufferInterface $chainCode
     * @param KeyInterface $key
     * @return HdNode
     */
    abstract protected function createChild(int $sequence, BufferInterface $chainCode, KeyInterface $key): HdNode;

    /**
     * Return whether the key is hardened
     *
     * @return bool
     */
    public function isHardened(): bool
    {
        return ($this->getSequence() >> 31) === 1;
    }

    /**
     * Return the chain code - a deterministic 'salt' for HMAC-SHA512
     * in child derivations
     *
     * @return BufferInterface
     */
    public function getChainCode(): BufferInterface
    {
        return $this->chainCode;
    }

    /**
     * @return PrivateKeyInterface
     */
    public function getPrivateKey(): PrivateKeyInterface
    {
        if ($this->key->isPrivate()) {
            /** @var PrivateKeyInterface $key */
            $key = $this->key;
            return $key;
        }

        throw new \RuntimeException('Unable to get private key, not known');
    }

    /**
     * Get the public key the private key or public key.
     *
     * @return PublicKeyInterface
     */
    public function getPublicKey(): PublicKeyInterface
    {
        if ($this->isPrivate()) {
            return $this->getPrivateKey()->getPublicKey();
        } else {
            /** @var PublicKeyInterface $key */
            $key = $this->key;
            return $key;
        }
    }

    /**
     * @return HdNode
     */
    public function withoutPrivateKey(): HdNode
    {
        $clone = clone $this;
        $clone->key = $clone->getPublicKey();
        return $clone;
    }

    /**
     * Return whether this is a private key
     *
     * @return bool
     */
    public function isPrivate(): bool
    {
        return $this->key->isPrivate();
    }

    /**
     * Create a buffer containing data to be hashed hashed to yield the child offset
     *
     * @param int $sequence
     * @return BufferInterface
     * @throws \Exception
     */
    protected function getHmacSeed(int $sequence): BufferInterface
    {
        if ($sequence < 0 || $sequence > IntRange::U32_MAX) {
            throw new \InvalidArgumentException("Sequence is outside valid range, must be >= 0 && <= (2^31)-1");
        }

        if ($sequence >> 31) {
            if (!$this->isPrivate()) {
                throw new \Exception("Can't derive a hardened key without the private key");
            }

            $data = "\x00{$this->getPrivateKey()->getBinary()}";
        } else {
            $data = $this->getPublicKey()->getBinary();
        }

        return new Buffer($data . pack("N", $sequence));
    }

    /**
     * Derive a child key
     *
     * @param int $sequence
     * @return HierarchicalKey
     * @throws \Exception
     */
    public function deriveChild(int $sequence): HdNode
    {
        $nextDepth = $this->getDepth() + 1;
        if ($nextDepth > IntRange::U8_MAX) {
            throw new \InvalidArgumentException('Invalid depth for BIP32 key, cannot exceed 255');
        }

        $hash = Hash::hmac('sha512', $this->getHmacSeed($sequence), $this->chainCode);
        $offset = $hash->slice(0, 32);
        $chain = $hash->slice(32, 32);

        if (false === $this->ecAdapter->validatePrivateKey($offset)) {
            return $this->deriveChild($sequence + 1);
        }

        $key = $this->key->tweakAdd($offset->getGmp());
        return $this->createChild($sequence, $chain, $key);
    }

    /**
     * @param array|\stdClass|\Traversable $list
     * @return HierarchicalKey
     * @throws \Exception
     */
    public function deriveFromList($list): HierarchicalKey
    {
        if (!is_array($list) && !$list instanceof \Traversable && !$list instanceof \stdClass) {
            throw new \InvalidArgumentException('List must be an array or \Traversable');
        }

        $key = $this;
        foreach ($list as $sequence) {
            $key = $key->deriveChild((int) $sequence);
        }

        return $key;
    }

    /**
     * Decodes a BIP32 path into actual 32bit sequence numbers and derives the child key
     *
     * @param string $path
     * @return HierarchicalKey
     * @throws \Exception
     */
    public function derivePath(string $path): HierarchicalKey
    {
        $sequences = new HierarchicalKeySequence();
        return $this->deriveFromList($sequences->decodePath($path));
    }
}
