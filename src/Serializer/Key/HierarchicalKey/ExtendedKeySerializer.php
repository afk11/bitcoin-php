<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Serializer\Key\HierarchicalKey;

use BitWasp\Bitcoin\Crypto\EcAdapter\Adapter\EcAdapterInterface;
use BitWasp\Bitcoin\Key\Deterministic\HierarchicalKey;
use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Key\PublicKeyFactory;
use BitWasp\Bitcoin\Network\NetworkInterface;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Exceptions\ParserOutOfRange;
use BitWasp\Buffertools\Parser;

class ExtendedKeySerializer
{
    /**
     * @var EcAdapterInterface
     */
    private $ecAdapter;

    /**
     * @var VersionedExtendedKeySerializer
     */
    private $verSer;

    /**
     * @param EcAdapterInterface $ecAdapter
     * @throws \Exception
     */
    public function __construct(EcAdapterInterface $ecAdapter, VersionedExtendedKeySerializer $verSer)
    {
        $this->verSer = $verSer;
        $this->ecAdapter = $ecAdapter;
    }

    /**
     * @param NetworkInterface $network
     * @param HierarchicalKey $key
     * @return BufferInterface
     * @throws \Exception
     */
    public function serialize(NetworkInterface $network, HierarchicalKey $key): BufferInterface
    {
        if ($key->isPrivate()) {
            $prefix = $network->getHDPrivByte();
        } else {
            $prefix = $network->getHDPubByte();
        }

        return $this->verSer->serialize($prefix, $key);
    }

    /**
     * @param NetworkInterface $network
     * @param Parser $parser
     * @return HierarchicalKey
     * @throws ParserOutOfRange
     */
    public function fromParser(NetworkInterface $network, Parser $parser): HierarchicalKey
    {
        try {
            /** @var BufferInterface $bytes */
            /** @var int $depth */
            /** @var int $parentFingerprint */
            /** @var int $sequence */
            /** @var BufferInterface $chainCode */
            /** @var BufferInterface $keyData - we are certain this is 32 bytes */
            list ($bytes, $depth, $parentFingerprint, $sequence, $chainCode, $keyData) =
                $this->verSer->fromParser($parser);

            $bytes = $bytes->getHex();
        } catch (ParserOutOfRange $e) {
            throw new ParserOutOfRange('Failed to extract HierarchicalKey from parser');
        }

        $isPrivate = $network->getHDPrivByte() === $bytes;
        $isPublic = $network->getHDPubByte() === $bytes;
        if (!($isPrivate || $isPublic)) {
            throw new \InvalidArgumentException('HD key magic bytes do not match network magic bytes');
        }

        if ($isPrivate) {
            $key = PrivateKeyFactory::fromBuffer($keyData->slice(1), true, $this->ecAdapter);
        } else {
            $key = PublicKeyFactory::fromBuffer($keyData, $this->ecAdapter);
        }

        return new HierarchicalKey($this->ecAdapter, $depth, $parentFingerprint, $sequence, $chainCode, $key);
    }

    /**
     * @param NetworkInterface $network
     * @param BufferInterface $buffer
     * @return HierarchicalKey
     * @throws ParserOutOfRange
     */
    public function parse(NetworkInterface $network, BufferInterface $buffer): HierarchicalKey
    {
        return $this->fromParser($network, new Parser($buffer));
    }
}
