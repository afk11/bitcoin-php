<?php

namespace BitWasp\Bitcoin\Crypto\EcAdapter\Signature;

use BitWasp\Bitcoin\Crypto\EcAdapter\Adapter\EcAdapterInterface;
use BitWasp\Bitcoin\Crypto\EcAdapter\Key\PrivateKeyInterface;
use BitWasp\Bitcoin\Crypto\Random\Rfc6979;
use BitWasp\Buffertools\BufferInterface;

class Signer implements SignerInterface
{
    /**
     * @var EcAdapterInterface
     */
    private $ecAdapter;

    /**
     * @var PrivateKeyInterface
     */
    private $priv;

    /**
     * Signer constructor.
     * @param EcAdapterInterface $ecAdapter
     * @param PrivateKeyInterface $privateKey
     */
    public function __construct(EcAdapterInterface $ecAdapter, PrivateKeyInterface $privateKey)
    {
        $this->ecAdapter = $ecAdapter;
        $this->priv = $privateKey;
    }

    /**
     * @return \BitWasp\Bitcoin\Crypto\EcAdapter\Key\PublicKeyInterface
     */
    public function getPublicKey()
    {
        return $this->priv->getPublicKey();
    }

    /**
     * @param BufferInterface $msg32
     * @return SignatureInterface
     */
    public function sign(BufferInterface $msg32)
    {
        return $this->ecAdapter->sign($msg32, $this->priv, new Rfc6979($this->ecAdapter, $this->priv, $msg32, 'sha256'));
    }
}
