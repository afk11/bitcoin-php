<?php

namespace BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Signature;

use BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Adapter\EcAdapter;
use BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Key\PrivateKey;
use BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Key\PublicKey;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

class SchnorrSigner
{
    private $adapter;
    public function __construct(EcAdapter $ecAdapter)
    {
        $this->adapter = $ecAdapter;
    }

    public function sign(PrivateKey $privateKey, BufferInterface $message32)
    {
        $G = $this->adapter->getGenerator();
        $hash = $this->hashPrivateData($privateKey, $message32);

        $k = gmp_mod($hash->getGmp(), $G->getOrder());
        $R = $G->mul($k);
        $jacobi = gmp_jacobi($R->getY(), $G->getCurve()->getPrime());
        if ($jacobi !== 1) {
            $k = gmp_sub($G->getOrder(), $k);
        }

        $hash = $this->hashPublicData($R->getX(), $privateKey->getPublicKey(), $message32);
        $e = gmp_mod($hash->getGmp(), $G->getOrder());
        $s = gmp_mod(gmp_add($k, gmp_mul($e, $privateKey->getSecret())), $G->getOrder());
        return new Signature($this->adapter, $R->getX(), $s);
    }

    private function hashPrivateData(PrivateKey $privateKey, BufferInterface $message32)
    {
        $hasher = hash_init('sha256');
        hash_update($hasher, $this->adapter->getMath()->intToFixedSizeString($privateKey->getSecret(), 32));
        hash_update($hasher, $message32->getBinary());
        return new Buffer(hash_final($hasher, true));
    }

    private function hashPublicData(\GMP $Rx, PublicKey $publicKey, BufferInterface $message32, string &$rxBytes = null)
    {
        $hasher = hash_init('sha256');
        $rxBytes = $this->adapter->getMath()->intToFixedSizeString($Rx, 32);
        hash_update($hasher, $Rx);
        hash_update($hasher, $publicKey->getBinary());
        hash_update($hasher, $message32->getBinary());
        return new Buffer(hash_final($hasher, true));
    }
    public function verify(BufferInterface $message32, PublicKey $publicKey, Signature $signature): bool
    {
        $G = $this->adapter->getGenerator();

        $RxBytes = null;
        $hash = $this->hashPublicData($signature->getR(), $publicKey, $message32, $RxBytes);

        $e = gmp_mod($hash->getGmp(), $G->getOrder());
        $R = $G->mul($signature->getS())
            ->add($publicKey->tweakMul(gmp_sub($G->getOrder(), $e))->getPoint());

        return gmp_cmp(gmp_jacobi($R->getY(), $G->getCurve()->getPrime()), 1) !== 0 &&
            hash_equals($RxBytes, $this->adapter->getMath()->intToFixedSizeString($R->getX(), 32))
        ;
    }
}
