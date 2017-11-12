<?php

namespace BitWasp\Bitcoin\Script\Interpreter;

use BitWasp\Bitcoin\Script\ScriptInterface;
use BitWasp\Bitcoin\Transaction\SignatureHash\BitcoinGoldSigHash;
use BitWasp\Bitcoin\Transaction\SignatureHash\SigHash;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

class BitcoinGoldChecker extends Checker
{
    protected $sigHashOptionalBits = SigHash::ANYONECANPAY | SigHash::BITCOINCASH;

    /**
     * @param ScriptInterface $script
     * @param int $sigHashType
     * @param int $sigVersion
     * @return BufferInterface
     */
    public function getSigHash(ScriptInterface $script, $sigHashType, $sigVersion)
    {
        if ($sigVersion !== 0) {
            throw new \RuntimeException("SigVersion must be 0");
        }

        $cacheCheck = $sigVersion . $sigHashType . $script->getBuffer()->getBinary();
        if (!isset($this->sigHashCache[$cacheCheck])) {
            $hasher = new BitcoinGoldSigHash($this->transaction, $this->amount);
            $hash = $hasher->calculate($script, $this->nInput, $sigVersion, $sigHashType);
            $this->sigHashCache[$cacheCheck] = $hash->getBinary();
        } else {
            $hash = new Buffer($this->sigHashCache[$cacheCheck], 32, $this->adapter->getMath());
        }

        return $hash;
    }
}
