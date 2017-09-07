<?php

namespace BitWasp\Bitcoin\Tests\Transaction\Factory;

use BitWasp\Bitcoin\Crypto\EcAdapter\Key\PrivateKeyInterface;
use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\ScriptInfo\Multisig;
use BitWasp\Bitcoin\Script\ScriptInfo\PayToPubkey;
use BitWasp\Bitcoin\Script\ScriptInfo\PayToPubkeyHash;
use BitWasp\Bitcoin\Tests\AbstractTestCase;
use BitWasp\Bitcoin\Transaction\Factory\Checksig;

class ChecksigTest extends AbstractTestCase
{
    public function scriptInfoProvider()
    {
        $keys = [
            PrivateKeyFactory::fromInt(1),
            PrivateKeyFactory::fromInt(2),
            PrivateKeyFactory::fromInt(3),
        ];

        $pubKeyBufs = array_map(function (PrivateKeyInterface $priv) {
            return $priv->getPublicKey()->getBuffer();
        }, $keys);

        return [
            [
                new Multisig(3, $pubKeyBufs, Opcodes::OP_CHECKMULTISIG, false),
            ],
            [
                new Multisig(3, $pubKeyBufs, Opcodes::OP_CHECKMULTISIGVERIFY, true),
            ],
            [
                new PayToPubkey(Opcodes::OP_CHECKSIG, $pubKeyBufs[0], false),
            ],
            [
                new PayToPubkey(Opcodes::OP_CHECKSIGVERIFY, $pubKeyBufs[0], true),
            ],
            [
                new PayToPubkeyHash(Opcodes::OP_CHECKSIG, $keys[0]->getPubKeyHash(), false),
            ],
            [
                new PayToPubkeyHash(Opcodes::OP_CHECKSIGVERIFY, $keys[0]->getPubKeyHash(), true),
            ],
        ];
    }

    /**
     * @param PayToPubkeyHash|PayToPubkey|Multisig $info
     * @dataProvider scriptInfoProvider
     */
    public function testScriptInfoCase($info)
    {
        $checksig = new Checksig($info);
        $this->assertSame($info, $checksig->getInfo());
        $this->assertEquals($info->isChecksigVerify(), $checksig->isVerify());
        $this->assertEquals($info->getType(), $checksig->getType());
        $this->assertEquals($info->getRequiredSigCount(), $checksig->getRequiredSigs());
    }
}
