<?php

namespace BitWasp\Bitcoin\Tests\Script\ScriptInfo;

use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Script\Classifier\OutputClassifier;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\ScriptInfo\PayToPubkeyHash;
use BitWasp\Bitcoin\Script\ScriptType;
use BitWasp\Bitcoin\Tests\AbstractTestCase;
use BitWasp\Buffertools\Buffer;

class PayToPubkeyHashTest extends AbstractTestCase
{
    public function testMethods()
    {
        $priv = PrivateKeyFactory::create();
        $pub = $priv->getPublicKey();
        $keyHash = $pub->getPubKeyHash();
        $script = ScriptFactory::scriptPubKey()->payToPubKeyHash($keyHash);

        $classifier = new OutputClassifier();
        $this->assertEquals(ScriptType::P2PKH, $classifier->classify($script));

        $info = PayToPubkeyHash::fromScript($script);
        $this->assertEquals(1, $info->getRequiredSigCount());
        $this->assertEquals(1, $info->getKeyCount());
        $this->assertTrue($info->checkInvolvesKey($pub));

        $otherpriv = PrivateKeyFactory::create();
        $otherpub = $otherpriv->getPublicKey();
        $this->assertFalse($info->checkInvolvesKey($otherpub));

        $this->assertTrue($keyHash->equals($info->getPubKeyHash()));
    }

    public function testVerifyMustBeEnabled()
    {
        $priv = PrivateKeyFactory::create();
        $pub = $priv->getPublicKey();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("CHECKSIGVERIFY not allowed");

        new PayToPubkeyHash(Opcodes::OP_CHECKSIGVERIFY, $pub->getPubKeyHash(), false);
    }

    public function testKeyHashSize()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Key hash must be 20 bytes");

        new PayToPubkeyHash(Opcodes::OP_CHECKSIG, new Buffer());
    }

    public function testChecksOpcode()
    {
        $priv = PrivateKeyFactory::create();
        $pub = $priv->getPublicKey();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Invalid opcode for PayToPubkeyHash script");

        new PayToPubkeyHash(Opcodes::OP_DUP, $pub->getPubKeyHash());
    }
}
