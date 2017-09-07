<?php

namespace BitWasp\Bitcoin\Tests\Script\ScriptInfo;

use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Key\PublicKeyFactory;
use BitWasp\Bitcoin\Script\Classifier\OutputClassifier;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\ScriptInfo\Multisig;
use BitWasp\Bitcoin\Script\ScriptType;
use BitWasp\Bitcoin\Tests\AbstractTestCase;

class MultisigTest extends AbstractTestCase
{
    public function testMethods()
    {
        $pub = PublicKeyFactory::fromHex('045b81f0017e2091e2edcd5eecf10d5bdd120a5514cb3ee65b8447ec18bfc4575c6d5bf415e54e03b1067934a0f0ba76b01c6b9ab227142ee1d543764b69d901e0');
        $otherpub = $pub->tweakAdd(gmp_init(1));

        $script = ScriptFactory::scriptPubKey()->multisig(2, [$pub, $otherpub], false);
        $classifier = new OutputClassifier();
        $this->assertEquals(ScriptType::MULTISIG, $classifier->classify($script));

        $info = Multisig::fromScript($script);
        $this->assertEquals(2, $info->getRequiredSigCount());
        $this->assertEquals(2, $info->getKeyCount());
        $this->assertTrue($info->checkInvolvesKey($pub));
        $this->assertTrue($info->checkInvolvesKey($otherpub));

        $unrelatedPub = $otherpub->tweakAdd(gmp_init(1));
        $this->assertFalse($info->checkInvolvesKey($unrelatedPub));

        $this->assertTrue($info->getKeyBuffers()[0]->equals($pub->getBuffer()));
        $this->assertTrue($info->getKeyBuffers()[1]->equals($otherpub->getBuffer()));
    }
    public function testVerifyMustBeEnabled()
    {
        $priv = PrivateKeyFactory::create();
        $pub = $priv->getPublicKey();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("CHECKMULTISIGVERIFY not allowed");

        new Multisig(1, [$pub->getBuffer()], Opcodes::OP_CHECKMULTISIGVERIFY, false);
    }

    public function testVerifyIsEnabled()
    {
        $priv = PrivateKeyFactory::create();
        $pub = $priv->getPublicKey();

        $multisig = new Multisig(1, [$pub->getBuffer()], Opcodes::OP_CHECKMULTISIGVERIFY, true);
        $this->assertEquals(Opcodes::OP_CHECKMULTISIGVERIFY, $multisig->isChecksigVerify());
    }

    public function testChecksOpcode()
    {
        $priv = PrivateKeyFactory::create();
        $pub = $priv->getPublicKey();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid opcode for Multisig");

        new Multisig(1, [$pub->getBuffer()], Opcodes::OP_DUP, true);
    }

}
