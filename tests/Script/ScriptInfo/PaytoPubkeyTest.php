<?php

namespace BitWasp\Bitcoin\Tests\Script\ScriptInfo;

use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Script\Classifier\OutputClassifier;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\ScriptInfo\PayToPubkey;
use BitWasp\Bitcoin\Script\ScriptType;
use BitWasp\Bitcoin\Tests\AbstractTestCase;

class PaytoPubkeyTest extends AbstractTestCase
{
    public function testMethods()
    {
        $priv = PrivateKeyFactory::create();
        $pub = $priv->getPublicKey();

        $script = ScriptFactory::sequence([$pub->getBuffer(), Opcodes::OP_CHECKSIG]);
        $classifier = new OutputClassifier();
        $this->assertEquals(ScriptType::P2PK, $classifier->classify($script));

        $info = PayToPubkey::fromScript($script);
        $this->assertEquals(1, $info->getRequiredSigCount());
        $this->assertEquals(1, $info->getKeyCount());
        $this->assertTrue($pub->getBuffer()->equals($info->getKeyBuffer()));
        $this->assertTrue($info->checkInvolvesKey($pub));

        $otherPriv = PrivateKeyFactory::create();
        $otherPub = $otherPriv->getPublicKey();

        $this->assertFalse($info->checkInvolvesKey($otherPub));
    }

    public function testVerifyMustBeEnabled()
    {
        $priv = PrivateKeyFactory::create();
        $pub = $priv->getPublicKey();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("CHECKSIGVERIFY not allowed");

        new PayToPubkey(Opcodes::OP_CHECKSIGVERIFY, $pub->getBuffer(), false);
    }
}
