<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Tests\Serializer\Script;

use BitWasp\Bitcoin\Key\Factory\PrivateKeyFactory;
use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\ScriptInterface;
use BitWasp\Bitcoin\Serializer\Script\AsmEncoder;
use BitWasp\Bitcoin\Tests\AbstractTestCase;
use BitWasp\Buffertools\Buffer;

class AsmEncoderTest extends AbstractTestCase
{
    public function getTestCases(): array
    {
        $buffer = new Buffer(str_repeat('A', 512));
        $hash32 = new Buffer(str_repeat('A', 32));
        $hash20 = new Buffer(str_repeat('A', 20));
        $pkf = PrivateKeyFactory::compressed();
        $key1 = $pkf->fromHex("0000000000000000000000000000000000000000000000000000000000000001")->getPublicKey()->getBuffer();
        $key2 = $pkf->fromHex("0000000000000000000000000000000000000000000000000000000000000002")->getPublicKey()->getBuffer();
        return [
            [ScriptFactory::create()
                ->opcode(Opcodes::OP_0)
                ->opcode(Opcodes::OP_16)
                ->push($buffer)
                ->opcode(Opcodes::OP_RETURN)
                ->getScript(), "0 16 0x4d0002{$buffer->getHex()} OP_RETURN"],
            [ScriptFactory::create()
                ->opcode(Opcodes::OP_IF, Opcodes::OP_ELSE, Opcodes::OP_NOTIF, Opcodes::OP_ENDIF, Opcodes::OP_ENDIF)
                ->getScript(), "OP_IF OP_ELSE OP_NOTIF OP_ENDIF OP_ENDIF"],
            [ScriptFactory::create()
                ->opcode(Opcodes::OP_0)->push($hash32)
                ->getScript(), "0 0x20{$hash32->getHex()}"],
            [ScriptFactory::create()
                ->opcode(Opcodes::OP_0)->push($hash20)
                ->getScript(), "0 0x14{$hash20->getHex()}"],
            [ScriptFactory::scriptPubKey()->p2pkh($hash20),
                "OP_DUP OP_HASH160 0x14{$hash20->getHex()} OP_EQUALVERIFY OP_CHECKSIG"],
            [ScriptFactory::scriptPubKey()->p2sh($hash20),
                "OP_HASH160 0x14{$hash20->getHex()} OP_EQUAL"],
            [ScriptFactory::scriptPubKey()->multisigKeyBuffers(1, [$key1, $key2]),
                "1 0x21{$key1->getHex()} 0x21{$key2->getHex()} 2 OP_CHECKMULTISIG"],
        ];
    }

    /**
     * @dataProvider getTestCases
     * @param ScriptInterface $script
     * @param string $expectedScript
     */
    public function testWorkingCase(ScriptInterface $script, string $expectedScript)
    {
        $serializer = new AsmEncoder(new Opcodes());
        $encoded = $serializer->serialize($script);
        $this->assertEquals($expectedScript, $encoded);

        $decoded = $serializer->parse($encoded);
        $this->assertEquals($script->getBinary(), $decoded->getBinary());

        $decoded = $serializer->parse($serializer->serialize($script, AsmEncoder::FLAG_PRETTY_PRINT));
        $this->assertEquals($script->getBinary(), $decoded->getBinary());
    }

    public function testParseQuotedString()
    {
        $serializer = new AsmEncoder();
        $string = '\'Azzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\' OP_EQUAL';
        $decoded = $serializer->parse($string);
        $this->assertEquals(
            "0x4b417a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a OP_EQUAL",
            $serializer->serialize($decoded)
        );
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Script parse error: element "OP_INVALID_OPCODE"
     */
    public function testUnknownUpcode()
    {
        $serializer = new AsmEncoder();
        $string = 'OP_INVALID_OPCODE';
        $serializer->parse($string);
    }
}
