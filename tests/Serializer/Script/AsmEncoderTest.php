<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Tests\Serializer\Script;

use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Serializer\Script\AsmEncoder;
use BitWasp\Bitcoin\Tests\AbstractTestCase;
use BitWasp\Buffertools\Buffer;

class AsmEncoderTest extends AbstractTestCase
{
    public function testWorkingCase()
    {
        $buffer = new Buffer(str_repeat('A', 512));
        $script = ScriptFactory::create()
            ->opcode(Opcodes::OP_0)
            ->opcode(Opcodes::OP_16)
            ->push($buffer)
            ->opcode(Opcodes::OP_RETURN)
            ->getScript();

        $serializer = new AsmEncoder(new Opcodes());
        $encoded = $serializer->serialize($script);
        $this->assertEquals("0 16 0x4d0002{$buffer->getHex()} OP_RETURN", $encoded);

        $decoded = $serializer->parse($encoded);
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
