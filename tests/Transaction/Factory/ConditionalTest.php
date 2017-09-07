<?php

namespace BitWasp\Bitcoin\Tests\Transaction\Factory;

use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Tests\AbstractTestCase;
use BitWasp\Bitcoin\Transaction\Factory\Conditional;
use BitWasp\Buffertools\Buffer;

class ConditionalTest extends AbstractTestCase
{
    public function testIfDefaults()
    {
        $opcode = Opcodes::OP_IF;
        $cond = new Conditional($opcode);
        $this->assertEquals($opcode, $cond->getOp());
        $this->assertFalse($cond->hasValue());

        $serialized = $cond->serialize();
        $this->assertEquals([], $serialized);

        $cond->setValue(true);
        $this->assertTrue($cond->hasValue());
        $this->assertEquals([new Buffer("\x01")], $cond->serialize());

        $cond->setValue(false);
        $this->assertTrue($cond->hasValue());
        $this->assertEquals([new Buffer("")], $cond->serialize());
    }

    public function testNotIfDefaults()
    {
        $opcode = Opcodes::OP_NOTIF;
        $cond = new Conditional($opcode);
        $this->assertEquals($opcode, $cond->getOp());
        $this->assertFalse($cond->hasValue());

        $serialized = $cond->serialize();
        $this->assertEquals([], $serialized);

        $cond->setValue(true);
        $this->assertTrue($cond->hasValue());
        $this->assertEquals([new Buffer("\x01")], $cond->serialize());

        $cond->setValue(false);
        $this->assertTrue($cond->hasValue());
        $this->assertEquals([new Buffer("")], $cond->serialize());
    }

    public function invalidOpcodeProvider()
    {
        return [[Opcodes::OP_0], [Opcodes::OP_1], [Opcodes::OP_EQUALVERIFY]];
    }

    /**
     * @dataProvider invalidOpcodeProvider
     */
    public function testInvalidOpcode($op)
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Opcode for conditional is only IF / NOTIF");

        new Conditional($op);
    }
}
