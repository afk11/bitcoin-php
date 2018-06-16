<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Serializer\Script;

use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Script;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\ScriptInterface;
use BitWasp\Buffertools\Buffer;

class AsmEncoder
{
    /**
     * @var Opcodes
     */
    private $opcodes;

    const FLAG_PRETTY_PRINT = 1 << 1;

    public function __construct(Opcodes $opcodes = null)
    {
        if (null === $opcodes) {
            $opcodes = new Opcodes();
        }
        $this->opcodes = $opcodes;
    }

    public function serialize(ScriptInterface $script, int $options = 0): string
    {
        $items = [];

        foreach ($script->getScriptParser() as $operation) {
            $opcode = $operation->getOp();
            if ($opcode === Opcodes::OP_0) {
                $items[] = "0";
            } else if ($opcode >= Opcodes::OP_1 && $opcode <= Opcodes::OP_16 || $opcode === Opcodes::OP_1NEGATE) {
                $items[] = $opcode - Opcodes::OP_1NEGATE - 1;
            } else if ($opcode > Opcodes::OP_NOP && $opcode < Opcodes::OP_NOP10) {
                $items[] = $this->opcodes->getOp($operation->getOp());
            } else if ($operation->isPush()) {
                $items[] = "0x" . ScriptFactory::create()->push($operation->getData())->getScript()->getHex();
            }
        }

        if ($options & 1) {
            $lines = [];
            $line = [];
            foreach ($items as $i => $item) {
                if ($item === 'OP_IF' || $item === 'OP_NOTIF' || $item === 'OP_ELSE' || $item === 'OP_ENDIF') {
                    $lines[] = implode(" ", $line);
                    $line = [];
                }

                $line[] = $item;

                if ($item === 'OP_IF' || $item === 'OP_NOTIF' || $item === 'OP_ELSE' || $item === 'OP_ENDIF') {
                    $lines[] = implode(" ", $line);
                    $line = [];
                }
            }

            if (count($line) > 0) {
                $lines[] = implode(" ", $line);
                $line = [];
            }

            return implode("\n", array_filter($lines, 'strlen'));
        }

        return implode(" ", $items);
    }

    public function parse(string $scriptAsm): ScriptInterface
    {
        $builder = ScriptFactory::create();
        $split = explode(" ", $scriptAsm);
        foreach ($split as $item) {
            if (strlen($item) == '') {
            } else if (preg_match("/^[0-9]*$/", $item) || substr($item, 0, 1) === "-" && preg_match("/^[0-9]*$/", substr($item, 1))) {
                $builder->int((int) $item);
            } else if (substr($item, 0, 2) === "0x") {
                $scriptConcat = new Script(Buffer::hex(substr($item, 2)));
                $builder->concat($scriptConcat);
            } else if (strlen($item) >= 2 && substr($item, 0, 1) === "'" && substr($item, -1) === "'") {
                $buffer = new Buffer(substr($item, 1, strlen($item) - 2));
                $builder->push($buffer);
            } else {
                try {
                    $builder->opcode($this->opcodes->getOpByName($item));
                } catch (\Exception $e) {
                    throw new \RuntimeException('Script parse error: element "' . $item . '"');
                }
            }
        }

        return $builder->getScript();
    }
}
