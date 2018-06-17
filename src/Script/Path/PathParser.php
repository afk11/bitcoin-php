<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Script\Path;

use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Parser\Operation;
use BitWasp\Bitcoin\Script\ScriptInterface;
use BitWasp\Buffertools\BufferInterface;

class PathParser
{
    /**
     * @var CodePath[]
     */
    private $codePaths = [];

    public static function parse(ScriptInterface $script)
    {
        $parser = new self();
        // Build code paths
        foreach ($script->getScriptParser() as $operation) {
            if ($operation->isPush()) {
                $parser->addData($operation->getData());
            } else {
                $parser->addOp($operation);
            }
        }

        foreach ($parser->getCodePaths() as $codePath) {
            if ($codePath->isConditionalActive()) {
                throw new \RuntimeException("Invalid script, unbalanced conditional");
            }
        }

        return $parser;
    }

    public function __construct()
    {
        $this->codePaths[] = new CodePath('', [], []);
    }

    /**
     * @return CodePath[]
     */
    public function getCodePaths(): array
    {
        return $this->codePaths;
    }

    public function split(bool $activation)
    {
        $numPaths = count($this->codePaths);
        for ($i = 0; $i < $numPaths; $i++) {
            if ($this->codePaths[$i]->isActive()) {
                $newIdx = count($this->codePaths);
                echo "split $i , activation " . ($activation?"y":"n").PHP_EOL;
                echo "before  $i - " . $this->codePaths[$i].PHP_EOL;
                $this->codePaths[$newIdx] = $this->codePaths[$i]->split($activation, $newIdx);
                echo "current $i - ".$this->codePaths[$i].PHP_EOL;
                echo "new     $newIdx - ". $this->codePaths[$newIdx].PHP_EOL;
            } else {
                echo "inactive branch ($i)\n";
                $this->codePaths[$i]->inactiveBranch($activation);
            }
        }
    }

    public function addOp(Operation $operation)
    {
        switch ($operation->getOp()) {
            case Opcodes::OP_IF:
            case Opcodes::OP_NOTIF:
                echo "OP_IF/OP_NOTIF split\n";
                $this->split(Opcodes::OP_IF === $operation->getOp());
                break;
            case Opcodes::OP_ENDIF:
                echo "OP_ENDIF popactive\n";
                foreach ($this->codePaths as $i => $codePath) {
                    echo "$i - before  " . $codePath.PHP_EOL;
                    $codePath->addOp($operation);
                    $codePath->popActive();
                    echo "$i - after " . $codePath.PHP_EOL;
                }
                break;
            case Opcodes::OP_ELSE:
                echo "OP_ELSE swapActive\n";
                foreach ($this->codePaths as $i => $codePath) {
                    echo "$i - before " . $codePath.PHP_EOL;
                    $codePath->addOp($operation);
                    $codePath->swapActive();
                    echo "$i - after " . $codePath.PHP_EOL;
                }
                break;
            default:
                echo "op: ".(new Opcodes())->getOp($operation->getOp()).PHP_EOL;
                foreach ($this->codePaths as $i => $codePath) {
                    if ($codePath->isActive()) {
                        echo "on path $i\n";
                        $codePath->addOp($operation);
                    }
                }
        }
    }

    public function addData(BufferInterface $data)
    {
        echo "addData ({$data->getHex()})\n";
        foreach ($this->codePaths as $i => $codePath) {
            if ($codePath->isActive()) {
                echo "on path $i\n";
                $codePath->addData($data);
            }
        }
    }
}
