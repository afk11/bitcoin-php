<?php

declare(strict_types=1);

namespace BitWasp\Bitcoin\Script\Path;

use BitWasp\Bitcoin\Script\Opcodes;
use BitWasp\Bitcoin\Script\Parser\Operation;
use BitWasp\Bitcoin\Script\Script;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\ScriptInterface;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

class CodePath
{
    private $script = '';
    private $active = [];
    private $trace = [];
    private $indexOpposite = [];

    public function __construct(string $script, array $active, array $trace)
    {
        $this->script = $script;
        $this->active = $active;
        $this->trace = $trace;
    }

    public function __toString()
    {
        return sprintf("CodePath(vfStack=%s, trace=%s, script=%s)",
            implode(" ", array_map('intval', $this->active)),
            implode(" ", array_map('intval', $this->trace)),
            bin2hex($this->script)
        );
    }

    public function getTrace()
    {
        return $this->trace;
    }

    public function getScript(): ScriptInterface
    {
        return new Script(new Buffer($this->script));
    }

    public function isConditionalActive()
    {
        return count($this->active) > 0;
    }

    public function isActive(): bool
    {
        if ($this->isConditionalActive()) {
            return $this->active[count($this->active) - 1];
        }
        return true;
    }

    public function swapActive()
    {
        if (0 === count($this->active)) {
            // activate first codepath
            $this->active[] = true;
        }
        $i = count($this->active) - 1;
        $this->active[$i] = !$this->active[$i];
    }

    public function popActive()
    {
        if (0 === count($this->active)) {
            throw new \RuntimeException("ENDIF without IF");
        }
        array_pop($this->active);
    }

    public function inactiveBranch(bool $activation)
    {
        $script = chr($activation ? Opcodes::OP_IF : Opcodes::OP_NOTIF);
        $this->script .= $script;
        array_push($this->active, false);
    }

    public function split(bool $activation, int $antiIndex): CodePath
    {
        $new = new CodePath($this->script, $this->active, $this->trace);
        $script = chr($activation ? Opcodes::OP_IF : Opcodes::OP_NOTIF);
        $this->script .= $script;
        array_push($this->active, $activation);
        array_push($this->trace, $activation);
        array_push($this->indexOpposite, $antiIndex);

        $new->script .= $script;
        array_push($new->active, !$activation);
        array_push($new->trace, !$activation);

        return $new;
    }

    public function addOp(Operation $operation)
    {
        $this->script .= ScriptFactory::create()->opcode($operation->getOp())->getScript()->getBinary();
    }

    public function addData(BufferInterface $data)
    {
        $this->script .= ScriptFactory::create()->data($data)->getScript()->getBinary();
    }
}
