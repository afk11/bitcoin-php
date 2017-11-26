<?php

namespace BitWasp\Bitcoin\RpcTest;


use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Block\Block;
use BitWasp\Bitcoin\Block\BlockHeader;
use BitWasp\Bitcoin\Block\MerkleRoot;
use BitWasp\Bitcoin\Chain\ProofOfWork;
use BitWasp\Bitcoin\Chain\Params\Regtest;
use BitWasp\Bitcoin\Crypto\Hash;
use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Script\ScriptWitness;
use BitWasp\Bitcoin\Transaction\Factory\TxBuilder;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Buffertools;

class GenerateBlockTest extends AbstractTestCase
{
    /**
     * @var RegtestBitcoinFactory
     */
    private $rpcFactory;

    public function __construct($name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);

        static $rpcFactory = null;
        if (null === $rpcFactory) {
            $rpcFactory = new RegtestBitcoinFactory();
        }
        $this->rpcFactory = $rpcFactory;
    }

    public function testCanGenerateANonWitnessBlock()
    {
        $bitcoind = $this->rpcFactory->startBitcoind();

        $tipsResult = $bitcoind->request('getchaintips');
        $this->assertEquals(null, $tipsResult['error']);

        $bestTip = null;
        foreach ($tipsResult['result'] as $tip) {
            if ("active" === $tip['status']) {
                $bestTip = $tip;
            }
        }

        $prevHeight = $bestTip['height'];

        $coinbaseSig = ScriptFactory::create()
            ->int($prevHeight + 1)
            ->push(Buffer::hex("01"))
            ->getScript()
        ;

        $privateKey = PrivateKeyFactory::create();
        $coinbasePubKey = ScriptFactory::scriptPubKey()->p2wkh($privateKey->getPubKeyHash());

        $cbBuilder = new TxBuilder();
        $cbBuilder->coinbase($coinbaseSig);
        $cbBuilder->output(5000000000, $coinbasePubKey);

        $coinbase = $cbBuilder->get();
        $merkleRoot = $coinbase->getTxId();

        $bestBlock = $bitcoind->request('getblock', [$bestTip['hash']])['result'];
        print_r($bestBlock);

        $now = $bestBlock['time'] + 10;
        $bits = Buffer::hex($bestBlock['bits'])->getInt();
        $base = new BlockHeader(
            1,
            Buffer::hex($bestTip['hash']),
            $merkleRoot,
            $now,
            $bits,
            0
        );

        $math = Bitcoin::getMath();
        $params = new Regtest($math);
        $pow = new ProofOfWork($math, $params);
        $data = substr($base->getBinary(), 0, -4);

        for ($i = 0; $i < pow(2, 32); $i++) {
            $blob = $data . pack("V", $i);
            $hash = (new Buffer(hash('sha256', hash('sha256', $blob, true), true)))
                ->flip();

            try {
                if ($pow->check($hash, $bits)) {
                    break;
                }
            } catch (\Exception $e) {

            }
        }

        /** @var BufferInterface $hash */

        $header = new BlockHeader(
            $base->getVersion(),
            $base->getPrevBlock(),
            $base->getMerkleRoot(),
            $base->getTimestamp(),
            $bits,
            $i
        );

        $block = new Block($math, $header, [$coinbase]);
        $blockHex = $block->getHex();

        $result = $bitcoind->request("submitblock", [$blockHex]);
        $this->assertRpcNoError($result);

        $newBestBlockHash = $bitcoind->request("getbestblockhash");
        $this->assertRpcGetBestBlockHash($newBestBlockHash);
        $this->assertEquals($newBestBlockHash['result'], $hash->getHex(), "bestblockhash doesn't match our block hash");

        $blockRes = $bitcoind->request('getblock', [$newBestBlockHash['result']]);
        $this->assertRpcGetBlock($blockRes);

        $block = $blockRes['result'];
        $this->assertEquals($prevHeight + 1, $block['height']);
        $this->assertEquals(1, $block['confirmations']);
        $this->assertEquals($header->getVersion(), $block['version']);
        $this->assertEquals($header->getBits(), Buffer::hex($block['bits'])->getInt());
        $this->assertEquals($header->getNonce(), $block['nonce']);
        $this->assertEquals($now, $block['time']);
        $this->assertEquals($base->getPrevBlock()->getHex(), $block['previousblockhash']);
        $this->assertEquals($base->getMerkleRoot()->getHex(), $block['merkleroot']);

        $bitcoind->destroy();
    }

    public function testCanGenerateAWitnessBlock()
    {
        $bitcoind = $this->rpcFactory->startBitcoind();
        $bitcoind->activateSoftforks();

        $tipsResult = $bitcoind->request('getchaintips');
        $this->assertEquals(null, $tipsResult['error']);

        $math = Bitcoin::getMath();
        $bestTip = null;
        foreach ($tipsResult['result'] as $tip) {
            if ("active" === $tip['status']) {
                $bestTip = $tip;
            }
        }

        $height = $bestTip['height'];

        $bestBlock = $bitcoind->request('getblock', [$bestTip['hash']])['result'];

        $random = new Random();
        $witnessRes = $random->bytes(32);
        $coinbaseWit = new ScriptWitness([
            $witnessRes,
        ]);

        $coinbaseSig = ScriptFactory::create()
            ->int($height)
            ->push(Buffer::hex("01"))
            ->getScript()
        ;

        $root = (new MerkleRoot($math, [Buffer::hex("", 32)]))
            ->calculateHash();

        $witCommit = Hash::sha256d(Buffertools::concat($root, $witnessRes));
        $privateKey = PrivateKeyFactory::create();

        $coinbasePubKey = ScriptFactory::scriptPubKey()->p2wkh($privateKey->getPubKeyHash());
        $witOutput = ScriptFactory::scriptPubKey()->witnessCoinbaseCommitment($witCommit);

        $cbBuilder = new TxBuilder();
        $cbBuilder->coinbase($coinbaseSig);
        $cbBuilder->output(5000000000, $coinbasePubKey);
        $cbBuilder->output(0, $witOutput);
        $cbBuilder->witnesses([
            $coinbaseWit
        ]);

        $coinbase = $cbBuilder->get();
        $merkleRoot = $coinbase->getTxId();

        $now = $bestBlock['time'] + 10;
        $bits = Buffer::hex($bestBlock['bits'])->getInt();
        $base = new BlockHeader(
            1,
            Buffer::hex($bestTip['hash']),
            $merkleRoot,
            $now,
            $bits,
            0
        );

        $data = substr($base->getBinary(), 0, -4);

        $params = new Regtest($math);
        $pow = new ProofOfWork($math, $params);

        for ($i = 0; $i < pow(2, 32); $i++) {
            $blob = $data . pack("V", $i);
            $hash = (new Buffer(hash('sha256', hash('sha256', $blob, true), true)))
                ->flip();

            try {
                $pow->check($hash, $bits);
                break;
            } catch (\Exception $e) {

            }
        }

        $header = new BlockHeader(
            $base->getVersion(),
            $base->getPrevBlock(),
            $base->getMerkleRoot(),
            $base->getTimestamp(),
            $bits,
            $i
        );

        $block = new Block($math, $header, [$coinbase]);
        $blockHex = $block->getHex();

        $result = $bitcoind->request("submitblock", [$blockHex]);
        $this->assertRpcSubmitBlock($result);

        $bitcoind->destroy();
    }
}
