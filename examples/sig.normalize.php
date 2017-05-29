<?php

use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Crypto\EcAdapter\EcAdapterFactory;
use BitWasp\Bitcoin\Crypto\EcAdapter\EcSerializer;
use BitWasp\Bitcoin\Crypto\EcAdapter\Serializer\Signature\DerSignatureSerializerInterface;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Signature\TransactionSignature;
use BitWasp\Bitcoin\Transaction\SignatureHash\SigHash;
use BitWasp\Bitcoin\Transaction\TransactionFactory;
use BitWasp\Buffertools\Buffer;
use BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Signature\Signature;
use BitWasp\Buffertools\Buffertools;
use Mdanter\Ecc\EccFactory;

require __DIR__ . "/../vendor/autoload.php";

$ecc = EcAdapterFactory::getPhpEcc(Bitcoin::getMath(), Bitcoin::getGenerator());
EcAdapterFactory::setAdapter($ecc);

$sig = "3046022100eb9bb2e33ba279e8caeacb5101ae1e3bed77a6c88c771eaad4f2a1964d0c6d86022100ad4c6ff742db9949ff533dcd559b23694dd75a1a3c54b1b8962315065ac5377501";
$derSigSerializer = EcSerializer::getSerializer(DerSignatureSerializerInterface::class);
/** @var DerSignatureSerializerInterface $derSigSerializer */
$s = $derSigSerializer->parse(Buffer::hex($sig));

$gen = EccFactory::getSecgCurves()->generator256k1();
$c = $gen->getCurve();

$o = $gen->getOrder();

$max = gmp_div($o, gmp_init(2, 10));
echo gmp_strval($max, 10).PHP_EOL;
echo gmp_strval(gmp_sub($o, $s->getS())).PHP_EOL;

$r = new Signature($ecc, $s->getR(), gmp_sub($o, $s->getS()));
$txSig = new TransactionSignature($ecc, $r, SigHash::ALL);

echo $r->getHex().PHP_EOL;

//$tx = "0100000001d129bfacfb07e603b6d5dd160e2795686254684ff2991b9f7775e662c731cb0601000000fdfe000047304402204d140c640ccdb70aeac8d58de42e2880efe737d1f125adba861357fc4d613ec30220212fc2751a5c8e565bd96d9516cfda7a864788e891351c9bc86b15a502fddd3201493046022100eb9bb2e33ba279e8caeacb5101ae1e3bed77a6c88c771eaad4f2a1964d0c6d86022100ad4c6ff742db9949ff533dcd559b23694dd75a1a3c54b1b8962315065ac53775014c69522102951f8b7189e7096194cd2461b2d66b561d894ef2d36bd1bb0af86a2fa21fd3fb2102a3e85daaf647c8985727662b3a037c48db3cbe5236c32526fe4d506d9b55a34721032eda18a391eb3db1812810836668980469c02b858f5df4bcf15114b06c5b619453aeffffffff02a08601000000000017a91487148c0201c58fb7223b14c8b7d81443d37c418f8750eb0b040000000017a914a18ee4fb6a3e673b1a41f0710b0dd05ca6483d198700000000";
$tx = "0100000001d129bfacfb07e603b6d5dd160e2795686254684ff2991b9f7775e662c731cb0601000000b600493046022100eb9bb2e33ba279e8caeacb5101ae1e3bed77a6c88c771eaad4f2a1964d0c6d86022100ad4c6ff742db9949ff533dcd559b23694dd75a1a3c54b1b8962315065ac53775014c69522102951f8b7189e7096194cd2461b2d66b561d894ef2d36bd1bb0af86a2fa21fd3fb2102a3e85daaf647c8985727662b3a037c48db3cbe5236c32526fe4d506d9b55a34721032eda18a391eb3db1812810836668980469c02b858f5df4bcf15114b06c5b619453aeffffffff02a08601000000000017a91487148c0201c58fb7223b14c8b7d81443d37c418f8750eb0b040000000017a914a18ee4fb6a3e673b1a41f0710b0dd05ca6483d198700000000";
$tx = TransactionFactory::fromHex($tx);

$script = $tx->getInput(0)->getScript();
$parser = $script->getScriptParser();
$decoded = $parser->decode();
$values = [];
foreach ($decoded as $de) {
    $values[] = $de->getData();
}
$values[1] = $txSig->getBuffer();
$new = ScriptFactory::sequence($values);
$mutator = TransactionFactory::mutate($tx);
$mutator->inputsMutator()[0]->script($new);
$fixed = $mutator->done();
echo $fixed->getHex().PHP_EOL;
