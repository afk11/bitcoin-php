<?php

use BitWasp\Bitcoin\Address\AddressFactory;
use BitWasp\Bitcoin\Key\PrivateKeyFactory;
use BitWasp\Bitcoin\Script\ScriptFactory;
use BitWasp\Bitcoin\Transaction\Factory\Signer;
use BitWasp\Bitcoin\Transaction\Factory\TxBuilder;
use BitWasp\Bitcoin\Transaction\SignatureHash\SigHash;
use BitWasp\Bitcoin\Transaction\TransactionOutput;

require __DIR__ . "/../vendor/autoload.php";

$dest = PrivateKeyFactory::fromInt(999999999);
$sweepAddr = AddressFactory::fromKey($dest->getPublicKey());

$inputs = [
    [
        "txid" => "4141414141414141414141414141414141414141414141414141414141414141",
        "vout" => 0,
        "value" => 100000000,
        "scriptPubKey" => $sweepAddr->getScriptPubKey()->getHex(),
    ],
];

foreach ($inputs as &$input) {
    $input['txout'] = new TransactionOutput($input["value"], ScriptFactory::fromHex($input['scriptPubKey']));
}

$totalIn = array_sum(array_column($inputs, 'value'));

$dest = PrivateKeyFactory::fromInt(999999999);
$sweepAddr = AddressFactory::fromKey($dest->getPublicKey());

$unsigned = (new TxBuilder());
$unsigned->output($totalIn - 6000, $sweepAddr->getScriptPubKey());

$sighash = SigHash::ALL | 0x40;
foreach ($inputs as $input) {
    $unsigned->input($input['txid'], $input['vout']);
}

$signer = new Signer($unsigned->get());
$signer->redeemBitcoinGold(true);
foreach ($inputs as $i => $input) {
    $signer
        ->input($i, $input['txout'])
        ->sign($dest, $sighash);
}

$signed = $signer->get();

echo $signed->getHex().PHP_EOL;

