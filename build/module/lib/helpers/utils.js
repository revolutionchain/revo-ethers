import { encode as encodeVaruint, encodingLength } from 'varuint-bitcoin';
import { defineReadOnly } from "@ethersproject/properties";
import { encode } from 'bip66';
import { OPS } from "./opcodes";
import { GLOBAL_VARS } from "./global-vars";
import { BufferCursor } from './buffer-cursor';
import { getAddress } from "@ethersproject/address";
//@ts-ignore
import { ecdsaSign, sign } from 'secp256k1';
let secp256k1Sign = ecdsaSign;
if (!ecdsaSign && sign) {
    // support version 3 secp256k1 library (used by metamask)
    //@ts-ignore
    secp256k1Sign = function (buffer, privateKey) {
        // v3 uses different version of Buffer, fake that these are compatabile
        //@ts-ignore
        buffer._isBuffer = true;
        //@ts-ignore
        privateKey._isBuffer = true;
        return sign(buffer, privateKey);
    };
}
import { encode as encodeCInt, decode as decodeCInt } from "bitcoinjs-lib/src/script_number";
import { sha256, ripemd160 } from "hash.js";
import { BigNumber } from "bignumber.js";
// 1 satoshi is e-8 so we need bignumber to not set an exponent for numbers greater than that
// since we use exponents to do multiplication
// BigNumber.config({ EXPONENTIAL_AT: 10 })
import { arrayify, hexlify } from "ethers/lib/utils";
import { BigNumber as BigNumberEthers } from "ethers";
import { decode } from "./hex-decoder";
import { computePublicKey } from "@ethersproject/signing-key";
// const toBuffer = require('typedarray-to-buffer')
const bitcoinjs = require("bitcoinjs-lib");
// metamask BigNumber uses a different version so the API doesn't match up
[
    "lessThanOrEqualTo",
    "greaterThan",
    "lessThan",
].forEach((methodName) => {
    // adds is ____ to prototype to reference existing method for api compat
    const is = "is" + methodName.charAt(0).toUpperCase() + methodName.slice(1);
    // @ts-ignore
    if (!BigNumber.prototype[is] && BigNumber.prototype[methodName]) {
        // @ts-ignore
        BigNumber.prototype[is] = BigNumber.prototype[methodName];
    }
});
function cloneBuffer(buffer) {
    let result = Buffer.alloc(buffer.length);
    buffer.copy(result);
    return result;
}
function cloneTx(tx) {
    let result = { version: tx.version, locktime: tx.locktime, vins: [], vouts: [] };
    for (let vin of tx.vins) {
        result.vins.push({
            txid: cloneBuffer(vin.txid),
            vout: vin.vout,
            hash: cloneBuffer(vin.hash),
            sequence: vin.sequence,
            script: cloneBuffer(vin.script),
            scriptSig: null
        });
    }
    for (let vout of tx.vouts) {
        result.vouts.push({
            script: cloneBuffer(vout.script),
            value: vout.value,
        });
    }
    return result;
}
// refer to https://en.bitcoin.it/wiki/Transaction#General_format_of_a_Bitcoin_transaction_.28inside_a_block.29
export function calcTxBytes(vins, vouts) {
    return GLOBAL_VARS.TX_OVERHEAD_NVERSION +
        encodingLength(vins.length) +
        vins
            .map(vin => (vin.scriptSig ? vin.scriptSig.byteLength : vin.script.byteLength))
            .reduce((sum, len) => sum + GLOBAL_VARS.TX_INPUT_OUTPOINT + encodingLength(len) + len + GLOBAL_VARS.TX_INPUT_NSEQUENCE, 0) +
        encodingLength(vouts.length) +
        vouts
            .map(vout => vout.script.byteLength)
            .reduce((sum, len) => sum + GLOBAL_VARS.TX_OUTPUT_NVALUE + encodingLength(len) + len, 0) +
        GLOBAL_VARS.TX_OVERHEAD_NLOCKTIME;
}
export function txToBuffer(tx) {
    let neededBytes = calcTxBytes(tx.vins, tx.vouts);
    let buffer = Buffer.alloc(neededBytes);
    let cursor = new BufferCursor(buffer);
    // version
    cursor.writeUInt32LE(tx.version);
    // vin length
    cursor.writeBytes(encodeVaruint(tx.vins.length));
    // vin
    for (let vin of tx.vins) {
        cursor.writeBytes(vin.hash);
        cursor.writeUInt32LE(vin.vout);
        if (vin.scriptSig !== null) {
            cursor.writeBytes(encodeVaruint(vin.scriptSig.length));
            cursor.writeBytes(vin.scriptSig);
        }
        else {
            cursor.writeBytes(encodeVaruint(vin.script.length));
            cursor.writeBytes(vin.script);
        }
        cursor.writeUInt32LE(vin.sequence);
    }
    // vout length
    cursor.writeBytes(encodeVaruint(tx.vouts.length));
    // vouts
    for (let vout of tx.vouts) {
        cursor.writeUInt64LE(vout.value);
        cursor.writeBytes(encodeVaruint(vout.script.length));
        cursor.writeBytes(vout.script);
    }
    // locktime
    cursor.writeUInt32LE(tx.locktime);
    return buffer;
}
// refer to: https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/script_signature.js
function toDER(x) {
    let i = 0;
    while (x[i] === 0)
        ++i;
    if (i === x.length)
        return Buffer.alloc(1);
    x = x.slice(i);
    if (x[0] & 0x80)
        return Buffer.concat([Buffer.alloc(1), x], 1 + x.length);
    return x;
}
// refer to: https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/script_signature.js
function encodeSig(signature, hashType) {
    const hashTypeMod = hashType & ~0x80;
    if (hashTypeMod <= 0 || hashTypeMod >= 4)
        throw new Error('Invalid hashType ' + hashType);
    const hashTypeBuffer = Buffer.from([hashType]);
    const bufferSignature = Buffer.from(signature);
    const r = toDER(bufferSignature.slice(0, 32));
    const s = toDER(bufferSignature.slice(32, 64));
    return Buffer.concat([encode(r, s), hashTypeBuffer]);
}
/////////////////////////////////////////
export async function signp2pkh(tx, vindex, privKey) {
    return await signp2pkhWith(tx, vindex, (hash) => {
        return secp256k1Sign(hash, arrayify(privKey));
    });
}
export async function signp2pkhWith(tx, vindex, signer) {
    let clone = cloneTx(tx);
    // clean up relevant script
    // TODO: Implement proper handling of OP_CODESEPARATOR, this was filtering 'ab' from the script entirely preventing pubkeyhash with ab addresses from generating proper tx
    // Since all scripts are generated locally in this library, temporarily not having this implemented is OK as no scripts will have this opcode
    // let filteredPrevOutScript = clone.vins[vindex].script.filter((op: any) => op !== OPS.OP_CODESEPARATOR);
    // Uint8Array issue here
    // clone.vins[vindex].script = toBuffer(filteredPrevOutScript);
    // zero out scripts of other inputs
    for (let i = 0; i < clone.vins.length; i++) {
        if (i === vindex)
            continue;
        clone.vins[i].script = Buffer.alloc(0);
    }
    // write to the buffer
    let buffer = txToBuffer(clone);
    // extend and append hash type
    buffer = Buffer.alloc(buffer.byteLength + 4, buffer);
    // append the hash type
    buffer.writeUInt32LE(GLOBAL_VARS.HASH_TYPE, buffer.byteLength - 4);
    // double-sha256
    let firstHash = sha256().update(buffer).digest();
    let secondHash = sha256().update(firstHash).digest();
    // sign on next tick so we don't block UI
    await new Promise((resolve) => setImmediate(resolve));
    // sign hash
    let sig = await signer(new Uint8Array(secondHash));
    // encode sig
    return encodeSig(sig.signature, GLOBAL_VARS.HASH_TYPE);
}
export function p2pkScriptSig(sig) {
    return bitcoinjs.script.compile([sig]);
}
export function p2pkScript(pubKey) {
    return bitcoinjs.script.compile([
        pubKey,
        OPS.OP_CHECKSIG
    ]);
}
export function p2pkhScriptSig(sig, pubkey) {
    return bitcoinjs.script.compile([sig, Buffer.from(pubkey, 'hex')]);
}
// Refer to:
// https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/p2pkh.js#L58
export function p2pkhScript(hash160PubKey) {
    return bitcoinjs.script.compile([
        OPS.OP_DUP,
        OPS.OP_HASH160,
        hash160PubKey,
        OPS.OP_EQUALVERIFY,
        OPS.OP_CHECKSIG
    ]);
}
const scriptMap = {
    p2pkh: p2pkhScript,
};
export function contractTxScript(contractAddress, gasLimit, gasPrice, encodedData) {
    // If contractAddress is missing, assume it's a create script, else assume its a call contract interaction
    if (contractAddress === "") {
        return bitcoinjs.script.compile([
            OPS.OP_4,
            encodeCInt(gasLimit),
            encodeCInt(gasPrice),
            Buffer.from(encodedData, "hex"),
            OPS.OP_CREATE,
        ]);
    }
    else {
        return bitcoinjs.script.compile([
            OPS.OP_4,
            encodeCInt(gasLimit),
            encodeCInt(gasPrice),
            Buffer.from(encodedData, "hex"),
            Buffer.from(contractAddress, "hex"),
            OPS.OP_CALL,
        ]);
    }
}
function reverse(src) {
    let buffer = Buffer.alloc(src.length);
    for (var i = 0, j = src.length - 1; i <= j; ++i, --j) {
        buffer[i] = src[j];
        buffer[j] = src[i];
    }
    return buffer;
}
export function generateContractAddress(txid) {
    let buffer = Buffer.alloc(32 + 4);
    let cursor = new BufferCursor(buffer);
    cursor.writeBytes(reverse(Buffer.from(txid, "hex")));
    // Assuming vout index is 0 as the transaction is serialized with that assumption.
    cursor.writeUInt32LE(0);
    let firstHash = sha256().update(buffer.toString("hex"), "hex").digest("hex");
    let secondHash = ripemd160().update(firstHash, "hex").digest("hex");
    return getAddress(secondHash).substring(2);
}
export async function addVins(outputs, spendableUtxos, neededAmount, needChange, gasPriceString, hash160PubKey, publicKey) {
    // minimum gas price is 40 satoshi
    // minimum sat/kb is 4000
    const gasPrice = BigNumberEthers.from(gasPriceString);
    const minimumSatoshiPerByte = 400;
    if (gasPrice.lt(BigNumberEthers.from(minimumSatoshiPerByte))) {
        throw new Error("Gas price lower than minimum relay fee: " + gasPriceString + " => " + gasPrice.toString() + " < " + minimumSatoshiPerByte);
    }
    let inputs = [];
    let amounts = [];
    let vinTypes = [];
    let change;
    let inputsAmount = BigNumberEthers.from(0);
    const neededAmountBN = BigNumberEthers.from(new BigNumber(qtumToSatoshi(neededAmount)).toString());
    let vbytes = BigNumberEthers.from(GLOBAL_VARS.TX_OVERHEAD_BASE);
    const spendVSizeLookupMap = {
        p2pk: BigNumberEthers.from(GLOBAL_VARS.TX_INPUT_BASE + GLOBAL_VARS.TX_INPUT_SCRIPTSIG_P2PK).toNumber(),
        p2pkh: BigNumberEthers.from(GLOBAL_VARS.TX_INPUT_BASE + GLOBAL_VARS.TX_INPUT_SCRIPTSIG_P2PKH).toNumber(),
    };
    const changeType = 'p2pkh';
    const outputVSizeLookupMap = {
        p2pkh: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2PKH).toNumber(),
        p2wpkh: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2WPKH).toNumber(),
        p2sh2of3: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2SH2OF3).toNumber(),
        p2wsh2of3: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2WSH2OF3).toNumber(),
        p2tr: BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2TR).toNumber(),
    };
    for (let i = 0; i < outputs.length; i++) {
        const output = outputs[i];
        let outputVSize = output;
        if (typeof output === "string") {
            if (!outputVSizeLookupMap.hasOwnProperty(output.toLowerCase())) {
                throw new Error("Unsupported output script type: " + output.toLowerCase());
            }
            else {
                // @ts-ignore
                outputVSize = outputVSizeLookupMap[output.toLowerCase()];
            }
        }
        else if (output.hasOwnProperty('script') && output.hasOwnProperty('value')) {
            // longer script sizes require up to 3 vbytes to encode
            const scriptEncodingLength = encodingLength(output.script.byteLength) - 1;
            outputVSize = BigNumberEthers.from(GLOBAL_VARS.TX_OUTPUT_BASE + scriptEncodingLength + output.script.byteLength).toNumber();
        }
        else {
            outputVSize = BigNumberEthers.from(outputVSize).toNumber();
        }
        vbytes = vbytes.add(outputVSize);
    }
    let needMoreInputs = true;
    let i = 0;
    for (i = 0; i < spendableUtxos.length; i++) {
        const spendableUtxo = spendableUtxos[i];
        // investigate issue where amount has no decimal point as calculation panics
        // @ts-ignore
        const amount = spendableUtxo.amountNumber;
        const utxoValue = parseFloat(shiftBy(amount, 8));
        // balance += utxoValue;
        let script = Buffer.from(spendableUtxo.scriptPubKey);
        // all scripts will be p2pkh for now
        const typ = spendableUtxo.type || '';
        if (typ.toLowerCase() === "p2pk") {
            script = p2pkScript(Buffer.from(publicKey.split("0x")[1], "hex"));
        }
        else if (typ.toLowerCase() === "p2pkh") {
            script = p2pkhScript(Buffer.from(hash160PubKey, "hex"));
        }
        if (!spendVSizeLookupMap.hasOwnProperty(typ.toLowerCase())) {
            throw new Error("Unsupported spendable script type: " + typ.toLowerCase());
        }
        inputs.push({
            txid: Buffer.from(spendableUtxo.txid, 'hex'),
            vout: spendableUtxo.vout,
            hash: reverse(Buffer.from(spendableUtxo.txid, 'hex')),
            sequence: 0xffffffff,
            script: script,
            scriptSig: null
        });
        vinTypes.push(typ);
        // @ts-ignore
        const outputVSize = spendVSizeLookupMap[typ.toLowerCase()];
        vbytes = vbytes.add(outputVSize);
        const fee = BigNumberEthers.from(vbytes).mul(gasPrice);
        inputsAmount = inputsAmount.add(utxoValue);
        amounts.push(utxoValue);
        if (neededAmountBN.eq(inputsAmount)) {
            if (i === spendableUtxos.length - 1) {
                // reached end
                // have exactly the needed amount
                // spending all utxo values
                // when caller computes change, it won't generate a change address
                needMoreInputs = false;
            }
            else {
                // not sending all
                // confirm that there is enough in inputs to cover network fees
                const neededAmountPlusFees = neededAmountBN.add(fee);
                const changeVBytes = outputVSizeLookupMap[changeType];
                const changeFee = BigNumberEthers.from(changeVBytes).mul(gasPrice).toNumber();
                const neededAmountPlusFeesAndChange = needChange ? neededAmountPlusFees.add(changeFee) : neededAmountPlusFees;
                if (inputsAmount.eq(neededAmountPlusFees)) {
                    // no change output required, matches exactly
                    needMoreInputs = false;
                }
                else if (inputsAmount.lt(neededAmountPlusFees)) {
                    // not enough to cover total to send + fees, we need another input
                }
                else if (inputsAmount.gte(neededAmountPlusFeesAndChange)) {
                    // has enough to cover with a change output
                    needMoreInputs = false;
                    vbytes = vbytes.add(changeVBytes);
                    change = inputsAmount.sub(neededAmountPlusFeesAndChange);
                }
                else {
                    // not enough to cover with a change output, we need another input
                }
            }
        }
        else if (neededAmountBN.lt(inputsAmount)) {
            // have enough, check that there is enough change to cover fees
            const totalNeededPlusFees = neededAmountBN.add(fee);
            const changeVBytes = outputVSizeLookupMap[changeType];
            const changeFee = BigNumberEthers.from(changeVBytes).mul(gasPrice).toNumber();
            const totalNeededPlusFeesAndChange = needChange ? totalNeededPlusFees.add(changeFee) : totalNeededPlusFees;
            if (inputsAmount.eq(totalNeededPlusFees)) {
                // no change output required, matches exactly
                needMoreInputs = false;
            }
            else if (inputsAmount.lt(totalNeededPlusFees)) {
                // not enough to cover total to send + fees, we need another input
            }
            else if (inputsAmount.gte(totalNeededPlusFeesAndChange)) {
                if (needChange) {
                    // has enough to cover with a change output
                    needMoreInputs = false;
                    vbytes = vbytes.add(changeVBytes);
                    change = inputsAmount.sub(totalNeededPlusFeesAndChange);
                    // throw new Error("Change output...2");
                }
                else {
                    // no change output requested
                    // bump the output by the change
                }
            }
            else {
                // not enough to cover with a change output, we need another input
            }
        }
        else {
            // neededAmountBN.gt(inputsAmount)
        }
        if (!needMoreInputs) {
            break;
        }
        if (i % 100 === 0) {
            // lots of UTXOs, don't block UI
            await new Promise((resolve) => setImmediate(resolve));
        }
    }
    if (needMoreInputs) {
        const missing = neededAmountBN.sub(inputsAmount).toNumber();
        throw new Error("Need " + missing + " more satoshi, we have " + inputsAmount.toString());
    }
    const fee = BigNumberEthers.from(vbytes).mul(gasPrice);
    const availableAmount = inputsAmount.sub(fee).toNumber();
    return [inputs, amounts, availableAmount, fee, change, changeType, vinTypes];
}
export function getMinNonDustValue(input, feePerByte) {
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // A typical spendable non-segwit txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a spendable txout less than
    // 182*dustRelayFee/1000 (in satoshis).
    // 546 satoshis at the default rate of 3000 sat/kB.
    // A typical spendable segwit txout is 31 bytes big, and will
    // need a CTxIn of at least 67 bytes to spend:
    // so dust is a spendable txout less than
    // 98*dustRelayFee/1000 (in satoshis).
    // 294 satoshis at the default rate of 3000 sat/kB.
    let size = 0;
    switch (input.type) {
        case "P2PKH":
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size = GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2PKH;
            size += 32 + 4 + 1 + 107 + 4; // 148
            break;
        // @ts-ignore
        case "P2PK":
            // TODO: Implement support
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size += 32 + 4 + 1 + 107 + 4; // 148
        // fallthrough, unsupported script type
        // @ts-ignore
        case "P2SH":
            // TODO: Implement support
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size += 32 + 4 + 1 + 107 + 4; // 148
        // fallthrough, unsupported script type
        // @ts-ignore
        case "P2WH":
            // TODO: Implement support
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size += 32 + 4 + 1 + (107 / GLOBAL_VARS.WITNESS_SCALE_FACTOR) + 4; // 68
        // fallthrough, unsupported script type
        default:
            throw new Error("Unsupported output script type: " + input.type);
    }
    return BigNumberEthers.from(feePerByte).mul(size).toNumber();
}
function shiftBy(amount, byPowerOfTen) {
    let amountString;
    if (typeof amount === "number") {
        amountString = `${amount}`;
    }
    else if (typeof amount === 'string') {
        amountString = amount;
    }
    else {
        amountString = BigNumberEthers.from(amount).toString();
    }
    const indexOfExponent = amountString.indexOf('e');
    if (indexOfExponent !== -1) {
        // very small or large number with lots of decimals with an exponent
        // we want to adjust the exponent
        const exponentString = amountString.substring(indexOfExponent + 1, amountString.length);
        // exponentString = '-10', '+10' etc
        const exponent = parseInt(exponentString);
        const shiftedExponent = exponent + byPowerOfTen;
        amountString = amountString.substring(0, indexOfExponent);
        byPowerOfTen = shiftedExponent;
    }
    return byPowerOfTen === 0 ? amountString : `${amountString}e${byPowerOfTen < 0 ? '' : '+'}${byPowerOfTen}`;
}
function satoshiToQtum(inSatoshi) {
    return shiftBy(inSatoshi || 0, -8);
}
function qtumToSatoshi(inQtum) {
    return shiftBy(inQtum || 0, 8);
}
function checkLostPrecisionInGasPrice(gasPrice) {
    const roundedGasPrice = new BigNumber(new BigNumber(satoshiToQtum(gasPrice)).toFixed(8)).toNumber();
    const originalGasPrice = new BigNumber(new BigNumber(satoshiToQtum(gasPrice)).toFixed()).toNumber();
    if (roundedGasPrice != originalGasPrice) {
        throw new Error("Precision lost in gasPrice: " + (originalGasPrice - roundedGasPrice));
    }
}
function getContractVout(gasPrice, gasLimit, data, address, value) {
    return {
        script: contractTxScript(address === "" ? "" : address.split("0x")[1], gasLimit, gasPrice, data.split("0x")[1]),
        value: new BigNumber(value).times(1e8).toNumber(),
    };
}
export function parseSignedTransaction(transaction) {
    if (transaction.startsWith("0x")) {
        transaction = transaction.substring(2);
    }
    let tx = {
        hash: "",
        to: "",
        from: "",
        nonce: 1,
        gasLimit: BigNumberEthers.from("0x3d090"),
        gasPrice: BigNumberEthers.from("0x28"),
        data: "",
        value: BigNumberEthers.from("0x0"),
        chainId: 81,
    };
    // Set hash (double sha256 of raw TX string)
    const sha256HashFirst = sha256().update(transaction, "hex").digest("hex");
    const sha256HashSecond = reverse(Buffer.from(sha256().update(sha256HashFirst, "hex").digest("hex"), "hex")).toString("hex");
    tx['hash'] = `0x${sha256HashSecond}`;
    const btcDecodedRawTx = decode(transaction);
    // Check if first OP code is OP_DUP -> assume p2pkh script
    if (bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[0] === OPS.OP_DUP) {
        tx['to'] = `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[2].toString("hex")}`;
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['value'] = BigNumberEthers.from(hexlify(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value));
    }
    // Check if first OP code is OP_4 and length is > 5 -> assume contract call
    else if (bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[0] === OPS.OP_4 && bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script).length > 5) {
        tx['to'] = `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[4].toString("hex")}`;
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['value'] = btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value > 0 ? BigNumberEthers.from(hexlify(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value)) : BigNumberEthers.from("0x0");
        tx['data'] = bitcoinjs.script.decompile(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].script)[3].toString("hex");
        tx['value'] = BigNumberEthers.from(hexlify(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value)).toNumber() === 0 ? BigNumberEthers.from("0x0") : BigNumberEthers.from(hexlify(btcDecodedRawTx.outs[GLOBAL_VARS.UTXO_VINDEX].value));
    }
    // assume contract creation
    else {
        tx['to'] = "";
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['gasLimit'] = BigNumberEthers.from(hexlify(decodeCInt(bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[1])));
        tx['gasPrice'] = BigNumberEthers.from(hexlify(decodeCInt(bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[2])));
        tx['data'] = bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[3].toString("hex");
    }
    return tx;
}
export function computeAddress(key, compressed) {
    const publicKey = computePublicKey(key, compressed);
    return computeAddressFromPublicKey(publicKey);
}
export function computeAddressFromPublicKey(publicKey) {
    if (!publicKey.startsWith("0x")) {
        publicKey = "0x" + publicKey;
    }
    const sha256Hash = sha256().update(publicKey.split("0x")[1], "hex").digest("hex");
    const prefixlessAddress = ripemd160().update(sha256Hash, "hex").digest("hex");
    return getAddress(`0x${prefixlessAddress}`);
}
export function configureQtumAddressGeneration(hdnode) {
    // QTUM computes address from the public key differently than ethereum, ethereum uses keccak256 while QTUM uses ripemd160(sha256(compressedPublicKey))
    // @ts-ignore
    defineReadOnly(hdnode, "qtumAddress", computeAddress(hdnode.publicKey, true));
    return hdnode;
}
export function checkTransactionType(tx) {
    if (!!tx.to === false && (!!tx.value === false || BigNumberEthers.from(tx.value).toNumber() === 0) && !!tx.data === true) {
        const needed = new BigNumber(satoshiToQtum(tx.gasPrice)).times(BigNumberEthers.from(tx.gasLimit).toNumber()).toFixed(8).toString();
        return { transactionType: GLOBAL_VARS.CONTRACT_CREATION, neededAmount: needed };
    }
    else if (!!tx.to === false && BigNumberEthers.from(tx.value).toNumber() > 0 && !!tx.data === true) {
        return { transactionType: GLOBAL_VARS.DEPLOY_ERROR, neededAmount: "0" };
    }
    else if (!!tx.to === true && !!tx.data === true) {
        const needed = !!tx.value === true ?
            new BigNumber(new BigNumber(satoshiToQtum(tx.gasPrice)).toFixed(8))
                .times(BigNumberEthers.from(tx.gasLimit).toNumber())
                .plus(satoshiToQtum(tx.value)).toFixed(8) :
            new BigNumber(new BigNumber(satoshiToQtum(tx.gasPrice)).toFixed(8))
                .times(BigNumberEthers.from(tx.gasLimit).toNumber()).toFixed(8);
        return { transactionType: GLOBAL_VARS.CONTRACT_CALL, neededAmount: needed };
    }
    else {
        const gas = new BigNumber(satoshiToQtum(tx.gasPrice)).times(BigNumberEthers.from(tx.gasLimit).toNumber());
        const needed = new BigNumber(satoshiToQtum(tx.value)).plus(gas).toFixed(8);
        return { transactionType: GLOBAL_VARS.P2PKH, neededAmount: needed };
    }
}
export async function serializeTransaction(utxos, fetchUtxos, neededAmount, tx, transactionType, privateKey, publicKey, filterDust) {
    const signer = (hash) => {
        return secp256k1Sign(hash, arrayify(privateKey));
    };
    return await serializeTransactionWith(utxos, fetchUtxos, neededAmount, tx, transactionType, signer, publicKey, filterDust);
}
const consumedUtxos = {};
function getUtxoPK(utxo) {
    if (!utxo.hasOwnProperty('txid') || !utxo.hasOwnProperty('vout')) {
        throw new Error('Unknown UTXO object type');
    }
    let txid = utxo.txid;
    if (typeof txid !== 'string') {
        if (txid.toString) {
            txid = txid.toString('hex');
        }
    }
    if (!txid.startsWith("0x")) {
        txid = "0x" + txid;
    }
    return txid + utxo.vout;
}
function isConsumedUtxo(utxo) {
    let id = getUtxoPK(utxo);
    return consumedUtxos[id];
}
function consumeUtxos(utxo) {
    const id = getUtxoPK(utxo);
    if (consumedUtxos[id]) {
        return;
    }
    consumedUtxos[id] = true;
    setTimeout(() => delete consumedUtxos[id], 45000);
}
export async function serializeTransactionWith(utxos, fetchUtxos, neededAmount, tx, transactionType, signer, publicKey, filterDust) {
    utxos = utxos.filter((utxo) => !isConsumedUtxo(utxo));
    // Building the QTUM tx that will eventually be serialized.
    let qtumTx = { version: 2, locktime: 0, vins: [], vouts: [] };
    // reduce precision in gasPrice to 1 satoshi
    tx.gasPrice = tx.gasPrice;
    // tx.gasPrice = dropPrecisionLessThanOneSatoshi(BigNumberEthers.from(tx.gasPrice).toString());
    // in ethereum, the way to send your entire balance is to solve a simple equation:
    // amount to send in wei = entire balance in wei - (gas limit * gas price)
    // in order to properly be able to spend all UTXOs we need compute
    // we need to filter outputs that are dust
    // something is considered dust
    checkLostPrecisionInGasPrice(BigNumberEthers.from(tx.gasPrice).toNumber());
    // 40 satoshi gasPrice => 400 satoshi/byte which is the minimum relay fee
    const satoshiPerByte = BigNumberEthers.from(tx.gasPrice).mul(10);
    const gas = BigNumberEthers.from(BigNumberEthers.from(tx.gasPrice).mul(BigNumberEthers.from(tx.gasLimit).toNumber()).toString());
    const nonContractTx = transactionType === GLOBAL_VARS.P2PKH;
    let neededAmountBN = BigNumberEthers.from(parseFloat(neededAmount + `e+8`));
    const neededAmountMinusGasBN = nonContractTx ? neededAmountBN.sub(gas) : neededAmountBN;
    const spendableUtxos = filterUtxos(utxos, satoshiPerByte, filterDust);
    const vouts = [];
    let needChange = true;
    if (transactionType === GLOBAL_VARS.CONTRACT_CREATION) {
        const contractCreateVout = getContractVout(BigNumberEthers.from(tx.gasPrice).toNumber(), BigNumberEthers.from(tx.gasLimit).toNumber(), 
        // @ts-ignore
        tx.data, "", 
        // OP_CREATE cannot send QTUM when deploying contract
        new BigNumber(BigNumberEthers.from("0x0").toNumber() + `e-8`).toFixed(8));
        vouts.push(contractCreateVout);
        qtumTx.vouts.push(contractCreateVout);
    }
    else if (transactionType === GLOBAL_VARS.CONTRACT_CALL) {
        const contractVoutValue = !!tx.value === true ?
            new BigNumber(satoshiToQtum(tx.value)).toNumber() :
            new BigNumber(BigNumberEthers.from("0x0").toNumber() + `e-8`).toFixed(8);
        const contractCallVout = getContractVout(BigNumberEthers.from(tx.gasPrice).toNumber(), BigNumberEthers.from(tx.gasLimit).toNumber(), 
        // @ts-ignore
        tx.data, tx.to, contractVoutValue);
        vouts.push(contractCallVout);
        qtumTx.vouts.push(contractCallVout);
    }
    else if (transactionType === GLOBAL_VARS.P2PKH) {
        // need to correct neededAmount
        // check if sending all
        let inputsAmount = BigNumberEthers.from(0);
        let i = 0;
        for (i = 0; i < spendableUtxos.length; i++) {
            const spendableUtxo = spendableUtxos[i];
            // investigate issue where amount has no decimal point as calculation panics
            // @ts-ignore
            const amount = spendableUtxo.amountNumber;
            const utxoValue = parseFloat(shiftBy(amount, 8));
            inputsAmount = inputsAmount.add(utxoValue);
        }
        needChange = !inputsAmount.eq(neededAmountBN);
        if (needChange) {
            neededAmountBN = neededAmountMinusGasBN;
            neededAmount = satoshiToQtum(neededAmountBN);
        }
        if (!neededAmountBN.eq(BigNumberEthers.from(0))) {
            // no need to generate an empty UTXO and clog the blockchain
            vouts.push('p2pkh');
        }
    }
    else if (transactionType === GLOBAL_VARS.DEPLOY_ERROR) {
        // user requested sending QTUM with OP_CREATE which will result in the QTUM being lost
        throw new Error("Cannot send QTUM to contract when deploying a contract");
    }
    else {
        throw new Error("Internal error: unknown transaction type: " + transactionType);
    }
    // @ts-ignore
    const hash160PubKey = tx.from.split("0x")[1];
    // @ts-ignore
    let vins, amounts, availableAmount, fee, changeAmount, changeType, vinTypes;
    try {
        // @ts-ignore
        [vins, amounts, availableAmount, fee, changeAmount, changeType, vinTypes] = await addVins(vouts, spendableUtxos, neededAmount, needChange, satoshiPerByte.toString(), hash160PubKey, publicKey);
    }
    catch (e) {
        if (!neededAmountBN.eq(neededAmountMinusGasBN) || ((typeof e.message) === 'string' && e.message.indexOf('more satoshi') === -1)) {
            throw e;
        }
        // needs more satoshi, provide more inputs
        // we probably need to filter dust here since the above non-filtered dust failed, there should be more inputs here
        const allSpendableUtxos = filterUtxos(await fetchUtxos(), satoshiPerByte, filterDust).filter((utxo) => !isConsumedUtxo(utxo));
        const neededAmountMinusGas = satoshiToQtum(neededAmountMinusGasBN);
        // @ts-ignore
        [vins, amounts, availableAmount, fee, changeAmount, changeType, vinTypes] = await addVins(vouts, allSpendableUtxos, neededAmountMinusGas, needChange, satoshiPerByte.toString(), hash160PubKey, publicKey);
    }
    if (vins.length === 0) {
        throw new Error("Couldn't find any vins");
    }
    qtumTx.vins = vins;
    vins.forEach(consumeUtxos);
    if (transactionType === GLOBAL_VARS.P2PKH) {
        // @ts-ignore
        const hash160Address = tx.to.split("0x")[1];
        let value;
        if (changeAmount) {
            // not using all
            value = new BigNumber(BigNumberEthers.from(tx.value).toNumber()).toNumber();
        }
        else {
            value = new BigNumber(availableAmount).toNumber();
        }
        if (value != 0) {
            const p2pkhVout = {
                script: p2pkhScript(Buffer.from(hash160Address, "hex")),
                value: value
            };
            qtumTx.vouts.push(p2pkhVout);
        }
    }
    // add change if needed
    if (changeAmount) {
        qtumTx.vouts.push({
            // @ts-ignore
            script: scriptMap[changeType](Buffer.from(hash160PubKey, "hex")),
            value: changeAmount.toNumber()
        });
    }
    // Sign necessary vins
    const updatedVins = [];
    for (let i = 0; i < qtumTx.vins.length; i++) {
        if (vinTypes[i].toLowerCase() === "p2pk") {
            updatedVins.push({ ...qtumTx.vins[i], ['scriptSig']: p2pkScriptSig(await signp2pkhWith(qtumTx, i, signer)) });
        }
        else {
            updatedVins.push({ ...qtumTx.vins[i], ['scriptSig']: p2pkhScriptSig(await signp2pkhWith(qtumTx, i, signer), publicKey.split("0x")[1]) });
        }
    }
    qtumTx.vins = updatedVins;
    // Build the serialized transaction string.
    return txToBuffer(qtumTx).toString('hex');
}
function filterUtxos(utxos, satoshiPerByte, filterDust) {
    for (let i = 0; i < utxos.length; i++) {
        // @ts-ignore
        utxos[i].amountNumber = parseFloat(parseFloat(utxos[i].amount).toFixed(8));
    }
    return utxos.filter((utxo) => {
        if (utxo.safe === undefined || !utxo.safe) {
            // unsafe to spend utxo
            return false;
        }
        if (filterDust) {
            // @ts-ignore
            const utxoValue = parseFloat(utxo.amountNumber + `e+8`);
            const minimumValueToNotBeDust = getMinNonDustValue(utxo, satoshiPerByte);
            return utxoValue >= minimumValueToNotBeDust;
        }
        return true;
    });
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXRpbHMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbGliL2hlbHBlcnMvdXRpbHMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLE1BQU0sSUFBSSxhQUFhLEVBQUUsY0FBYyxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFFMUUsT0FBTyxFQUFFLGNBQWMsRUFBRSxNQUFNLDJCQUEyQixDQUFDO0FBQzNELE9BQU8sRUFBRSxNQUFNLEVBQUUsTUFBTSxPQUFPLENBQUM7QUFDL0IsT0FBTyxFQUFFLEdBQUcsRUFBRSxNQUFNLFdBQVcsQ0FBQztBQUNoQyxPQUFPLEVBQUUsV0FBVyxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQzVDLE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUMvQyxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sd0JBQXdCLENBQUM7QUFFcEQsWUFBWTtBQUNaLE9BQU8sRUFBRSxTQUFTLEVBQUUsSUFBSSxFQUFFLE1BQU0sV0FBVyxDQUFDO0FBQzVDLElBQUksYUFBYSxHQUFHLFNBQVMsQ0FBQTtBQUM3QixJQUFJLENBQUMsU0FBUyxJQUFJLElBQUksRUFBRTtJQUNwQix5REFBeUQ7SUFDekQsWUFBWTtJQUNaLGFBQWEsR0FBRyxVQUFTLE1BQU0sRUFBRSxVQUFVO1FBQ3ZDLHVFQUF1RTtRQUN2RSxZQUFZO1FBQ1osTUFBTSxDQUFDLFNBQVMsR0FBRyxJQUFJLENBQUM7UUFDeEIsWUFBWTtRQUNaLFVBQVUsQ0FBQyxTQUFTLEdBQUcsSUFBSSxDQUFDO1FBQzVCLE9BQU8sSUFBSSxDQUFDLE1BQU0sRUFBRSxVQUFVLENBQUMsQ0FBQztJQUNwQyxDQUFDLENBQUE7Q0FDSjtBQUNELE9BQU8sRUFBRSxNQUFNLElBQUksVUFBVSxFQUFFLE1BQU0sSUFBSSxVQUFVLEVBQUUsTUFBTSxpQ0FBaUMsQ0FBQTtBQUM1RixPQUFPLEVBQUUsTUFBTSxFQUFFLFNBQVMsRUFB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