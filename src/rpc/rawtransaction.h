// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_RAWTRANSACTION_H
#define BITCOIN_RPC_RAWTRANSACTION_H

#include <psbt.h>

class CBasicKeyStore;
struct CMutableTransaction;
class UniValue;

namespace interfaces {
class Chain;
} // namespace interfaces

/** Sign a transaction with the given keystore and previous transactions */
UniValue SignTransaction(interfaces::Chain& chain, CMutableTransaction& mtx, const UniValue& prevTxs, CBasicKeyStore *keystore, bool tempKeystore, const UniValue& hashType);

/** Create a transaction from univalue parameters. If (and only if)
    output_pubkeys_out is null, the "nonce hack" of storing Confidential
    Assets output pubkeys in nonces will be used. */
CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, const UniValue& rbf, std::map<CTxOut, PSBTOutput>* outputs_aux = nullptr, bool allow_peg_in = true, bool allow_issuance = true);

/** Create a peg-in input */
void CreatePegInInput(CMutableTransaction& mtx, uint32_t input_idx, CTransactionRef& tx_btc, CMerkleBlock& merkle_block, const std::set<CScript>& claim_scripts, const std::vector<unsigned char>& txData, const std::vector<unsigned char>& txOutProofData);
void CreatePegInInput(CMutableTransaction& mtx, uint32_t input_idx, Sidechain::Bitcoin::CTransactionRef& tx_btc, Sidechain::Bitcoin::CMerkleBlock& merkle_block, const std::set<CScript>& claim_scripts, const std::vector<unsigned char>& txData, const std::vector<unsigned char>& txOutProofData);

#endif // BITCOIN_RPC_RAWTRANSACTION_H
