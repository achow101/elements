// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PSBT_H
#define BITCOIN_PSBT_H

#include <attributes.h>
#include <chainparams.h>
#include <node/transaction.h>
#include <primitives/transaction.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/bitcoin/merkleblock.h>
#include <merkleblock.h>
#include <pubkey.h>
#include <script/sign.h>

#include <boost/variant.hpp>

// Magic bytes
static constexpr uint8_t PSBT_MAGIC_BYTES[5] = {'p', 's', 'b', 't', 0xff};
static constexpr uint8_t PSBT_ELEMENTS_MAGIC_BYTES[5] = {'p', 's', 'e', 't', 0xff};

// Global types
static constexpr uint8_t PSBT_GLOBAL_UNSIGNED_TX = 0x00;
// Elements stuff
static constexpr uint8_t PSBT_ELEMENTS_GLOBAL_SCALAR = 0x00;

static constexpr uint8_t PSBT_PROPRIETARY = 0xFC;

// Input types
static constexpr uint8_t PSBT_IN_NON_WITNESS_UTXO = 0x00;
static constexpr uint8_t PSBT_IN_WITNESS_UTXO = 0x01;
static constexpr uint8_t PSBT_IN_PARTIAL_SIG = 0x02;
static constexpr uint8_t PSBT_IN_SIGHASH = 0x03;
static constexpr uint8_t PSBT_IN_REDEEMSCRIPT = 0x04;
static constexpr uint8_t PSBT_IN_WITNESSSCRIPT = 0x05;
static constexpr uint8_t PSBT_IN_BIP32_DERIVATION = 0x06;
static constexpr uint8_t PSBT_IN_SCRIPTSIG = 0x07;
static constexpr uint8_t PSBT_IN_SCRIPTWITNESS = 0x08;
// Elements stuff (private use area)
// Issuance things
static constexpr uint8_t PSBT_ELEMENTS_IN_ISSUANCE_VALUE = 0x00;
static constexpr uint8_t PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT = 0x01;
static constexpr uint8_t PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF = 0x02;
static constexpr uint8_t PSBT_ELEMENTS_IN_ISSUANCE_KEYS_RANGEPROOF = 0x03;
// Peg-in stuff
static constexpr uint8_t PSBT_ELEMENTS_IN_PEG_IN_TX = 0x04;
static constexpr uint8_t PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF = 0x05;
static constexpr uint8_t PSBT_ELEMENTS_IN_PEG_IN_GENESIS = 0x06;
static constexpr uint8_t PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT = 0x07;
static constexpr uint8_t PSBT_ELEMENTS_IN_PEG_IN_VALUE = 0x08;
static constexpr uint8_t PSBT_ELEMENTS_IN_PEG_IN_WITNESS = 0x09;
// More issuance things
static constexpr uint8_t PSBT_ELEMENTS_IN_ISSUANCE_KEYS = 0x0a;
static constexpr uint8_t PSBT_ELEMENTS_IN_ISSUANCE_KEYS_COMMITMENT = 0x0b;

// Output types
static constexpr uint8_t PSBT_OUT_REDEEMSCRIPT = 0x00;
static constexpr uint8_t PSBT_OUT_WITNESSSCRIPT = 0x01;
static constexpr uint8_t PSBT_OUT_BIP32_DERIVATION = 0x02;
// Elements stuff (private use area)
// Confidential Assets
static constexpr uint8_t PSBT_ELEMENTS_OUT_VALUE = 0x00;
static constexpr uint8_t PSBT_ELEMENTS_OUT_VALUE_COMMITMENT = 0x01;
static constexpr uint8_t PSBT_ELEMENTS_OUT_ASSET = 0x02;
static constexpr uint8_t PSBT_ELEMENTS_OUT_ASSET_COMMITMENT = 0x03;
static constexpr uint8_t PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF = 0x04;
static constexpr uint8_t PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF = 0x05;
static constexpr uint8_t PSBT_ELEMENTS_OUT_BLINDING_PUBKEY = 0x06;
static constexpr uint8_t PSBT_ELEMENTS_OUT_ECDH_PUBKEY = 0x07;
static constexpr uint8_t PSBT_ELEMENTS_OUT_BLINDER_INDEX = 0x08;

// Proprietary type identifer string
static const std::string PSBT_ELEMENTS_ID("pset");

// The separator is 0x00. Reading this in means that the unserializer can interpret it
// as a 0 length key which indicates that this is the separator. The separator has no value.
static constexpr uint8_t PSBT_SEPARATOR = 0x00;

/** A structure for PSBTs which contain per-input information */
struct PSBTInput
{
    CTransactionRef non_witness_utxo;
    CTxOut witness_utxo;
    CScript redeem_script;
    CScript witness_script;
    CScript final_script_sig;
    CScriptWitness final_script_witness;
    std::map<CPubKey, KeyOriginInfo> hd_keypaths;
    std::map<CKeyID, SigPair> partial_sigs;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown;
    int sighash_type = 0;

    boost::optional<CAmount> issuance_value;
    CConfidentialValue issuance_value_commitment;
    std::vector<unsigned char> issuance_rangeproof;
    std::vector<unsigned char> issuance_keys_rangeproof;
    boost::optional<CAmount> issuance_inflation_keys_amt;
    CConfidentialValue issuance_inflation_keys_commitment;

    boost::variant<boost::blank, CTransactionRef, Sidechain::Bitcoin::CTransactionRef> peg_in_tx;
    boost::variant<boost::blank, CMerkleBlock, Sidechain::Bitcoin::CMerkleBlock> txout_proof;
    CScript claim_script;
    uint256 genesis_hash;
    boost::optional<CAmount> peg_in_value;
    CScriptWitness peg_in_witness;

    bool IsNull() const;
    void FillSignatureData(SignatureData& sigdata) const;
    void FromSignatureData(const SignatureData& sigdata);
    bool Merge(const PSBTInput& input);
    bool IsSane() const;
    PSBTInput() {}

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        // Write the utxo
        // If there is a non-witness utxo, then don't add the witness one.
        if (non_witness_utxo) {
            SerializeToVector(s, PSBT_IN_NON_WITNESS_UTXO);
            OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() | SERIALIZE_TRANSACTION_NO_WITNESS);
            SerializeToVector(os, non_witness_utxo);
        } else if (!witness_utxo.IsNull()) {
            SerializeToVector(s, PSBT_IN_WITNESS_UTXO);
            SerializeToVector(s, witness_utxo);
        }

        if (final_script_sig.empty() && final_script_witness.IsNull()) {
            // Write any partial signatures
            for (auto sig_pair : partial_sigs) {
                SerializeToVector(s, PSBT_IN_PARTIAL_SIG, MakeSpan(sig_pair.second.first));
                s << sig_pair.second.second;
            }

            // Write the sighash type
            if (sighash_type > 0) {
                SerializeToVector(s, PSBT_IN_SIGHASH);
                SerializeToVector(s, sighash_type);
            }

            // Write the redeem script
            if (!redeem_script.empty()) {
                SerializeToVector(s, PSBT_IN_REDEEMSCRIPT);
                s << redeem_script;
            }

            // Write the witness script
            if (!witness_script.empty()) {
                SerializeToVector(s, PSBT_IN_WITNESSSCRIPT);
                s << witness_script;
            }

            // Write any hd keypaths
            SerializeHDKeypaths(s, hd_keypaths, PSBT_IN_BIP32_DERIVATION);
        }

        // Write script sig
        if (!final_script_sig.empty()) {
            SerializeToVector(s, PSBT_IN_SCRIPTSIG);
            s << final_script_sig;
        }
        // write script witness
        if (!final_script_witness.IsNull()) {
            SerializeToVector(s, PSBT_IN_SCRIPTWITNESS);
            SerializeToVector(s, final_script_witness.stack);
        }

        // Issuance value
        // We shouldn't have both the value and value commitment, but maybe we do, so ignore the explicit value
        if (!issuance_value_commitment.IsNull()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT);
            SerializeToVector(s, issuance_value_commitment);
        } else if (issuance_value) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_ISSUANCE_VALUE);
            SerializeToVector(s, *issuance_value);
        }

        // Issuance rangeproof
        if (!issuance_rangeproof.empty()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF);
            s << issuance_rangeproof;
        }

        // Issuance inflation keys rangeproof
        if (!issuance_keys_rangeproof.empty()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_ISSUANCE_KEYS_RANGEPROOF);
            s << issuance_keys_rangeproof;
        }

        // Write peg-in data
        if (Params().GetConsensus().ParentChainHasPow()) {
            if (peg_in_tx.which() > 0) {
                const Sidechain::Bitcoin::CTransactionRef& btc_peg_in_tx = boost::get<Sidechain::Bitcoin::CTransactionRef>(peg_in_tx);
                if (btc_peg_in_tx) {
                    SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_PEG_IN_TX);
                    OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() | SERIALIZE_TRANSACTION_NO_WITNESS);
                    SerializeToVector(os, btc_peg_in_tx);
                }
            }
            if (txout_proof.which() > 0) {
                const Sidechain::Bitcoin::CMerkleBlock& btc_txout_proof = boost::get<Sidechain::Bitcoin::CMerkleBlock>(txout_proof);
                if (!btc_txout_proof.header.IsNull()) {
                    SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF);
                    SerializeToVector(s, btc_txout_proof);
                }
            }
        } else {
            if (peg_in_tx.which() > 0) {
                const CTransactionRef& elem_peg_in_tx = boost::get<CTransactionRef>(peg_in_tx);
                if (elem_peg_in_tx) {
                    SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_PEG_IN_TX);
                    OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() | SERIALIZE_TRANSACTION_NO_WITNESS);
                    SerializeToVector(os, elem_peg_in_tx);
                }
            }
            if (txout_proof.which() > 0) {
                const CMerkleBlock& elem_txout_proof = boost::get<CMerkleBlock>(txout_proof);
                if (!elem_txout_proof.header.IsNull()) {
                    SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF);
                    SerializeToVector(s, elem_txout_proof);
                }
            }
        }
        if (!claim_script.empty()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT);
            s << claim_script;
        }
        if (!genesis_hash.IsNull()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_PEG_IN_GENESIS);
            SerializeToVector(s, genesis_hash);
        }

        // Peg-in value
        if (peg_in_value) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_PEG_IN_VALUE);
            SerializeToVector(s, *peg_in_value);
        }

        // Peg-in witness
        if (!peg_in_witness.IsNull()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_PEG_IN_WITNESS);
            SerializeToVector(s, peg_in_witness.stack);
        }

        // Issuance inflation keys value
        if (issuance_inflation_keys_amt) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_ISSUANCE_KEYS);
            SerializeToVector(s, *issuance_inflation_keys_amt);
        }

        // Issuance inflation keys value
        if (!issuance_inflation_keys_commitment.IsNull()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_IN_ISSUANCE_KEYS_COMMITMENT);
            SerializeToVector(s, issuance_inflation_keys_commitment);
        }

        // Write unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        s << PSBT_SEPARATOR;
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Read loop
        bool found_sep = false;
        while(!s.empty()) {
            // Read
            std::vector<unsigned char> key;
            s >> key;

            // the key is empty if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key.empty()) {
                found_sep = true;
                break;
            }

            // First byte of key is the type
            unsigned char type = key[0];

            // Do stuff based on type
            switch(type) {
                case PSBT_IN_NON_WITNESS_UTXO:
                {
                    if (non_witness_utxo) {
                        throw std::ios_base::failure("Duplicate Key, input non-witness utxo already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Non-witness utxo key is more than one byte type");
                    }
                    // Set the stream to unserialize with witness since this is always a valid network transaction
                    OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() & ~SERIALIZE_TRANSACTION_NO_WITNESS);
                    UnserializeFromVector(os, non_witness_utxo);
                    break;
                }
                case PSBT_IN_WITNESS_UTXO:
                    if (!witness_utxo.IsNull()) {
                        throw std::ios_base::failure("Duplicate Key, input witness utxo already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Witness utxo key is more than one byte type");
                    }
                    UnserializeFromVector(s, witness_utxo);
                    break;
                case PSBT_IN_PARTIAL_SIG:
                {
                    // Make sure that the key is the size of pubkey + 1
                    if (key.size() != CPubKey::PUBLIC_KEY_SIZE + 1 && key.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type partial signature pubkey");
                    }
                    // Read in the pubkey from key
                    CPubKey pubkey(key.begin() + 1, key.end());
                    if (!pubkey.IsFullyValid()) {
                       throw std::ios_base::failure("Invalid pubkey");
                    }
                    if (partial_sigs.count(pubkey.GetID()) > 0) {
                        throw std::ios_base::failure("Duplicate Key, input partial signature for pubkey already provided");
                    }

                    // Read in the signature from value
                    std::vector<unsigned char> sig;
                    s >> sig;

                    // Add to list
                    partial_sigs.emplace(pubkey.GetID(), SigPair(pubkey, std::move(sig)));
                    break;
                }
                case PSBT_IN_SIGHASH:
                    if (sighash_type > 0) {
                        throw std::ios_base::failure("Duplicate Key, input sighash type already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Sighash type key is more than one byte type");
                    }
                    UnserializeFromVector(s, sighash_type);
                    break;
                case PSBT_IN_REDEEMSCRIPT:
                {
                    if (!redeem_script.empty()) {
                        throw std::ios_base::failure("Duplicate Key, input redeemScript already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Input redeemScript key is more than one byte type");
                    }
                    s >> redeem_script;
                    break;
                }
                case PSBT_IN_WITNESSSCRIPT:
                {
                    if (!witness_script.empty()) {
                        throw std::ios_base::failure("Duplicate Key, input witnessScript already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Input witnessScript key is more than one byte type");
                    }
                    s >> witness_script;
                    break;
                }
                case PSBT_IN_BIP32_DERIVATION:
                {
                    DeserializeHDKeypaths(s, key, hd_keypaths);
                    break;
                }
                case PSBT_IN_SCRIPTSIG:
                {
                    if (!final_script_sig.empty()) {
                        throw std::ios_base::failure("Duplicate Key, input final scriptSig already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Final scriptSig key is more than one byte type");
                    }
                    s >> final_script_sig;
                    break;
                }
                case PSBT_IN_SCRIPTWITNESS:
                {
                    if (!final_script_witness.IsNull()) {
                        throw std::ios_base::failure("Duplicate Key, input final scriptWitness already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Final scriptWitness key is more than one byte type");
                    }
                    UnserializeFromVector(s, final_script_witness.stack);
                    break;
                }
                case PSBT_PROPRIETARY:
                {
                    VectorReader skey(s.GetType(), s.GetVersion(), key, 1);
                    std::string identifier;
                    skey >> identifier;

                    if (identifier != PSBT_ELEMENTS_ID) {
                        // This is not our proprietary type, skip it
                        continue;
                    }

                    size_t subkey_len = skey.size();
                    uint64_t subtype = ReadCompactSize(skey);

                    switch(subtype) {
                        case PSBT_ELEMENTS_IN_ISSUANCE_VALUE:
                        {
                            if (issuance_value != boost::none) {
                                throw std::ios_base::failure("Duplicate Key, input issuance value already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Input issuance value is more than one byte type");
                            }
                            CAmount amt;
                            UnserializeFromVector(s, amt);
                            issuance_value = amt;
                            break;
                        }
                        case PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT:
                        {
                            if (!issuance_value_commitment.IsNull()) {
                                throw std::ios_base::failure("Duplicate Key, input issuance value commitment already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Input issuance value commitment key is more than one byte type");
                            }
                            UnserializeFromVector(s, issuance_value_commitment);
                            break;
                        }
                        case PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF:
                        {
                            if (!issuance_rangeproof.empty()) {
                                throw std::ios_base::failure("Duplicate Key, input issuance value rangeproof already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Input issuance value rangeproof key is more than one byte type");
                            }
                            s >> issuance_rangeproof;
                            break;
                        }
                        case PSBT_ELEMENTS_IN_ISSUANCE_KEYS_RANGEPROOF:
                        {
                            if (!issuance_keys_rangeproof.empty()) {
                                throw std::ios_base::failure("Duplicate Key, input issuance inflation keys rangeproof already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Input issuance inflation keys rangeproof key is more than one byte type");
                            }
                            s >> issuance_keys_rangeproof;
                            break;
                        }
                        case PSBT_ELEMENTS_IN_PEG_IN_TX:
                        {
                            if (peg_in_tx.which() != 0) {
                                throw std::ios_base::failure("Duplicate Key, peg-in tx already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Peg-in tx key is more than one byte type");
                            }
                            if (Params().GetConsensus().ParentChainHasPow()) {
                                Sidechain::Bitcoin::CTransactionRef tx_btc;
                                OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion());
                                UnserializeFromVector(os, tx_btc);
                                peg_in_tx = tx_btc;
                            } else {
                                CTransactionRef tx_btc;
                                OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion());
                                UnserializeFromVector(os, tx_btc);
                                peg_in_tx = tx_btc;
                            }
                            break;
                        }
                        case PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF:
                        {
                            if (txout_proof.which() != 0) {
                                throw std::ios_base::failure("Duplicate Key, peg-in txout proof already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Peg-in txout proof key is more than one byte type");
                            }
                            if (Params().GetConsensus().ParentChainHasPow()) {
                                Sidechain::Bitcoin::CMerkleBlock tx_proof;
                                UnserializeFromVector(s, tx_proof);
                                txout_proof = tx_proof;
                            } else {
                                CMerkleBlock tx_proof;
                                UnserializeFromVector(s, tx_proof);
                                txout_proof = tx_proof;
                            }
                            break;
                        }
                        case PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT:
                        {
                            if (!claim_script.empty()) {
                                throw std::ios_base::failure("Duplicate Key, peg-in claim script already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Peg-in claim script key is more than one byte type");
                            }
                            s >> claim_script;
                            break;
                        }
                        case PSBT_ELEMENTS_IN_PEG_IN_GENESIS:
                        {
                            if (!genesis_hash.IsNull()) {
                                throw std::ios_base::failure("Duplicate Key, peg-in genesis hash already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Peg-in genesis hash is more than one byte type");
                            }
                            UnserializeFromVector(s, genesis_hash);
                            break;
                        }
                        case PSBT_ELEMENTS_IN_PEG_IN_VALUE:
                        {
                            if (peg_in_value != boost::none) {
                                throw std::ios_base::failure("Duplicate Key, input issuance value already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Input issuance value is more than one byte type");
                            }
                            CAmount amt;
                            UnserializeFromVector(s, amt);
                            peg_in_value = amt;
                            break;
                        }
                        case PSBT_ELEMENTS_IN_PEG_IN_WITNESS:
                        {
                            if (!final_script_witness.IsNull()) {
                                throw std::ios_base::failure("Duplicate Key, input peg-in witness already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Input peg-in witness key is more than one byte type");
                            }
                            UnserializeFromVector(s, peg_in_witness.stack);
                            break;
                        }
                        case PSBT_ELEMENTS_IN_ISSUANCE_KEYS:
                        {
                            if (issuance_inflation_keys_amt != boost::none) {
                                throw std::ios_base::failure("Duplicate Key, input issuance inflation keys already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Input issuance inflation keys is more than one byte type");
                            }
                            CAmount amt;
                            UnserializeFromVector(s, amt);
                            issuance_inflation_keys_amt = amt;
                            break;
                        }
                        case PSBT_ELEMENTS_IN_ISSUANCE_KEYS_COMMITMENT:
                        {
                            if (!issuance_inflation_keys_commitment.IsNull()) {
                                throw std::ios_base::failure("Duplicate Key, input issuance inflation keys commitment already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Input issuance inflation keys commitment key is more than one byte type");
                            }
                            UnserializeFromVector(s, issuance_inflation_keys_commitment);
                            break;
                        }
                    }
                    break;
                }
                // Unknown stuff
                default:
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    std::vector<unsigned char> val_bytes;
                    s >> val_bytes;
                    unknown.emplace(std::move(key), std::move(val_bytes));
                    break;
            }
        }

        if (!found_sep) {
            throw std::ios_base::failure("Separator is missing at the end of an input map");
        }
    }

    template <typename Stream>
    PSBTInput(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

/** A structure for PSBTs which contains per output information */
struct PSBTOutput
{
    CScript redeem_script;
    CScript witness_script;
    std::map<CPubKey, KeyOriginInfo> hd_keypaths;

    CPubKey blinding_pubkey;
    boost::optional<CAmount> value;
    CConfidentialValue value_commitment;
    uint256 asset;
    CConfidentialAsset asset_commitment;
    std::vector<unsigned char> range_proof;
    std::vector<unsigned char> surjection_proof;
    CPubKey ecdh_key;

    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown;

    boost::optional<uint32_t> blinder_index;

    bool IsNull() const;
    void FillSignatureData(SignatureData& sigdata) const;
    void FromSignatureData(const SignatureData& sigdata);
    bool Merge(const PSBTOutput& output);
    bool IsSane() const;
    bool IsBlinded() const; //! This output has a blinding pubkey and is or will be blinded.
    bool IsPartiallyBlinded() const; //! This output has some blinding information. This is not a good state to be in.
    bool IsFullyBlinded() const; //! This output has all of the blinding information and is actually blinded.
    PSBTOutput() {}

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        // Write the redeem script
        if (!redeem_script.empty()) {
            SerializeToVector(s, PSBT_OUT_REDEEMSCRIPT);
            s << redeem_script;
        }

        // Write the witness script
        if (!witness_script.empty()) {
            SerializeToVector(s, PSBT_OUT_WITNESSSCRIPT);
            s << witness_script;
        }

        // Write any hd keypaths
        SerializeHDKeypaths(s, hd_keypaths, PSBT_OUT_BIP32_DERIVATION);

        // Write the elements stuff
        // Value
        // We shouldn't have both value and value commitment, but if we do, write only the value commmitment
        if (!value_commitment.IsNull()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_OUT_VALUE_COMMITMENT);
            SerializeToVector(s, value_commitment);
        } else if (value) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_OUT_VALUE);
            SerializeToVector(s, *value);
        }

        // Asset
        // We shouldn't have both asset and asset commitment, but if we do, write only the asset commitment
        if (!asset_commitment.IsNull()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_OUT_ASSET_COMMITMENT);
            SerializeToVector(s, asset_commitment);
        } else if (!asset.IsNull()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_OUT_ASSET);
            SerializeToVector(s, asset);
        }

        // Value rangeproof
        if (!range_proof.empty()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF);
            s << range_proof;
        }

        // Asset surjection proof
        if (!surjection_proof.empty()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF);
            s << surjection_proof;
        }

        // Blinding pubkey
        if (blinding_pubkey.IsValid()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_OUT_BLINDING_PUBKEY);
            s << blinding_pubkey;
        }

        // ECDH pubkey
        if (ecdh_key.IsValid()) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_OUT_ECDH_PUBKEY);
            s << ecdh_key;
        }

        // Blinder index
        if (blinder_index != boost::none) {
            SerializeToVector(s, PSBT_PROPRIETARY, PSBT_ELEMENTS_ID, PSBT_ELEMENTS_OUT_BLINDER_INDEX);
            SerializeToVector(s, *blinder_index);
        }

        // Write unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        s << PSBT_SEPARATOR;
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Read loop
        bool found_sep = false;
        while(!s.empty()) {
            // Read
            std::vector<unsigned char> key;
            s >> key;

            // the key is empty if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key.empty()) {
                found_sep = true;
                break;
            }

            // First byte of key is the type
            unsigned char type = key[0];

            // Do stuff based on type
            switch(type) {
                case PSBT_OUT_REDEEMSCRIPT:
                {
                    if (!redeem_script.empty()) {
                        throw std::ios_base::failure("Duplicate Key, output redeemScript already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Output redeemScript key is more than one byte type");
                    }
                    s >> redeem_script;
                    break;
                }
                case PSBT_OUT_WITNESSSCRIPT:
                {
                    if (!witness_script.empty()) {
                        throw std::ios_base::failure("Duplicate Key, output witnessScript already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Output witnessScript key is more than one byte type");
                    }
                    s >> witness_script;
                    break;
                }
                case PSBT_OUT_BIP32_DERIVATION:
                {
                    DeserializeHDKeypaths(s, key, hd_keypaths);
                    break;
                }
                case PSBT_PROPRIETARY:
                {
                    VectorReader skey(s.GetType(), s.GetVersion(), key, 1);
                    std::string identifier;
                    skey >> identifier;

                    if (identifier != PSBT_ELEMENTS_ID) {
                        // This is not our proprietary type, skip it
                        continue;
                    }

                    size_t subkey_len = skey.size();
                    uint64_t subtype = ReadCompactSize(skey);

                    switch(subtype) {
                        case PSBT_ELEMENTS_OUT_VALUE:
                        {
                            if (value != boost::none) {
                                throw std::ios_base::failure("Duplicate key, output value already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Output value key is more than one byte type");
                            }
                            CAmount amt;
                            UnserializeFromVector(s, amt);
                            value = amt;
                            break;
                        }
                        case PSBT_ELEMENTS_OUT_VALUE_COMMITMENT:
                        {
                            if (!value_commitment.IsNull()) {
                                throw std::ios_base::failure("Duplicate Key, output value_commitment already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Output value_commitment key is more than one byte type");
                            }
                            UnserializeFromVector(s, value_commitment);
                            break;
                        }
                        case PSBT_ELEMENTS_OUT_ASSET:
                        {
                            if (!asset.IsNull()) {
                                throw std::ios_base::failure("Duplicate Key, output asset already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Output asset key is more than one byte type");
                            }
                            UnserializeFromVector(s, asset);
                            break;
                        }
                        case PSBT_ELEMENTS_OUT_ASSET_COMMITMENT:
                        {
                            if (!asset_commitment.IsNull()) {
                                throw std::ios_base::failure("Duplicate Key, output asset_commitment already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Output asset_commitment key is more than one byte type");
                            }
                            UnserializeFromVector(s, asset_commitment);
                            break;
                        }
                        case PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF:
                        {
                            if (!range_proof.empty()) {
                                throw std::ios_base::failure("Duplicate Key, output range_proof already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Output range_proof key is more than one byte type");
                            }
                            s >> range_proof;
                            break;
                        }
                        case PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF:
                        {
                            if (!surjection_proof.empty()) {
                                throw std::ios_base::failure("Duplicate Key, output surjection_proof already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Output surjection_proof key is more than one byte type");
                            }
                            s >> surjection_proof;
                            break;
                        }
                        case PSBT_ELEMENTS_OUT_BLINDING_PUBKEY:
                        {
                            if (blinding_pubkey.IsValid()) {
                                throw std::ios_base::failure("Duplicate Key, output blinding_pubkey already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Output blinding_pubkey key is more than one byte type");
                            }
                            s >> blinding_pubkey;
                            break;
                        }
                        case PSBT_ELEMENTS_OUT_ECDH_PUBKEY:
                        {
                            if (ecdh_key.IsValid()) {
                                throw std::ios_base::failure("Duplicate Key, output ecdh_pubkey already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Output ecdh_pubkey key is more than one byte type");
                            }
                            s >> ecdh_key;
                            break;
                        }
                        case PSBT_ELEMENTS_OUT_BLINDER_INDEX:
                        {
                            if (blinder_index != boost::none) {
                                throw std::ios_base::failure("Duplicate Key, output blinder_index already provided");
                            } else if (subkey_len != 1) {
                                throw std::ios_base::failure("Output blinder_index key is more than one byte type");
                            }
                            uint32_t i;
                            UnserializeFromVector(s, i);
                            blinder_index = i;
                            break;
                        }
                    }
                    break;
                }
                // Unknown stuff
                default: {
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    std::vector<unsigned char> val_bytes;
                    s >> val_bytes;
                    unknown.emplace(std::move(key), std::move(val_bytes));
                    break;
                }
            }
        }

        if (!found_sep) {
            throw std::ios_base::failure("Separator is missing at the end of an output map");
        }
    }

    template <typename Stream>
    PSBTOutput(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

/** A version of CTransaction with the PSBT format*/
struct PartiallySignedTransaction
{
    boost::optional<CMutableTransaction> tx;
    std::vector<PSBTInput> inputs;
    std::vector<PSBTOutput> outputs;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown;
    std::set<uint256> scalar_offsets;

    bool IsNull() const;

    /** Merge psbt into this. The two psbts must have the same underlying CTransaction (i.e. the
      * same actual Bitcoin transaction.) Returns true if the merge succeeded, false otherwise. */
    NODISCARD bool Merge(const PartiallySignedTransaction& psbt);
    bool IsSane() const;
    bool AddInput(const CTxIn& txin, PSBTInput& psbtin);
    bool AddOutput(const CTxOut& txout, const PSBTOutput& psbtout);
    PartiallySignedTransaction() {}
    PartiallySignedTransaction(const PartiallySignedTransaction& psbt_in) : tx(psbt_in.tx), inputs(psbt_in.inputs), outputs(psbt_in.outputs), unknown(psbt_in.unknown) {}
    explicit PartiallySignedTransaction(const CMutableTransaction& tx);
    /**
     * Finds the UTXO for a given input index
     *
     * @param[out] utxo The UTXO of the input if found
     * @param[in] input_index Index of the input to retrieve the UTXO of
     * @return Whether the UTXO for the specified input was found
     */
    bool GetInputUTXO(CTxOut& utxo, int input_index) const;
    /** Returns whether the PSBT has outputs that require blinding. Said outputs may already be blinded */
    bool IsBlinded() const;
    /** Returns whether the PSBT is fully blinded. Fully blinded means that no blinding is required, so this includes PSBTs that do not require blinding at all */
    bool IsFullyBlinded() const;

    template <typename Stream>
    inline void Serialize(Stream& s) const {

        // magic bytes
        if (g_con_elementsmode) {
            s << PSBT_ELEMENTS_MAGIC_BYTES;
        } else {
            s << PSBT_MAGIC_BYTES;
        }

        // unsigned tx flag
        SerializeToVector(s, PSBT_GLOBAL_UNSIGNED_TX);

        // Write serialized tx to a stream
        OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() | SERIALIZE_TRANSACTION_NO_WITNESS);
        SerializeToVector(os, *tx);

        // Write the unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        // Separator
        s << PSBT_SEPARATOR;

        // Write inputs
        for (const PSBTInput& input : inputs) {
            s << input;
        }
        // Write outputs
        for (const PSBTOutput& output : outputs) {
            s << output;
        }
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Read the magic bytes
        uint8_t magic[5];
        s >> magic;
        if (g_con_elementsmode) {
            if (!std::equal(magic, magic + 5, PSBT_ELEMENTS_MAGIC_BYTES)) {
                throw std::ios_base::failure("Invalid PSBT magic bytes");
            }
        } else  {
            if (!std::equal(magic, magic + 5, PSBT_MAGIC_BYTES)) {
                throw std::ios_base::failure("Invalid PSBT magic bytes");
            }
        }

        // Read global data
        bool found_sep = false;
        while(!s.empty()) {
            // Read
            std::vector<unsigned char> key;
            s >> key;

            // the key is empty if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key.empty()) {
                found_sep = true;
                break;
            }

            // First byte of key is the type
            unsigned char type = key[0];

            // Do stuff based on type
            switch(type) {
                case PSBT_GLOBAL_UNSIGNED_TX:
                {
                    if (tx) {
                        throw std::ios_base::failure("Duplicate Key, unsigned tx already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global unsigned tx key is more than one byte type");
                    }
                    CMutableTransaction mtx;
                    // Set the stream to serialize with non-witness since this should always be non-witness
                    OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() | SERIALIZE_TRANSACTION_NO_WITNESS);
                    UnserializeFromVector(os, mtx);
                    tx = std::move(mtx);
                    // Make sure that all scriptSigs and scriptWitnesses are empty
                    tx->witness.vtxinwit.resize(tx->vin.size());
                    for (unsigned int i = 0; i < tx->vin.size(); i++) {
                        const CTxIn& txin = tx->vin[i];
                        if (!txin.scriptSig.empty() || !tx->witness.vtxinwit[i].scriptWitness.IsNull()) {
                            throw std::ios_base::failure("Unsigned tx does not have empty scriptSigs and scriptWitnesses.");
                        }
                    }
                    break;
                }
                case PSBT_PROPRIETARY:
                {
                    VectorReader skey(s.GetType(), s.GetVersion(), key, 1);
                    std::string identifier;
                    skey >> identifier;

                    if (identifier != PSBT_ELEMENTS_ID) {
                        // This is not our proprietary type, skip it
                        continue;
                    }

                    size_t subkey_len = skey.size();
                    uint64_t subtype = ReadCompactSize(skey);

                    switch(subtype) {
                        case PSBT_ELEMENTS_GLOBAL_SCALAR:
                        {
                            uint256 scalar;
                            skey >> scalar;
                            if (scalar_offsets.count(scalar) > 0) {
                                throw std::ios_base::failure("Duplicate key, the same scalar offset was provided multiple times");
                            } else if (key.size() != 33) {
                                throw std::ios_base::failure("Global scalar offset key was not the expected length");
                            }
                            std::vector<unsigned char> val;
                            s >> val;
                            if (val.size() != 0) {
                                throw std::ios_base::failure("Global scalar value was not empty");
                            }
                            scalar_offsets.insert(scalar);
                            break;
                        }
                    }
                    break;
                }
                // Unknown stuff
                default: {
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    std::vector<unsigned char> val_bytes;
                    s >> val_bytes;
                    unknown.emplace(std::move(key), std::move(val_bytes));
                }
            }
        }

        if (!found_sep) {
            throw std::ios_base::failure("Separator is missing at the end of the global map");
        }

        // Make sure that we got an unsigned tx
        if (!tx) {
            throw std::ios_base::failure("No unsigned transcation was provided");
        }

        // Read input data
        unsigned int i = 0;
        while (!s.empty() && i < tx->vin.size()) {
            PSBTInput input;
            s >> input;
            inputs.push_back(input);

            // Make sure the non-witness utxo matches the outpoint
            if (input.non_witness_utxo && input.non_witness_utxo->GetHash() != tx->vin[i].prevout.hash) {
                throw std::ios_base::failure("Non-witness UTXO does not match outpoint hash");
            }
            ++i;
        }
        // Make sure that the number of inputs matches the number of inputs in the transaction
        if (inputs.size() != tx->vin.size()) {
            throw std::ios_base::failure("Inputs provided does not match the number of inputs in transaction.");
        }

        // Read output data
        i = 0;
        while (!s.empty() && i < tx->vout.size()) {
            PSBTOutput output;
            s >> output;
            outputs.push_back(output);
            ++i;
        }
        // Make sure that the number of outputs matches the number of outputs in the transaction
        if (outputs.size() != tx->vout.size()) {
            throw std::ios_base::failure("Outputs provided does not match the number of outputs in transaction.");
        }
        // Sanity check
        if (!IsSane()) {
            throw std::ios_base::failure("PSBT is not sane.");
        }
    }

    template <typename Stream>
    PartiallySignedTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

/** Checks whether a PSBTInput is already signed. */
bool PSBTInputSigned(PSBTInput& input);

/** Signs a PSBTInput, verifying that all provided data matches what is being signed. */
bool SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, int sighash = SIGHASH_ALL, SignatureData* out_sigdata = nullptr, bool use_dummy = false);

/**
 * Finalizes a PSBT if possible, combining partial signatures.
 *
 * @param[in,out] &psbtx reference to PartiallySignedTransaction to finalize
 * return True if the PSBT is now complete, false otherwise
 */
bool FinalizePSBT(PartiallySignedTransaction& psbtx);

/**
 * Finalizes a PSBT if possible, and extracts it to a CMutableTransaction if it could be finalized.
 *
 * @param[in]  &psbtx reference to PartiallySignedTransaction
 * @param[out] result CMutableTransaction representing the complete transaction, if successful
 * @return True if we successfully extracted the transaction, false otherwise
 */
bool FinalizeAndExtractPSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& result);

/**
 * Combines PSBTs with the same underlying transaction, resulting in a single PSBT with all partial signatures from each input.
 *
 * @param[out] &out   the combined PSBT, if successful
 * @param[in]  psbtxs the PSBTs to combine
 * @return error (OK if we successfully combined the transactions, other error if they were not compatible)
 */
NODISCARD TransactionError CombinePSBTs(PartiallySignedTransaction& out, const std::vector<PartiallySignedTransaction>& psbtxs);

//! Decode a base64ed PSBT into a PartiallySignedTransaction
NODISCARD bool DecodeBase64PSBT(PartiallySignedTransaction& decoded_psbt, const std::string& base64_psbt, std::string& error);
//! Decode a raw (binary blob) PSBT into a PartiallySignedTransaction
NODISCARD bool DecodeRawPSBT(PartiallySignedTransaction& decoded_psbt, const std::string& raw_psbt, std::string& error);

std::string EncodePSBT(const PartiallySignedTransaction& psbt);

#endif // BITCOIN_PSBT_H
