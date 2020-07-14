// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pegins.h>
#include <psbt.h>
#include <util/strencodings.h>
#include <confidential_validation.h>

PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx) : tx(tx)
{
    inputs.resize(tx.vin.size());
    outputs.resize(tx.vout.size());

    // Extract the issuance data from the inputs
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        CTxIn& txin = this->tx->vin[i];
        PSBTInput& input = inputs[i];

        if (!txin.assetIssuance.IsNull()) {
            if (txin.assetIssuance.nAmount.IsExplicit()) {
                input.issuance_value = txin.assetIssuance.nAmount.GetAmount();
            } else {
                input.issuance_value_commitment = txin.assetIssuance.nAmount;
            }
            txin.assetIssuance.nAmount.SetNull();

            if (txin.assetIssuance.nInflationKeys.IsExplicit()) {
                input.issuance_inflation_keys_amt = txin.assetIssuance.nInflationKeys.GetAmount();
            } else {
                input.issuance_inflation_keys_commitment = txin.assetIssuance.nInflationKeys;
            }
            txin.assetIssuance.nInflationKeys.SetNull();
        }
    }

    // Extract the value, asset, and nonce from the outputs
    for (unsigned int i = 0; i < tx.vout.size(); ++i) {
        CTxOut& txout = this->tx->vout[i];
        PSBTOutput& output = outputs[i];

        if (txout.nAsset.IsExplicit()) {
            output.asset = txout.nAsset.GetAsset().id;
        } else {
            output.asset_commitment = txout.nAsset;
        }
        txout.nAsset.SetNull();

        if (txout.nValue.IsExplicit()) {
            output.value = txout.nValue.GetAmount();
        } else {
            output.value_commitment = txout.nValue;
        }
        txout.nValue.SetNull();

        if (!txout.nNonce.IsNull()) {
            output.ecdh_key.Set(txout.nNonce.vchCommitment.begin(), txout.nNonce.vchCommitment.end());
            txout.nNonce.SetNull();
        }
    }
}

bool PartiallySignedTransaction::IsNull() const
{
    return !tx && inputs.empty() && outputs.empty() && unknown.empty();
}

bool PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psbt)
{
    // Prohibited to merge two PSBTs over different transactions
    if (tx->GetHash() != psbt.tx->GetHash()) {
        return false;
    }

    for (unsigned int i = 0; i < inputs.size(); ++i) {
        if (!inputs[i].Merge(psbt.inputs[i])) {
            return false;
        }
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        if (!outputs[i].Merge(psbt.outputs[i])) {
            return false;
        }
    }
    unknown.insert(psbt.unknown.begin(), psbt.unknown.end());

    return true;
}

bool PartiallySignedTransaction::IsSane() const
{
    for (unsigned int i = 0; i < inputs.size(); ++i) {
        const PSBTInput& input = inputs[i];
        if (!input.IsSane()) return false;
        // Check issuance is empty in the input
        if (!tx->vin[i].assetIssuance.IsNull()) {
            if (!tx->vin[i].assetIssuance.nAmount.IsNull()) return false;
            if (!input.issuance_value && input.issuance_value_commitment.IsNull()) return false;
        }
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        const PSBTOutput& output = outputs[i];
        if (!output.IsSane()) return false;
        // Check that asset, value, and nonce are empty
        if (!tx->vout[i].nValue.IsNull()) return false;
        if (!tx->vout[i].nAsset.IsNull()) return false;
        if (!tx->vout[i].nNonce.IsNull()) return false;
    }
    return true;
}

bool PartiallySignedTransaction::AddInput(const CTxIn& txin, PSBTInput& psbtin)
{
    if (std::find(tx->vin.begin(), tx->vin.end(), txin) != tx->vin.end()) {
        return false;
    }
    tx->vin.push_back(txin);
    psbtin.partial_sigs.clear();
    psbtin.final_script_sig.clear();
    psbtin.final_script_witness.SetNull();
    inputs.push_back(psbtin);
    return true;
}

bool PartiallySignedTransaction::AddOutput(const CTxOut& txout, const PSBTOutput& psbtout)
{
    tx->vout.push_back(txout);
    outputs.push_back(psbtout);
    return true;
}

bool PartiallySignedTransaction::GetInputUTXO(CTxOut& utxo, int input_index) const
{
    PSBTInput input = inputs[input_index];
    int prevout_index = tx->vin[input_index].prevout.n;
    if (input.non_witness_utxo) {
        utxo = input.non_witness_utxo->vout[prevout_index];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
    } else if (tx->vin[input_index].m_is_pegin && input.peg_in_value && !input.claim_script.empty()) {
        // For Peg-ins, get the UTXO from the peg-in stuff
        utxo = CTxOut(Params().GetConsensus().pegged_asset, CConfidentialValue(*input.peg_in_value), input.claim_script);
    } else {
        return false;
    }
    return true;
}

bool PSBTInput::IsNull() const
{
    return !non_witness_utxo && witness_utxo.IsNull() && partial_sigs.empty() && unknown.empty() && hd_keypaths.empty() && redeem_script.empty() && witness_script.empty();
}

void PSBTInput::FillSignatureData(SignatureData& sigdata) const
{
    if (!final_script_sig.empty()) {
        sigdata.scriptSig = final_script_sig;
        sigdata.complete = true;
    }
    if (!final_script_witness.IsNull()) {
        sigdata.scriptWitness = final_script_witness;
        sigdata.complete = true;
    }
    if (sigdata.complete) {
        return;
    }

    sigdata.signatures.insert(partial_sigs.begin(), partial_sigs.end());
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
}

void PSBTInput::FromSignatureData(const SignatureData& sigdata)
{
    if (sigdata.complete) {
        partial_sigs.clear();
        hd_keypaths.clear();
        redeem_script.clear();
        witness_script.clear();

        if (!sigdata.scriptSig.empty()) {
            final_script_sig = sigdata.scriptSig;
        }
        if (!sigdata.scriptWitness.IsNull()) {
            final_script_witness = sigdata.scriptWitness;
        }
        return;
    }

    partial_sigs.insert(sigdata.signatures.begin(), sigdata.signatures.end());
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
}

bool PSBTInput::Merge(const PSBTInput& input)
{
    if (!non_witness_utxo && input.non_witness_utxo) non_witness_utxo = input.non_witness_utxo;
    if (witness_utxo.IsNull() && !input.witness_utxo.IsNull()) {
        witness_utxo = input.witness_utxo;
        non_witness_utxo = nullptr; // Clear out any non-witness utxo when we set a witness one.
    }

    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    hd_keypaths.insert(input.hd_keypaths.begin(), input.hd_keypaths.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());

    if (redeem_script.empty() && !input.redeem_script.empty()) redeem_script = input.redeem_script;
    if (witness_script.empty() && !input.witness_script.empty()) witness_script = input.witness_script;
    if (final_script_sig.empty() && !input.final_script_sig.empty()) final_script_sig = input.final_script_sig;
    if (final_script_witness.IsNull() && !input.final_script_witness.IsNull()) final_script_witness = input.final_script_witness;

    if (peg_in_tx.which() == 0 && peg_in_tx.which() > 0) peg_in_tx = input.peg_in_tx;
    if (txout_proof.which() == 0 && peg_in_tx.which() > 0) txout_proof = input.txout_proof;
    if (claim_script.empty() && !input.claim_script.empty()) claim_script = input.claim_script;
    if (genesis_hash.IsNull() && !input.genesis_hash.IsNull()) genesis_hash = input.genesis_hash;

    return true;
}

bool PSBTInput::IsSane() const
{
    // Cannot have both witness and non-witness utxos
    if (!witness_utxo.IsNull() && non_witness_utxo) return false;

    // If we have a witness_script or a scriptWitness, we must also have a witness utxo
    if (!witness_script.empty() && witness_utxo.IsNull()) return false;
    if (!final_script_witness.IsNull() && witness_utxo.IsNull()) return false;

    // Cannot have both issuance value and issuance value commitment
    if (issuance_value && !issuance_value_commitment.IsNull()) return false;

    return true;
}

void PSBTOutput::FillSignatureData(SignatureData& sigdata) const
{
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
}

void PSBTOutput::FromSignatureData(const SignatureData& sigdata)
{
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
}

bool PSBTOutput::IsNull() const
{
    return redeem_script.empty() && witness_script.empty() && hd_keypaths.empty() && unknown.empty();
}

bool PSBTOutput::IsSane() const
{
    // Must have one of explicit value and asset or their commitments
    if (!value && value_commitment.IsNull()) return false;
    if (asset.IsNull() & asset_commitment.IsNull()) return false;

    // Cannot have explicit value and value commitment
    if (value && !value_commitment.IsNull()) return false;
    // Cannot have explicit asset and asset commitment
    if (!asset.IsNull() && !asset_commitment.IsNull()) return false;

    // If this output needs to be blinded, make sure it is either fully blinded or not blinded
    if (IsBlinded() && (IsPartiallyBlinded() && !IsFullyBlinded())) return false;
    // If output is blinded, a blinder index needs to be specified
    if (IsBlinded() && !blinder_index) return false;

    return true;
}

bool PSBTOutput::Merge(const PSBTOutput& output)
{
    hd_keypaths.insert(output.hd_keypaths.begin(), output.hd_keypaths.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());

    if (redeem_script.empty() && !output.redeem_script.empty()) redeem_script = output.redeem_script;
    if (witness_script.empty() && !output.witness_script.empty()) witness_script = output.witness_script;

    // If this IsBlinded and output IsBlinded, make sure the creator added fields are the same
    if (IsBlinded() && output.IsBlinded()) {
        if (!blinding_pubkey.IsValid() || !output.blinding_pubkey.IsValid() || !blinder_index || !output.blinder_index) return false;
        if (blinding_pubkey != output.blinding_pubkey) return false;
        if (blinder_index != output.blinder_index) return false;
    }

    // If this IsFullyBlinded and output IsFullyBlinded, just double check them
    if (IsFullyBlinded() && output.IsFullyBlinded()) {
        if (!value_commitment.IsNull() && !output.value_commitment.IsNull() && (value_commitment != output.value_commitment)) return false;
        if (!asset_commitment.IsNull() && !output.asset_commitment.IsNull() && (asset_commitment != output.asset_commitment)) return false;
        if (!range_proof.empty() && !output.range_proof.empty() && (range_proof != output.range_proof)) return false;
        if (!surjection_proof.empty() && !output.surjection_proof.empty() && (surjection_proof != output.surjection_proof)) return false;
        if (value || output.value || !asset.IsNull() || !output.asset.IsNull()) return false;
    }

    // If output IsFullyBlinded and this is not, copy the blinding data and remove the explicits
    if (IsBlinded() && !IsFullyBlinded() && output.IsFullyBlinded()) {
        value_commitment = output.value_commitment;
        asset_commitment = output.asset_commitment;
        range_proof = output.range_proof;
        surjection_proof = output.surjection_proof;
        ecdh_key = output.ecdh_key;
    }

    return true;
}

bool PSBTOutput::IsBlinded() const
{
    return blinding_pubkey.IsValid();
}

bool PSBTOutput::IsPartiallyBlinded() const
{
    return IsBlinded() && (!value ||
        !value_commitment.IsNull() ||
        !asset_commitment.IsNull() ||
        asset.IsNull() ||
        !range_proof.empty() ||
        !surjection_proof.empty() ||
        ecdh_key.IsValid());
}

bool PSBTOutput::IsFullyBlinded() const
{
    return IsBlinded() && !value &&
        !value_commitment.IsNull() &&
        !asset_commitment.IsNull() &&
        asset.IsNull() &&
        !range_proof.empty() &&
        !surjection_proof.empty() &&
        ecdh_key.IsValid();
}

bool PSBTInputSigned(PSBTInput& input)
{
    return !input.final_script_sig.empty() || !input.final_script_witness.IsNull();
}

bool SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, int sighash, SignatureData* out_sigdata, bool use_dummy)
{
    PSBTInput& input = psbt.inputs.at(index);
    const CMutableTransaction& tx = *psbt.tx;

    if (PSBTInputSigned(input)) {
        return true;
    }

    // Fill SignatureData with input info
    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    // Get UTXO for this input
    bool require_witness_sig = false;
    CTxOut utxo;

    // Verify input sanity, which checks that at most one of witness or non-witness utxos is provided.
    if (!input.IsSane()) {
        return false;
    }

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = tx.vin[index].prevout;
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
        // When we're taking our information from a witness UTXO, we can't verify it is actually data from
        // the output being spent. This is safe in case a witness signature is produced (which includes this
        // information directly in the hash), but not for non-witness signatures. Remember that we require
        // a witness signature in this situation.
        require_witness_sig = true;
    } else {
        return false;
    }

    sigdata.witness = false;
    bool sig_complete;
    if (use_dummy) {
        sig_complete = ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, utxo.scriptPubKey, sigdata);
    } else {
        MutableTransactionSignatureCreator creator(&tx, index, utxo.nValue, sighash);
        sig_complete = ProduceSignature(provider, creator, utxo.scriptPubKey, sigdata);
    }
    // Verify that a witness signature was produced in case one was required.
    if (require_witness_sig && !sigdata.witness) return false;
    input.FromSignatureData(sigdata);

    // If we have a witness signature, use the smaller witness UTXO.
    if (sigdata.witness) {
        input.witness_utxo = utxo;
        input.non_witness_utxo = nullptr;
    }

    // Fill in the missing info
    if (out_sigdata) {
        out_sigdata->missing_pubkeys = sigdata.missing_pubkeys;
        out_sigdata->missing_sigs = sigdata.missing_sigs;
        out_sigdata->missing_redeem_script = sigdata.missing_redeem_script;
        out_sigdata->missing_witness_script = sigdata.missing_witness_script;
    }

    return sig_complete;
}

bool FinalizePSBT(PartiallySignedTransaction& psbtx)
{
    // Finalize input signatures -- in case we have partial signatures that add up to a complete
    //   signature, but have not combined them yet (e.g. because the combiner that created this
    //   PartiallySignedTransaction did not understand them), this will combine them into a final
    //   script.
    bool complete = true;
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        complete &= SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, SIGHASH_ALL);
    }

    return complete;
}

bool FinalizeAndExtractPSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& result)
{
    // It's not safe to extract a PSBT that isn't finalized, and there's no easy way to check
    //   whether a PSBT is finalized without finalizing it, so we just do this.
    if (!FinalizePSBT(psbtx)) {
        return false;
    }

    result = *psbtx.tx;
    result.witness.vtxinwit.resize(result.vin.size());
    for (unsigned int i = 0; i < result.vin.size(); ++i) {
        result.vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
        result.witness.vtxinwit[i].scriptWitness = psbtx.inputs[i].final_script_witness;
        PSBTInput& input = psbtx.inputs[i];

        /*
        if (input.value && input.peg_in_tx.which() != 0 && input.txout_proof.which() != 0 && !input.claim_script.empty() && !input.genesis_hash.IsNull()) {
            CScriptWitness pegin_witness;
            if (Params().GetConsensus().ParentChainHasPow()) {
                const Sidechain::Bitcoin::CTransactionRef& btc_peg_in_tx = boost::get<Sidechain::Bitcoin::CTransactionRef>(input.peg_in_tx);
                const Sidechain::Bitcoin::CMerkleBlock& btc_txout_proof = boost::get<Sidechain::Bitcoin::CMerkleBlock>(input.txout_proof);
                pegin_witness = CreatePeginWitness(*input.value, input.asset, input.genesis_hash, input.claim_script, btc_peg_in_tx, btc_txout_proof);
            } else {
                const CTransactionRef& elem_peg_in_tx = boost::get<CTransactionRef>(input.peg_in_tx);
                const CMerkleBlock& elem_txout_proof = boost::get<CMerkleBlock>(input.txout_proof);
                pegin_witness = CreatePeginWitness(*input.value, input.asset, input.genesis_hash, input.claim_script, elem_peg_in_tx, elem_txout_proof);
            }
            result.vin[i].m_is_pegin = true;
            result.witness.vtxinwit[i].m_pegin_witness = pegin_witness;
        }
        */
    }

    result.witness.vtxoutwit.resize(result.vout.size());
    for (unsigned int i = 0; i < result.vout.size(); ++i) {
        PSBTOutput& output = psbtx.outputs.at(i);
        CTxOut& out = result.vout[i];
        CTxOutWitness& outwit = result.witness.vtxoutwit[i];

        if (!output.value_commitment.IsNull()) {
            out.nValue = output.value_commitment;
        }
        if (!output.asset_commitment.IsNull()) {
            out.nAsset = output.asset_commitment;
        }
        /*
        if (!output.nonce_commitment.IsNull()) {
            out.nNonce = output.nonce_commitment;
        }
        */
        if (!output.range_proof.empty()) {
            outwit.vchRangeproof = output.range_proof;
        }
        if (!output.surjection_proof.empty()) {
            outwit.vchSurjectionproof = output.surjection_proof;
        }
    }

    return true;
}

TransactionError CombinePSBTs(PartiallySignedTransaction& out, const std::vector<PartiallySignedTransaction>& psbtxs)
{
    out = psbtxs[0]; // Copy the first one

    // Merge
    for (auto it = std::next(psbtxs.begin()); it != psbtxs.end(); ++it) {
        if (!out.Merge(*it)) {
            return TransactionError::PSBT_MISMATCH;
        }
    }
    if (!out.IsSane()) {
        return TransactionError::INVALID_PSBT;
    }

    return TransactionError::OK;
}

std::string EncodePSBT(const PartiallySignedTransaction& psbt)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbt;
    return EncodeBase64((unsigned char*)ssTx.data(), ssTx.size());
}


bool DecodeBase64PSBT(PartiallySignedTransaction& psbt, const std::string& base64_tx, std::string& error)
{
    bool invalid;
    std::string tx_data = DecodeBase64(base64_tx, &invalid);
    if (invalid) {
        error = "invalid base64";
        return false;
    }
    return DecodeRawPSBT(psbt, tx_data, error);
}

bool DecodeRawPSBT(PartiallySignedTransaction& psbt, const std::string& tx_data, std::string& error)
{
    CDataStream ss_data(tx_data.data(), tx_data.data() + tx_data.size(), SER_NETWORK, PROTOCOL_VERSION);
    try {
        ss_data >> psbt;
        if (!ss_data.empty()) {
            error = "extra data after PSBT";
            return false;
        }
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    return true;
}
