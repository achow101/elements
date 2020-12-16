// Copyright (c) 2017-2019 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blindpsbt.h>

#include <hash.h>
#include <primitives/transaction.h>
#include <primitives/confidential.h>
#include <psbt.h>
#include <issuance.h>
#include <random.h>
#include <util/system.h>

static secp256k1_context* secp256k1_blind_context = NULL;

class Blind_PSBT_ECC_Init {
public:
    Blind_PSBT_ECC_Init() {
        assert(secp256k1_blind_context == NULL);

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        assert(ctx != NULL);

        secp256k1_blind_context = ctx;
    }

    ~Blind_PSBT_ECC_Init() {
        secp256k1_context *ctx = secp256k1_blind_context;
        secp256k1_blind_context = NULL;

        if (ctx) {
            secp256k1_context_destroy(ctx);
        }
    }
};

static Blind_PSBT_ECC_Init ecc_init_on_load;

// Create surjection proof
bool CreateAssetSurjectionProof(std::vector<unsigned char>& output_proof, const std::vector<secp256k1_fixed_asset_tag>& fixed_input_tags, const std::vector<secp256k1_generator>& ephemeral_input_tags, const std::vector<uint256>& input_asset_blinders, const uint256& output_asset_blinder, const secp256k1_generator& output_asset_tag, const CAsset& asset)
{
    int ret;
    // 1 to 3 targets
    size_t inputs_to_select = std::min((size_t)3, fixed_input_tags.size());
    unsigned char randseed[32];
    GetStrongRandBytes(randseed, 32);
    size_t input_index;
    secp256k1_surjectionproof proof;
    secp256k1_fixed_asset_tag fixed_output_tag;
    memcpy(&fixed_output_tag, asset.begin(), 32);
    // Find correlation between asset tag and listed input tags
    if (secp256k1_surjectionproof_initialize(secp256k1_blind_context, &proof, &input_index, &fixed_input_tags[0], fixed_input_tags.size(), inputs_to_select, &fixed_output_tag, 100, randseed) == 0) {
        return false;
    }
    // Using the input chosen, build proof
    ret = secp256k1_surjectionproof_generate(secp256k1_blind_context, &proof, &ephemeral_input_tags[0], ephemeral_input_tags.size(), &output_asset_tag, input_index, input_asset_blinders[input_index].begin(), output_asset_blinder.begin());
    assert(ret == 1);
    // Double-check answer
    ret = secp256k1_surjectionproof_verify(secp256k1_blind_context, &proof, &ephemeral_input_tags[0], ephemeral_input_tags.size(), &output_asset_tag);
    assert(ret != 0);

    // Serialize into output witness structure
    size_t output_len = secp256k1_surjectionproof_serialized_size(secp256k1_blind_context, &proof);
    output_proof.resize(output_len);
    secp256k1_surjectionproof_serialize(secp256k1_blind_context, &output_proof[0], &output_len, &proof);
    assert(output_len == output_proof.size());
    return true;
}

uint256 GenerateRangeproofECDHKey(CPubKey& ephemeral_pubkey, const CPubKey blinding_pubkey)
{
    // Generate ephemeral key for ECDH nonce generation
    CKey ephemeral_key;
    ephemeral_key.MakeNewKey(true);
    ephemeral_pubkey = ephemeral_key.GetPubKey();
    assert(ephemeral_pubkey.size() == CConfidentialNonce::nCommittedSize);
    // Generate nonce
    uint256 nonce = ephemeral_key.ECDH(blinding_pubkey);
    CSHA256().Write(nonce.begin(), 32).Finalize(nonce.begin());
    return nonce;
}

bool CreateValueRangeProof(std::vector<unsigned char>& rangeproof, const uint256& value_blinder, const uint256& nonce, const CAmount amount, const CScript& scriptPubKey, const secp256k1_pedersen_commitment& value_commit, const secp256k1_generator& gen, const CAsset& asset, const uint256& asset_blinder)
{
    // Prep range proof
    size_t rangeproof_len = 5134;
    rangeproof.resize(rangeproof_len);

    // Compose sidechannel message to convey asset info (ID and asset blinds)
    unsigned char asset_message[SIDECHANNEL_MSG_SIZE];
    memcpy(asset_message, asset.begin(), 32);
    memcpy(asset_message + 32, asset_blinder.begin(), 32);

    // Sign rangeproof
    int ct_exponent = (int)gArgs.GetArg("-ct_exponent", 0);
    int ct_bits = (int)gArgs.GetArg("-ct_bits", 52);
    // If min_value is 0, scriptPubKey must be unspendable
    uint64_t min_value = scriptPubKey.IsUnspendable() ? 0 : 1;
    int res = secp256k1_rangeproof_sign(secp256k1_blind_context, rangeproof.data(), &rangeproof_len, min_value, &value_commit, value_blinder.begin(), nonce.begin(), ct_exponent, ct_bits, amount, asset_message, sizeof(asset_message), scriptPubKey.size() ? &scriptPubKey.front() : NULL, scriptPubKey.size(), &gen);
    rangeproof.resize(rangeproof_len);
    return (res == 1);
}

void CreateAssetCommitment(CConfidentialAsset& conf_asset, secp256k1_generator& asset_gen, const CAsset& asset, const uint256& asset_blinder)
{
    conf_asset.vchCommitment.resize(CConfidentialAsset::nCommittedSize);
    int ret = secp256k1_generator_generate_blinded(secp256k1_blind_context, &asset_gen, asset.begin(), asset_blinder.begin());
    assert(ret == 1);
    ret = secp256k1_generator_serialize(secp256k1_blind_context, conf_asset.vchCommitment.data(), &asset_gen);
    assert(ret != 0);
}

void CreateValueCommitment(CConfidentialValue& conf_value, secp256k1_pedersen_commitment& value_commit, const uint256& value_blinder, const secp256k1_generator& asset_gen, const CAmount amount)
{
    int ret;
    conf_value.vchCommitment.resize(CConfidentialValue::nCommittedSize);
    ret = secp256k1_pedersen_commit(secp256k1_blind_context, &value_commit, value_blinder.begin(), amount, &asset_gen);
    assert(ret != 0);
    secp256k1_pedersen_commitment_serialize(secp256k1_blind_context, conf_value.vchCommitment.data(), &value_commit);
    assert(conf_value.IsValid());
}

// Subtract b from a in place
bool SubtractScalars(uint256& a, const uint256& b)
{
    uint256 sub(b);
    if (secp256k1_ec_privkey_negate(secp256k1_blind_context, sub.begin()) != 1) return false;
    if (secp256k1_ec_privkey_tweak_add(secp256k1_blind_context, a.begin(), sub.begin()) != 1) return false;
    return true;
}

// Compute the scalar offset used for the final blinder computation
// value * asset_blinder + value_blinder
bool CalculateScalarOffset(uint256& out, CAmount value, const uint256& asset_blinder, const uint256& value_blinder)
{
    out = asset_blinder;
    uint256 val;
    // tweak_mul expects a 32 byte, big endian tweak.
    // We need to pack the 8 byte CAmount into a uint256 with the correct padding, so start it at 24 bytes from the front
    WriteBE64(val.begin() + 24, value);
    if (secp256k1_ec_privkey_tweak_mul(secp256k1_blind_context, out.begin(), val.begin()) != 1) return false;
    if (secp256k1_ec_privkey_tweak_add(secp256k1_blind_context, out.begin(), value_blinder.begin()) != 1) return false;
    return true;
}

// Computes a scalar offset and adds it to another existing one
bool ComputeAndAddToScalarOffset(uint256& a, CAmount value, const uint256& asset_blinder, const uint256& value_blinder)
{
    uint256 scalar;
    if (!CalculateScalarOffset(scalar, value, asset_blinder, value_blinder)) return false;
    if (secp256k1_ec_privkey_tweak_add(secp256k1_blind_context, a.begin(), scalar.begin()) != 1) return false;
    return true;
}

BlindingStatus BlindPSBT(PartiallySignedTransaction& psbt, std::map<uint32_t, std::tuple<CAmount, CAsset, uint256, uint256>> our_input_data, std::map<uint32_t, std::pair<CKey, CKey>> our_issuances_to_blind)
{
    int num_blinded = 0;
    std::vector<uint32_t> to_blind;
    for (unsigned int i = 0; i < psbt.outputs.size(); ++i) {
        PSBTOutput& output = psbt.outputs[i];
        if (output.IsFullyBlinded()) num_blinded++;
        if (output.IsBlinded()) to_blind.push_back(i);
    }
    if (num_blinded == to_blind.size()) {
        // All outputs are blinded, nothing left to do
        return BlindingStatus::OK;
    }

    std::vector<secp256k1_fixed_asset_tag> fixed_input_tags; // Explicit Asset IDs for the inputs we know. Blinded for unknown ones
    std::vector<secp256k1_generator> ephemeral_input_tags; // Blinded Asset IDs. Explicit Asset ID blinded with 0 if not blinded
    std::vector<uint256> input_asset_blinders; // Blinding factors for the input asset tags

    uint256 input_scalar;

    for (unsigned int i = 0; i < psbt.inputs.size(); ++i) {
        PSBTInput& input = psbt.inputs[i];
        CTxIn& txin = psbt.tx->vin[i];

        CTxOut utxo;
        if (!psbt.GetInputUTXO(utxo, i)) {
            return BlindingStatus::NEEDS_UTXOS;
        }
        CConfidentialAsset& asset = utxo.nAsset;

        ephemeral_input_tags.emplace_back();
        if (asset.IsExplicit()) {
            // Explicit asset
            if (secp256k1_generator_generate(secp256k1_blind_context, &ephemeral_input_tags.back(), asset.GetAsset().begin()) != 1) {
                return BlindingStatus::INVALID_ASSET;
            }
        } else {
            // Parse the asset commitment as a generator (because it is)
            if (secp256k1_generator_parse(secp256k1_blind_context, &ephemeral_input_tags.back(), asset.vchCommitment.data()) != 1) {
                return BlindingStatus::INVALID_ASSET_COMMITMENT;
            }
        }

        fixed_input_tags.emplace_back();
        auto it = our_input_data.find(i);
        if (it != our_input_data.end()) {
            memcpy(fixed_input_tags.back().data, std::get<1>(it->second).begin(), 32);
            input_asset_blinders.push_back(std::get<2>(it->second));
            // Add the value blinder to the input scalar
            if (!txin.m_is_pegin && !ComputeAndAddToScalarOffset(input_scalar, std::get<0>(it->second), std::get<2>(it->second), std::get<3>(it->second))) return BlindingStatus::SCALAR_UNABLE;
        } else if (asset.IsExplicit()) {
            memcpy(fixed_input_tags.back().data, asset.GetAsset().begin(), 32);
            input_asset_blinders.emplace_back(); // No blinding factor, put 0
        } else {
            memcpy(fixed_input_tags.back().data, asset.vchCommitment.data() + 1, 32);
            input_asset_blinders.emplace_back(); // We don't know the blinding factor, put 0
        }

        // Handle issuances
        CAssetIssuance& issuance = psbt.tx->vin[i].assetIssuance;
        if (input.issuance_value) {
            if (!input.issuance_value_commitment.IsCommitment() && input.issuance_rangeproof.size() == 0 && input.issuance_keys_rangeproof.size() == 0) {
                CAsset issuance_asset;
                CAsset reissuance_asset;

                uint256 entropy;
                if (!issuance.assetBlindingNonce.IsNull()) {
                    // Reissuance, use assetEntropy as the asset entropy
                    entropy = issuance.assetEntropy;
                } else {
                    // New issuance, make new entropy
                    GenerateAssetEntropy(entropy, psbt.tx->vin[i].prevout, issuance.assetEntropy);
                }

                // Asset isn't blinded yet. Add it to the list of input assets
                CalculateAsset(issuance_asset, entropy);
                fixed_input_tags.emplace_back();
                memcpy(fixed_input_tags.back().data, issuance_asset.begin(), 32);
                ephemeral_input_tags.emplace_back();
                if (secp256k1_generator_generate(secp256k1_blind_context, &ephemeral_input_tags.back(), issuance_asset.begin()) != 1) {
                    return BlindingStatus::INVALID_ASSET;
                }
                unsigned int iss_to_blind = 1; // Always do the first issuance blinding iteration for the issuance value

                bool blind_issuance = our_issuances_to_blind.count(i) > 0;

                if (issuance.assetBlindingNonce.IsNull() && input.issuance_inflation_keys_amt) {
                    // New issuance, do reissuance token things
                    CalculateReissuanceToken(reissuance_asset, entropy, blind_issuance);
                    // Add the reissuance_asset to the list of input assets
                    fixed_input_tags.emplace_back();
                    memcpy(fixed_input_tags.back().data, reissuance_asset.begin(), 32);
                    ephemeral_input_tags.emplace_back();
                    if (secp256k1_generator_generate(secp256k1_blind_context, &ephemeral_input_tags.back(), reissuance_asset.begin()) != 1) {
                        return BlindingStatus::INVALID_ASSET;
                    }
                    iss_to_blind++; // If we have a reissuance, do the second blinding iteration for the inflation keys
                }

                if (blind_issuance) {
                    for (unsigned int blind_i = 0; blind_i < iss_to_blind; ++blind_i) {
                        // To blind an issuance, both the issuance value and the number of inflation keys need to be blinded
                        // Since this process is basically the same for both, do it in a loop and switch based on the index
                        bool blind_value = blind_i == 0; // True for blinding the value, false for blinding the inflation keys
                        CAmount value = blind_value ? *input.issuance_value : *input.issuance_inflation_keys_amt;
                        CAsset asset = blind_value ? issuance_asset : reissuance_asset;
                        CKey blinding_privkey = blind_value ? our_issuances_to_blind.at(i).first : our_issuances_to_blind.at(i).second;

                        uint256 value_blinder;
                        GetStrongRandBytes(value_blinder.begin(), value_blinder.size());

                        // Create unblinded generator. Throw away everything except asset_gen
                        uint256 asset_blinder;
                        CConfidentialAsset conf_asset;
                        secp256k1_generator asset_gen;
                        CreateAssetCommitment(conf_asset, asset_gen, asset, asset_blinder);
                        input_asset_blinders.push_back(asset_blinder);

                        // Compute the scalar for this blinding and add to the input scalar
                        if (!ComputeAndAddToScalarOffset(input_scalar, value, asset_blinder, value_blinder)) return BlindingStatus::SCALAR_UNABLE;

                        // Create value commitment
                        secp256k1_pedersen_commitment value_commit;
                        CConfidentialValue conf_value;
                        CreateValueCommitment(conf_value, value_commit, value_blinder, asset_gen, value);

                        // Nonce is the blinding key
                        uint256 nonce = uint256(std::vector<unsigned char>(blinding_privkey.begin(), blinding_privkey.end()));

                        // Generate rangeproof
                        std::vector<unsigned char> rangeproof;
                        bool rangeresult = CreateValueRangeProof(rangeproof, value_blinder, nonce, value, CScript(), value_commit, asset_gen, asset, asset_blinder);
                        assert(rangeresult);

                        if (blind_value) {
                            input.issuance_value_commitment = conf_value;
                            input.issuance_rangeproof = rangeproof;
                            input.issuance_value = boost::none;
                        } else {
                            input.issuance_inflation_keys_commitment = conf_value;
                            input.issuance_keys_rangeproof = rangeproof;
                            input.issuance_inflation_keys_amt = boost::none;
                        }
                    }
                }
            }
        }
    }

    uint256 output_scalar;
    bool did_last_blind = false;
    for (uint32_t i : to_blind) {
        PSBTOutput& output = psbt.outputs[i];
        const CTxOut& txout = psbt.tx->vout[i];

        if (output.IsFullyBlinded()) continue;

        // Check this is our output to blind
        if (our_input_data.count(*output.blinder_index) == 0) continue;

        // Things we are going to stuff into the PSBTOutput if everything is successful
        CConfidentialValue value_commitment;
        CConfidentialAsset asset_commitment;
        std::vector<unsigned char> rangeproof;
        std::vector<unsigned char> asp;
        CPubKey ecdh_key;

        // Generate the blinders
        uint256 value_blinder;
        uint256 asset_blinder;
        GetStrongRandBytes(value_blinder.begin(), value_blinder.size());
        GetStrongRandBytes(asset_blinder.begin(), asset_blinder.size());

        // Compute the scalar for this blinding and add to the output scalar
        if (!ComputeAndAddToScalarOffset(output_scalar, *output.value, asset_blinder, value_blinder)) return BlindingStatus::SCALAR_UNABLE;

        // For the last blinder
        num_blinded++;
        if (num_blinded == to_blind.size()) {
            did_last_blind = true;

            // For the last blinder, we need to first compute a scalar offset for the inputs and outputs that haven't already been
            // accounted for in a scalar. Then for this last output, a randomly generated value blinder is created and all of the scalar
            // offsets subtracted from this.

            // First compute a scalar offset for the stuff we've already blinded and subtract that scalar from value_blinder
            if (!SubtractScalars(output_scalar, input_scalar)) return BlindingStatus::SCALAR_UNABLE;
            if (!SubtractScalars(value_blinder, output_scalar)) return BlindingStatus::SCALAR_UNABLE;

            // Now subtract ever other scalar from value_blinder
            for (const uint256& s : psbt.scalar_offsets) {
                if (!SubtractScalars(value_blinder, s)) return BlindingStatus::SCALAR_UNABLE;
            }

            // Make sure our blinder isn't 0 as this has privacy implications.
            // This can occur if the transaction has one input and one output.
            // This can also occur if another party is being malicious.
            // Or just bad luck.
            if (value_blinder.IsNull()) return BlindingStatus::INVALID_BLINDER;

            // Remove all scalar offsets
            psbt.scalar_offsets.clear();
        }

        CAsset asset(output.asset);

        // Blind the asset ID
        secp256k1_generator asset_generator;
        CreateAssetCommitment(asset_commitment, asset_generator, asset, asset_blinder);

        // Blind the value
        secp256k1_pedersen_commitment value_commit;
        CreateValueCommitment(value_commitment, value_commit, value_blinder, asset_generator, *output.value);

        // Generate rangproof nonce
        uint256 nonce = GenerateRangeproofECDHKey(ecdh_key, output.blinding_pubkey);

        // Generate rangeproof
        bool rangeresult = CreateValueRangeProof(rangeproof, value_blinder, nonce, *output.value, txout.scriptPubKey, value_commit, asset_generator, asset, asset_blinder);
        assert(rangeresult);

        // Create surjection proof for this output
        if (!CreateAssetSurjectionProof(asp, fixed_input_tags, ephemeral_input_tags, input_asset_blinders, asset_blinder, asset_generator, asset)) {
            return BlindingStatus::ASP_UNABLE;
        }

        // Fill output
        output.asset_commitment = asset_commitment;
        output.value_commitment = value_commitment;
        output.ecdh_key = ecdh_key;
        output.range_proof = rangeproof;
        output.surjection_proof = asp;

        // Drop explicit value and asset
        output.value = boost::none;
        output.asset.SetNull();
    }

    if (!did_last_blind) {
        // Subtract input scalar from output scalar
        if (!SubtractScalars(output_scalar, input_scalar)) return BlindingStatus::SCALAR_UNABLE;
        // Now add the scalar to the PSBT
        psbt.scalar_offsets.insert(output_scalar);
    }

    return BlindingStatus::OK;
}
