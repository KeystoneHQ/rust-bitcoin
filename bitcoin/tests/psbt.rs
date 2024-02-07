//! Tests PSBT integration vectors from BIP 174
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#test-vectors>

use core::convert::TryFrom;
use std::collections::BTreeMap;
use std::str::FromStr;
use secp256k1::{Signing, XOnlyPublicKey};

use bitcoin::bip32::{DerivationPath, Fingerprint, IntoDerivationPath, KeySource, Xpriv, Xpub};
use bitcoin::blockdata::opcodes::OP_0;
use bitcoin::blockdata::{script, transaction};
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hex::FromHex;
use bitcoin::psbt::{GetKey, Input, KeyRequest, Psbt, PsbtSighashType, SignError};
use bitcoin::script::PushBytes;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{absolute, Address, Amount, Denomination, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;

const NETWORK: Network = Network::Testnet;

#[track_caller]
fn hex_psbt(s: &str) -> Psbt {
    let v: Vec<u8> = Vec::from_hex(s).expect("valid hex digits");
    Psbt::deserialize(&v).expect("valid magic and valid separators")
}

#[track_caller]
fn hex_script(s: &str) -> ScriptBuf { ScriptBuf::from_hex(s).expect("valid hex digits") }

#[test]
fn bip174_psbt_workflow() {
    let secp = Secp256k1::new();

    //
    // Step 0: Create the extended private key from the test vector data.
    //

    let ext_priv = build_extended_private_key();
    let ext_pub = Xpub::from_priv(&secp, &ext_priv);
    let parent_fingerprint = ext_pub.fingerprint();

    //
    // Step 1: The creator.
    //

    let tx = create_transaction();
    let psbt = create_psbt(tx);

    //
    // Step 2: The first updater.
    //

    let psbt = update_psbt(psbt, parent_fingerprint);

    //
    // Step 3: The second updater.
    //

    let psbt = update_psbt_with_sighash_all(psbt);

    //
    // Step 4: The first signer.
    //

    // Strings from BIP 174 test vector.
    let test_vector = vec![
        ("cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr", "m/0h/0h/0h"), // from_priv, into_derivation_path?
        ("cR6SXDoyfQrcp4piaiHE97Rsgta9mNhGTen9XeonVgwsh4iSgw6d", "m/0h/0h/2h"),
    ];

    // We pass the keys to the signer after doing verification to make explicit
    // that signer is only using these two keys.
    let keys = parse_and_verify_keys(&ext_priv, &test_vector);
    let psbt_1 = signer_one_sign(psbt.clone(), keys);

    //
    // Step 5: The second signer.
    //

    // Strings from BIP 174 test vector.
    let test_vector = vec![
        ("cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au", "m/0h/0h/1h"),
        ("cNBc3SWUip9PPm1GjRoLEJT6T41iNzCYtD7qro84FMnM5zEqeJsE", "m/0h/0h/3h"),
    ];

    let keys = parse_and_verify_keys(&ext_priv, &test_vector);
    let psbt_2 = signer_two_sign(psbt, keys);

    //
    // Step 6: Combiner the two signed PSBTs.
    //

    let combined = combine(psbt_1, psbt_2);

    //
    // Step 7: Finalize the PSBT.
    //

    let finalized = finalize(combined);

    //
    // Step 8: Extract the transaction.
    //

    let _tx = extract_transaction(finalized);

    //
    // Step 9: Test lexicographical PSBT combiner.
    //
    // Combine would be done earlier, at Step 6, in typical workflow.
    // We define it here to reflect the order of test vectors in BIP 174.
    //

    combine_lexicographically();
}

/// Attempts to build an extended private key from seed and also directly from a string.
fn build_extended_private_key() -> Xpriv {
    // Strings from BIP 174 test vector.
    let extended_private_key = "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF";
    let seed = "cUkG8i1RFfWGWy5ziR11zJ5V4U4W3viSFCfyJmZnvQaUsd1xuF3T";

    let xpriv = Xpriv::from_str(extended_private_key).unwrap();

    let sk = PrivateKey::from_wif(seed).unwrap();
    let seeded = Xpriv::new_master(NETWORK, &sk.inner.secret_bytes()).unwrap();
    assert_eq!(xpriv, seeded);

    xpriv
}

/// Creates the initial transaction, called by the PSBT Creator.
fn create_transaction() -> Transaction {
    // Strings from BIP 174 test vector.
    let output_0 = TvOutput {
        amount: "1.49990000",
        script_pubkey: "0014d85c2b71d0060b09c9886aeb815e50991dda124d",
    };
    let output_1 = TvOutput {
        amount: "1.00000000",
        script_pubkey: "001400aea9a2e5f0f876a588df5546e8742d1d87008f",
    };
    let input_0 = TvInput {
        txid: "75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858",
        index: 0,
    };
    let input_1 = TvInput {
        txid: "1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83",
        index: 1,
    };
    struct TvOutput {
        amount: &'static str,
        script_pubkey: &'static str,
    }
    struct TvInput {
        txid: &'static str,
        index: u32,
    }

    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: input_0.txid.parse().expect("failed to parse txid"),
                    vout: input_0.index,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX, // Disable nSequence.
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: input_1.txid.parse().expect("failed to parse txid"),
                    vout: input_1.index,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_str_in(output_0.amount, Denomination::Bitcoin)
                    .expect("failed to parse amount"),
                script_pubkey: ScriptBuf::from_hex(output_0.script_pubkey)
                    .expect("failed to parse script"),
            },
            TxOut {
                value: Amount::from_str_in(output_1.amount, Denomination::Bitcoin)
                    .expect("failed to parse amount"),
                script_pubkey: ScriptBuf::from_hex(output_1.script_pubkey)
                    .expect("failed to parse script"),
            },
        ],
    }
}

/// Creates the initial PSBT, called by the Creator. Verifies against BIP 174 test vector.
#[track_caller]
fn create_psbt(tx: Transaction) -> Psbt {
    // String from BIP 174 test vector.
    let expected_psbt_hex = include_str!("data/create_psbt_hex");
    let expected_psbt: Psbt = hex_psbt(expected_psbt_hex);
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Updates `psbt` according to the BIP, returns the newly updated PSBT. Verifies against BIP 174 test vector.
#[track_caller]
fn update_psbt(mut psbt: Psbt, fingerprint: Fingerprint) -> Psbt {
    // Strings from BIP 174 test vector.
    let previous_tx_0 = include_str!("data/previous_tx_0_hex");
    let previous_tx_1 = include_str!("data/previous_tx_1_hex");

    let redeem_script_0 = "5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae";
    let redeem_script_1 = "00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903";
    let witness_script = "522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae";

    // Public key and its derivation path (these are the child pubkeys for our `Xpriv`,
    // can be verified by deriving the key using this derivation path).
    let pk_path = vec![
        ("029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f", "m/0h/0h/0h"),
        ("02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7", "m/0h/0h/1h"),
        ("03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc", "m/0h/0h/2h"),
        ("023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73", "m/0h/0h/3h"),
        ("03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771", "m/0h/0h/4h"),
        ("027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096", "m/0h/0h/5h"),
    ];

    let expected_psbt_hex = include_str!("data/update_1_psbt_hex");
    let expected_psbt: Psbt = hex_psbt(expected_psbt_hex);

    let mut input_0 = psbt.inputs[0].clone();

    let v = Vec::from_hex(previous_tx_1).unwrap();
    let tx: Transaction = deserialize(&v).unwrap();
    input_0.non_witness_utxo = Some(tx);
    input_0.redeem_script = Some(hex_script(redeem_script_0));
    input_0.bip32_derivation = bip32_derivation(fingerprint, &pk_path, vec![0, 1]);

    let mut input_1 = psbt.inputs[1].clone();

    let v = Vec::from_hex(previous_tx_0).unwrap();
    let tx: Transaction = deserialize(&v).unwrap();
    input_1.witness_utxo = Some(tx.output[1].clone());

    input_1.redeem_script = Some(hex_script(redeem_script_1));
    input_1.witness_script = Some(hex_script(witness_script));
    input_1.bip32_derivation = bip32_derivation(fingerprint, &pk_path, vec![2, 3]);

    psbt.inputs = vec![input_0, input_1];

    let mut output_0 = psbt.outputs[0].clone();
    output_0.bip32_derivation = bip32_derivation(fingerprint, &pk_path, vec![4]);

    let mut output_1 = psbt.outputs[1].clone();
    output_1.bip32_derivation = bip32_derivation(fingerprint, &pk_path, vec![5]);

    psbt.outputs = vec![output_0, output_1];

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// `pk_path` holds tuples of `(public_key, derivation_path)`. `indecies` is used to access the
/// `pk_path` vector. `fingerprint` is from the parent extended public key.
fn bip32_derivation(
    fingerprint: Fingerprint,
    pk_path: &[(&str, &str)],
    indecies: Vec<usize>,
) -> BTreeMap<secp256k1::PublicKey, KeySource> {
    let mut tree = BTreeMap::new();
    for i in indecies {
        let pk = pk_path[i].0;
        let path = pk_path[i].1;

        let pk = PublicKey::from_str(pk).unwrap();
        let path = path.into_derivation_path().unwrap();

        tree.insert(pk.inner, (fingerprint, path));
    }
    tree
}

/// Does the second update according to the BIP, returns the newly updated PSBT. Verifies against BIP 174 test vector.
#[track_caller]
fn update_psbt_with_sighash_all(mut psbt: Psbt) -> Psbt {
    let expected_psbt_hex = include_str!("data/update_2_psbt_hex");
    let expected_psbt: Psbt = hex_psbt(expected_psbt_hex);

    let ty = PsbtSighashType::from_str("SIGHASH_ALL").unwrap();

    let mut input_0 = psbt.inputs[0].clone();
    input_0.sighash_type = Some(ty);
    let mut input_1 = psbt.inputs[1].clone();
    input_1.sighash_type = Some(ty);

    psbt.inputs = vec![input_0, input_1];

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Verifies the keys in the test vector are valid for the extended private key and derivation path.
fn parse_and_verify_keys(
    ext_priv: &Xpriv,
    sk_path: &[(&str, &str)],
) -> BTreeMap<PublicKey, PrivateKey> {
    let secp = &Secp256k1::new();

    let mut key_map = BTreeMap::new();
    for (secret_key, derivation_path) in sk_path.iter() {
        let wif_priv = PrivateKey::from_wif(secret_key).expect("failed to parse key");

        let path =
            derivation_path.into_derivation_path().expect("failed to convert derivation path");
        let derived_priv =
            ext_priv.derive_priv(secp, &path).expect("failed to derive ext priv key").to_priv();
        assert_eq!(wif_priv, derived_priv);
        let derived_pub = derived_priv.public_key(secp);
        key_map.insert(derived_pub, derived_priv);
    }
    key_map
}

/// Does the first signing according to the BIP, returns the signed PSBT. Verifies against BIP 174 test vector.
#[track_caller]
fn signer_one_sign(psbt: Psbt, key_map: BTreeMap<bitcoin::PublicKey, PrivateKey>) -> Psbt {
    let expected_psbt_hex = include_str!("data/sign_1_psbt_hex");
    let expected_psbt: Psbt = hex_psbt(expected_psbt_hex);

    let psbt = sign(psbt, key_map);

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Does the second signing according to the BIP, returns the signed PSBT. Verifies against BIP 174 test vector.
#[track_caller]
fn signer_two_sign(psbt: Psbt, key_map: BTreeMap<bitcoin::PublicKey, PrivateKey>) -> Psbt {
    let expected_psbt_hex = include_str!("data/sign_2_psbt_hex");
    let expected_psbt: Psbt = hex_psbt(expected_psbt_hex);

    let psbt = sign(psbt, key_map);

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Does the combine according to the BIP, returns the combined PSBT. Verifies against BIP 174 test vector.
#[track_caller]
fn combine(mut this: Psbt, that: Psbt) -> Psbt {
    let expected_psbt_hex = include_str!("data/combine_psbt_hex");
    let expected_psbt: Psbt = hex_psbt(expected_psbt_hex);

    this.combine(that).expect("failed to combine PSBTs");

    assert_eq!(this, expected_psbt);
    this
}

/// Does the finalize step according to the BIP, returns the combined PSBT. Verifies against BIP 174
/// test vector.
#[track_caller]
fn finalize(psbt: Psbt) -> Psbt {
    let expected_psbt_hex = include_str!("data/finalize_psbt_hex");
    let expected_psbt: Psbt = hex_psbt(expected_psbt_hex);

    let psbt = finalize_psbt(psbt);

    assert_eq!(psbt, expected_psbt);
    psbt
}

/// Does the transaction extractor step according to the BIP, returns the combined PSBT. Verifies
/// against BIP 174 test vector.
fn extract_transaction(psbt: Psbt) -> Transaction {
    let expected_tx_hex = include_str!("data/extract_tx_hex");

    let tx = psbt.extract_tx_unchecked_fee_rate();

    let got = serialize_hex(&tx);
    assert_eq!(got, expected_tx_hex);

    tx
}

/// Combines two PSBTs lexicographically according to the BIP. Verifies against BIP 174 test vector.
#[track_caller]
fn combine_lexicographically() {
    let psbt_1_hex = include_str!("data/lex_psbt_1_hex");
    let psbt_2_hex = include_str!("data/lex_psbt_2_hex");

    let expected_psbt_hex = include_str!("data/lex_combine_psbt_hex");
    let expected_psbt: Psbt = hex_psbt(expected_psbt_hex);

    let v = Vec::from_hex(psbt_1_hex).unwrap();
    let mut psbt_1 = Psbt::deserialize(&v).expect("failed to deserialize psbt 1");

    let v = Vec::from_hex(psbt_2_hex).unwrap();
    let psbt_2 = Psbt::deserialize(&v).expect("failed to deserialize psbt 2");

    psbt_1.combine(psbt_2).expect("failed to combine PSBTs");

    assert_eq!(psbt_1, expected_psbt);
}

/// Signs `psbt` with `keys` if required.
fn sign(mut psbt: Psbt, keys: BTreeMap<bitcoin::PublicKey, PrivateKey>) -> Psbt {
    let secp = Secp256k1::new();
    psbt.sign(&keys, &secp).unwrap();
    psbt
}

/// Finalizes a PSBT accord to the Input Finalizer role described in BIP 174.
/// This is just a test. For a production-ready PSBT Finalizer, use [rust-miniscript](https://docs.rs/miniscript/latest/miniscript/psbt/trait.PsbtExt.html#tymethod.finalize)
fn finalize_psbt(mut psbt: Psbt) -> Psbt {
    // Input 0: legacy UTXO

    let sigs: Vec<_> = psbt.inputs[0].partial_sigs.values().collect();
    let script_sig = script::Builder::new()
        .push_opcode(OP_0) // OP_CHECKMULTISIG bug pops +1 value when evaluating so push OP_0.
        .push_slice(sigs[0].serialize())
        .push_slice(sigs[1].serialize())
        .push_slice(
            <&PushBytes>::try_from(psbt.inputs[0].redeem_script.as_ref().unwrap().as_bytes())
                .unwrap(),
        )
        .into_script();

    psbt.inputs[0].final_script_sig = Some(script_sig);

    psbt.inputs[0].partial_sigs = BTreeMap::new();
    psbt.inputs[0].sighash_type = None;
    psbt.inputs[0].redeem_script = None;
    psbt.inputs[0].bip32_derivation = BTreeMap::new();

    // Input 1: SegWit UTXO

    let script_sig = script::Builder::new()
        .push_slice(
            <&PushBytes>::try_from(psbt.inputs[1].redeem_script.as_ref().unwrap().as_bytes())
                .unwrap(),
        )
        .into_script();

    psbt.inputs[1].final_script_sig = Some(script_sig);

    let script_witness = {
        let sigs: Vec<_> = psbt.inputs[1].partial_sigs.values().collect();
        let mut script_witness = Witness::new();
        script_witness.push([]); // Push 0x00 to the stack.
        script_witness.push(&sigs[1].to_vec());
        script_witness.push(&sigs[0].to_vec());
        script_witness.push(psbt.inputs[1].witness_script.clone().unwrap().as_bytes());

        script_witness
    };

    psbt.inputs[1].final_script_witness = Some(script_witness);

    psbt.inputs[1].partial_sigs = BTreeMap::new();
    psbt.inputs[1].sighash_type = None;
    psbt.inputs[1].redeem_script = None;
    psbt.inputs[1].witness_script = None;
    psbt.inputs[1].bip32_derivation = BTreeMap::new();

    psbt
}

#[test]
fn bip371_psbt_workflow() {

    struct Keystore {
        sk: PrivateKey,
        mfp: Fingerprint,
    }

    impl GetKey for Keystore {
        type Error = SignError;
        fn get_key<C: Signing>(&self, key_request: KeyRequest, _secp: &Secp256k1<C>) -> Result<Option<PrivateKey>, Self::Error> {
            match key_request {
                KeyRequest::Bip32((mfp, _)) => {
                    if mfp == self.mfp {
                        Ok(Some(self.sk))
                    } else {
                        Err(SignError::KeyNotFound)
                    }
                }
                _ => Err(SignError::KeyNotFound)
            }
        }
    }

    let secp = &Secp256k1::<secp256k1::All>::gen_new();

    let sk_path = [
        ("dff1c8c2c016a572914b4c5adb8791d62b4768ae9d0a61be8ab94cf5038d7d90", "m/86'/1'/0'/0/0"),
        ("1ede31b0e7e47c2afc65ffd158b1b1b9d3b752bba8fd117dc8b9e944a390e8d9", "m/86'/1'/0'/0/1"),
        ("1fb777f1a6fb9b76724551f8bc8ad91b77f33b8c456d65d746035391d724922a", "m/86'/1'/0'/0/2"),
    ];
    let mfp = "73c5da0a";

    //
    // Step 0: Create P2TR address.
    //

    //m/86'/1'/0'/0/0
    let sk = sk_path[0].0;
    let script1 = create_script_for_taproot(secp, sk);

    //m/86'/1'/0'/0/1
    let sk = sk_path[1].0;
    let script2 = create_script_for_taproot(secp, sk);

    //m/86'/1'/0'/0/2
    let sk = sk_path[2].0;
    let script3 = create_script_for_taproot(secp, sk);

    // use public key of path "m/86'/1'/0'/0/2" as internal key
    let internal_key = priv_to_x_only_pub(secp, sk);

    let tree = create_taproot_tree(secp, script1.clone(), script2.clone(), script3.clone(), internal_key);

    let address = create_p2tr_address(tree.clone());
    assert_eq!("tb1pytee2mxz0f4fkrsqqws2lsgnkp8nrw2atjkjy2n9gahggsphr0gszaxxmv", address.to_string());

    // m/86'/1'/0'/0/7
    let to_address = "tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz";
    let to_address = Address::from_str(to_address).unwrap().assume_checked();

    // key path spend
    {
        //
        // Step 1: create psbt for key path spend.
        //
        let mut psbt_key_path_spend = create_psbt_for_taproot_key_path_spend(address.clone(), to_address.clone(), tree.clone());

        //
        // Step 2: sign psbt.
        //
        let sk: Vec<u8> = Vec::from_hex(sk).expect("valid hex digits");
        let sk = PrivateKey::from_slice(&sk, Network::Testnet).unwrap();
        let keystore = Keystore {
            mfp: Fingerprint::from_str(mfp).unwrap(),
            sk,
        };
        let _ = psbt_key_path_spend.sign(&keystore, secp);

        let sig = "92864dc9e56b6260ecbd54ec16b94bb597a2e6be7cca0de89d75e17921e0e1528cba32dd04217175c237e1835b5db1c8b384401718514f9443dce933c6ba9c87";
        assert_eq!(sig, psbt_key_path_spend.inputs[0].tap_key_sig.unwrap().sig.to_string());

        //
        // Step 3: finalize psbt.
        //
        let final_psbt = finalize_psbt_for_key_path_spend(psbt_key_path_spend);
        let tx = final_psbt.extract_tx().unwrap();

        let tx_id = "5306516f2032d9f34c9f2f6d2b1b8ad2486ef1ba196d8d8d780e59773e48ad6d";
        assert_eq!(tx_id, tx.txid().to_string());

        let tx_bytes = "020000000001013aee4d6b51da574900e56d173041115bd1e1d01d4697a845784cf716a10c98060000000000ffffffff0100190000000000002251202258f2d4637b2ca3fd27614868b33dee1a242b42582d5474f51730005fa99ce8014092864dc9e56b6260ecbd54ec16b94bb597a2e6be7cca0de89d75e17921e0e1528cba32dd04217175c237e1835b5db1c8b384401718514f9443dce933c6ba9c8700000000";
        let tx_hex = serialize_hex(&tx);
        assert_eq!(tx_bytes, tx_hex);
    }

    // script path spend
    {
        // use private key of path "m/86'/1'/0'/0/1" as signing key
        let sk = sk_path[1].0;
        let sk: Vec<u8> = Vec::from_hex(sk).expect("valid hex digits");
        let sk = PrivateKey::from_slice(&sk, Network::Testnet).unwrap();
        let x_only_pubkey = XOnlyPublicKey::from(sk.public_key(secp).inner);
        let signing_key_path = sk_path[1].1;
        let keystore = Keystore {
            mfp: Fingerprint::from_str(mfp).unwrap(),
            sk,
        };

        //
        // Step 1: create psbt for script path spend.
        //
        let mut psbt_script_path_spend = create_psbt_for_taproot_script_path_spend(address.clone(), to_address.clone(), tree.clone(), x_only_pubkey, signing_key_path, script2.clone());

        //
        // Step 2: sign psbt.
        //
        let _ = psbt_script_path_spend.sign(&keystore, secp);

        let sig = "9c1466e1631a58c55fcb8642ce5f7896314f4b565d92c5c80b17aa9abf56d22e0b5e5dcbcfe836bbd7d409491f58aa9e1f68a491ef8f05eef62fb50ffac85727";
        assert_eq!(sig, psbt_script_path_spend.inputs[0].tap_script_sigs.get(&(x_only_pubkey, script2.clone().tapscript_leaf_hash())).unwrap().sig.to_string());

        //
        // Step 3: finalize psbt.
        //
        let final_psbt = finalize_psbt_for_script_path_spend(psbt_script_path_spend);
        let tx = final_psbt.extract_tx().unwrap();

        let tx_id = "a51f723beffc810248809355ba9c9e4b39c6e55c08429f0aeaa79b73f18bc2a6";
        assert_eq!(tx_id, tx.txid().to_string());

        let tx_hex = serialize_hex(&tx);
        let tx_bytes = "0200000000010176a3c94a6b21d742e8ca192130ad10fdfc4c83510cb6baba8572a5fc70677c9d0000000000ffffffff0170170000000000002251202258f2d4637b2ca3fd27614868b33dee1a242b42582d5474f51730005fa99ce803419c1466e1631a58c55fcb8642ce5f7896314f4b565d92c5c80b17aa9abf56d22e0b5e5dcbcfe836bbd7d409491f58aa9e1f68a491ef8f05eef62fb50ffac857270122203058679f6d60b87ef921d98a2a9a1f1e0779dae27bedbd1cdb2f147a07835ac9ac61c1b68df382cad577d8304d5a8e640c3cb42d77c10016ab754caa4d6e68b6cb296d9b9d92a717ebeba858f75182936f0da5a7aecc434b0eebb2dc8a6af5409422ccf87f124e735a592a8ff390a68f6f05469ba8422e246dc78b0b57cd1576ffa98c00000000";
        assert_eq!(tx_bytes, tx_hex);
    }
}

fn create_script_for_taproot(secp: &Secp256k1::<secp256k1::All>, sk: &str) -> ScriptBuf {
    let sk: Vec<u8> = Vec::from_hex(sk).expect("valid hex digits");
    let sk = PrivateKey::from_slice(&sk, Network::Testnet).unwrap();
    let x_only_pubkey = XOnlyPublicKey::from(sk.public_key(secp).inner);
    script::Builder::new()
        .push_slice(x_only_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn priv_to_x_only_pub(secp: &Secp256k1::<secp256k1::All>, sk: &str) -> XOnlyPublicKey {
    let sk: Vec<u8> = Vec::from_hex(sk).expect("valid hex digits");
    let sk = PrivateKey::from_slice(&sk, Network::Testnet).unwrap();
    XOnlyPublicKey::from(sk.public_key(secp).inner)
}

fn create_taproot_tree(secp: &Secp256k1::<secp256k1::All>, script1: ScriptBuf, script2: ScriptBuf, script3: ScriptBuf, internal_key: XOnlyPublicKey) -> TaprootSpendInfo {
    let builder = TaprootBuilder::new();
    let builder = builder.add_leaf(2, script1).unwrap();
    let builder = builder.add_leaf(2, script2).unwrap();
    let builder = builder.add_leaf(1, script3).unwrap();
    builder.finalize(secp, internal_key).unwrap()
}

fn create_p2tr_address(tree: TaprootSpendInfo) -> Address {
    let output_key = tree.output_key();
    Address::p2tr_tweaked(output_key, Network::Testnet)
}

fn create_psbt_for_taproot_key_path_spend(from_address: Address, to_address: Address, tree: TaprootSpendInfo) -> Psbt {

    let send_value = 6400;
    let out_puts = vec![
        TxOut { value: Amount::from_sat(send_value), script_pubkey: to_address.script_pubkey() },
    ];
    let prev_tx_id = "06980ca116f74c7845a897461dd0e1d15b114130176de5004957da516b4dee3a";

    let transaction = Transaction {
        version: Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: prev_tx_id.parse().unwrap(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xFFFFFFFF), // Ignore nSequence.
            witness: Witness::default(),
        }],
        output: out_puts,
    };

    let mut psbt = Psbt::from_unsigned_tx(transaction).unwrap();


    let mfp = "73c5da0a";
    let internal_key_path = "m/86'/1'/0'/0/2";

    let mut origins = BTreeMap::new();
    origins.insert(
        tree.internal_key(),
        (
            vec![],
            (
                Fingerprint::from_str(mfp).unwrap(),
                DerivationPath::from_str(internal_key_path).unwrap(),
            ),
        ),
    );

    let utxo_value = 6588;
    let mut input = Input {
        witness_utxo: {
            let script_pubkey = from_address.script_pubkey();
            Some(TxOut { value: Amount::from_sat(utxo_value), script_pubkey })
        },
        tap_key_origins: origins,
        ..Default::default()
    };
    let ty = PsbtSighashType::from_str("SIGHASH_DEFAULT").unwrap();
    input.sighash_type = Some(ty);
    input.tap_internal_key = Some(tree.internal_key());
    input.tap_merkle_root = tree.merkle_root();
    psbt.inputs = vec![input];
    psbt
}

fn finalize_psbt_for_key_path_spend(mut psbt: Psbt) -> Psbt {
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        input.final_script_witness = Some(script_witness);
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });
    psbt
}

fn create_psbt_for_taproot_script_path_spend(from_address: Address, to_address: Address, tree: TaprootSpendInfo, x_only_pubkey_of_signing_key: XOnlyPublicKey, signing_key_path: &str, use_script: ScriptBuf) -> Psbt {
    let utxo_value = 6280;
    let send_value = 6000;
    let mfp = "73c5da0a";

    let out_puts = vec![
        TxOut { value: Amount::from_sat(send_value), script_pubkey: to_address.script_pubkey() },
    ];
    let prev_tx_id = "9d7c6770fca57285babab60c51834cfcfd10ad302119cae842d7216b4ac9a376";
    let transaction = Transaction {
        version: Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: prev_tx_id.parse().unwrap(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xFFFFFFFF), // Ignore nSequence.
            witness: Witness::default(),
        }],
        output: out_puts,
    };

    let mut psbt = Psbt::from_unsigned_tx(transaction).unwrap();

    let mut origins = BTreeMap::new();
    origins.insert(
        x_only_pubkey_of_signing_key,
        (
            vec![use_script.tapscript_leaf_hash()],
            (
                Fingerprint::from_str(mfp).unwrap(),
                DerivationPath::from_str(signing_key_path).unwrap(),
            ),
        ),
    );

    let mut tap_scripts = BTreeMap::new();
    tap_scripts.insert(
        tree.control_block(&(use_script.clone(), LeafVersion::TapScript)).unwrap(),
        (use_script.clone(), LeafVersion::TapScript),
    );

    let mut input = Input {
        witness_utxo: {
            let script_pubkey= from_address.script_pubkey();
            Some(TxOut { value: Amount::from_sat(utxo_value), script_pubkey })
        },
        tap_key_origins: origins,
        tap_scripts,
        ..Default::default()
    };
    let ty = PsbtSighashType::from_str("SIGHASH_ALL").unwrap();
    input.sighash_type = Some(ty);
    input.tap_internal_key = Some(tree.internal_key());
    input.tap_merkle_root = tree.merkle_root();
    psbt.inputs = vec![input];
    psbt
}


fn finalize_psbt_for_script_path_spend(mut psbt: Psbt) -> Psbt {
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        for (_, signature) in input.tap_script_sigs.iter() {
            script_witness.push(signature.to_vec());
        }
        for (control_block, (script, _)) in input.tap_scripts.iter() {
            script_witness.push(script.to_bytes());
            script_witness.push(control_block.serialize());
        }
        input.final_script_witness = Some(script_witness);
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
        input.tap_script_sigs = BTreeMap::new();
        input.tap_scripts = BTreeMap::new();
        input.tap_key_sig = None;
    });
    psbt
}
