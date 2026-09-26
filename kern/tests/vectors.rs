//! Every layer, checked against bytes dumped from the real bramble-core
//! classes (vectors/vectors.txt, produced by vectors/java/Dump.java).

use briarkern::bdf::Bdf;
use briarkern::crypto::SecretKey;
use briarkern::util::{from_hex, to_hex};
use std::collections::HashMap;

fn vectors() -> HashMap<String, String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/vectors.txt");
    let text = std::fs::read_to_string(path).expect("vectors.txt is missing");
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn key(v: &HashMap<String, String>, name: &str) -> SecretKey {
    let bytes = from_hex(&v[name]).expect("hex");
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    k
}

fn test_key() -> SecretKey {
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = (i + 1) as u8;
    }
    k
}

const INPUT_A: &[u8] = b"briar-vector-input-a";
const INPUT_B: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

#[test]
fn hash_mac_and_derive_key_match() {
    let v = vectors();
    assert_eq!(
        to_hex(&briarkern::crypto::hash("test/LABEL", &[INPUT_A, INPUT_B])),
        v["hash"]
    );
    assert_eq!(to_hex(&briarkern::crypto::hash("", &[])), v["hash_empty"]);
    assert_eq!(
        to_hex(&briarkern::crypto::mac(
            "test/LABEL",
            &test_key(),
            &[INPUT_A, INPUT_B]
        )),
        v["mac"]
    );
    assert_eq!(
        to_hex(&briarkern::crypto::derive_key(
            "test/LABEL",
            &test_key(),
            &[INPUT_A]
        )),
        v["derive_key"]
    );
}

#[test]
fn signatures_match() {
    let v = vectors();
    let seed = key(&v, "sign_seed");
    assert_eq!(
        to_hex(&briarkern::crypto::sign("test/SIGN", INPUT_A, &seed)),
        v["sign"]
    );
    let public = briarkern::crypto::signature_public_key(&seed);
    let signature = from_hex(&v["sign"]).unwrap();
    assert!(briarkern::crypto::verify_signature(
        &signature,
        "test/SIGN",
        INPUT_A,
        &public
    ));
}

#[test]
fn key_agreement_matches() {
    let v = vectors();
    let priv1 = key(&v, "agree_priv_1");
    let priv2 = key(&v, "agree_priv_2");
    let pub1 = key(&v, "agree_pub_1");
    let pub2 = key(&v, "agree_pub_2");
    assert_eq!(to_hex(&briarkern::crypto::agreement_public_key(&priv1)), v["agree_pub_1"]);
    assert_eq!(to_hex(&briarkern::crypto::agreement_public_key(&priv2)), v["agree_pub_2"]);
    assert_eq!(
        to_hex(&briarkern::crypto::agree(&priv1, &pub2).unwrap()),
        v["agree_raw"]
    );
    assert_eq!(
        to_hex(
            &briarkern::crypto::derive_shared_secret("test/SHARED", &pub2, &priv1, &[INPUT_A])
                .unwrap()
        ),
        v["derive_shared"]
    );
    assert!(briarkern::crypto::agree(&priv1, &[0u8; 32]).is_none());
    let _ = pub1;
}

#[test]
fn transport_keys_match() {
    use briarkern::transport::*;
    let v = vectors();
    let priv1 = key(&v, "agree_priv_1");
    let pub1 = key(&v, "agree_pub_1");
    let pub2 = key(&v, "agree_pub_2");
    assert_eq!(is_alice(&pub2, &pub1), v["is_alice_1"] == "true");
    let static_master = derive_static_master_key(&pub2, &priv1, &pub1).unwrap();
    assert_eq!(to_hex(&static_master), v["static_master_key"]);
    let pending_root = derive_handshake_root_key(&static_master, true);
    let contact_root = derive_handshake_root_key(&static_master, false);
    assert_eq!(to_hex(&pending_root), v["pending_root_key"]);
    assert_eq!(to_hex(&contact_root), v["contact_root_key"]);

    // Handshake mode, period 7, we are Alice
    let out = derive_handshake_keys(LAN_TRANSPORT_ID, &pending_root, 7, true);
    assert_eq!(to_hex(&out.tag_key), v["hs_out_tag"]);
    assert_eq!(to_hex(&out.header_key), v["hs_out_header"]);
    let in_curr = derive_handshake_keys(LAN_TRANSPORT_ID, &pending_root, 7, false);
    assert_eq!(to_hex(&in_curr.tag_key), v["hs_in_curr_tag"]);
    assert_eq!(to_hex(&in_curr.header_key), v["hs_in_curr_header"]);
    assert_eq!(
        to_hex(&derive_handshake_keys(LAN_TRANSPORT_ID, &pending_root, 6, false).tag_key),
        v["hs_in_prev_tag"]
    );
    assert_eq!(
        to_hex(&derive_handshake_keys(LAN_TRANSPORT_ID, &pending_root, 8, false).tag_key),
        v["hs_in_next_tag"]
    );

    // Rotation mode, contact added in period 7
    let rot_out = derive_rotation_keys(LAN_TRANSPORT_ID, &contact_root, 7, 7, true);
    assert_eq!(to_hex(&rot_out.tag_key), v["rot_out_tag"]);
    assert_eq!(to_hex(&rot_out.header_key), v["rot_out_header"]);
    let rot_in = derive_rotation_keys(LAN_TRANSPORT_ID, &contact_root, 7, 7, false);
    assert_eq!(to_hex(&rot_in.tag_key), v["rot_in_curr_tag"]);
    assert_eq!(to_hex(&rot_in.header_key), v["rot_in_curr_header"]);
    assert_eq!(
        to_hex(&derive_rotation_keys(LAN_TRANSPORT_ID, &contact_root, 7, 6, false).tag_key),
        v["rot_in_prev_tag"]
    );
    assert_eq!(
        to_hex(&derive_rotation_keys(LAN_TRANSPORT_ID, &contact_root, 7, 8, false).tag_key),
        v["rot_in_next_tag"]
    );

    assert_eq!(to_hex(&encode_tag(&test_key(), 4, 3)), v["tag_v4_s3"]);
}

#[test]
fn encrypted_stream_matches() {
    use briarkern::stream::StreamWriter;
    use briarkern::transport::StreamKeys;
    let v = vectors();
    let mut nonce = [0u8; 24];
    for i in 0..24 {
        nonce[i] = 0x10 + i as u8;
    }
    let mut frame_key = [0u8; 32];
    for i in 0..32 {
        frame_key[i] = 0xa0u8.wrapping_add(i as u8);
    }
    let keys = StreamKeys {
        tag_key: test_key(),
        header_key: test_key(),
    };
    let mut out: Vec<u8> = Vec::new();
    {
        let mut writer = StreamWriter::with_fixed_randomness(&mut out, &keys, 5, nonce, frame_key);
        writer.write_raw_frame(INPUT_A, 0, false).unwrap();
        writer.write_raw_frame(INPUT_B, 3, true).unwrap();
    }
    assert_eq!(to_hex(&out), v["stream"]);
}

#[test]
fn stream_round_trips() {
    use briarkern::stream::{StreamReader, StreamWriter};
    use briarkern::transport::{encode_tag, StreamKeys, PROTOCOL_VERSION, TAG_LEN};
    use std::io::{Read, Write};
    let keys = StreamKeys {
        tag_key: test_key(),
        header_key: test_key(),
    };
    let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    let mut wire: Vec<u8> = Vec::new();
    {
        let mut writer = StreamWriter::new(&mut wire, &keys, 9);
        writer.write_all(&payload).unwrap();
        writer.send_end_of_stream().unwrap();
    }
    assert_eq!(&wire[..TAG_LEN], &encode_tag(&keys.tag_key, PROTOCOL_VERSION, 9)[..]);
    let mut reader = StreamReader::new(&wire[TAG_LEN..], keys.header_key, 9);
    let mut got = Vec::new();
    reader.read_to_end(&mut got).unwrap();
    assert_eq!(got, payload);
}

#[test]
fn bdf_encodings_match() {
    let v = vectors();
    assert_eq!(
        to_hex(&briarkern::bdf::to_bytes(&Bdf::List(vec![
            Bdf::Int(1),
            Bdf::Str("hallo".into()),
            Bdf::Raw(vec![1, 2, 3])
        ]))),
        v["bdf_simple"]
    );
    let nested = Bdf::List(vec![
        Bdf::List(vec![
            Bdf::Int(0),
            Bdf::Int(127),
            Bdf::Int(128),
            Bdf::Int(32768),
            Bdf::Int(-1),
            Bdf::Int(2147483648),
        ]),
        Bdf::dict(vec![
            ("b", Bdf::Bool(true)),
            ("a", Bdf::Null),
            ("c", Bdf::Str("text".into())),
        ]),
        Bdf::List(vec![]),
    ]);
    assert_eq!(to_hex(&briarkern::bdf::to_bytes(&nested)), v["bdf_nested"]);
    assert_eq!(
        to_hex(&briarkern::bdf::to_bytes(&Bdf::List(vec![Bdf::Str(
            "Grüße, Briar".into()
        )]))),
        v["bdf_text"]
    );
    // And back again
    let raw = from_hex(&v["bdf_nested"]).unwrap();
    assert_eq!(briarkern::bdf::from_bytes(&raw).unwrap(), nested);
}

#[test]
fn identifiers_match() {
    let v = vectors();
    let group = briarkern::ids::group_id("org.briarproject.briar.messaging", 0, &[9, 8, 7]);
    assert_eq!(to_hex(&group), v["group_id"]);
    assert_eq!(
        to_hex(&briarkern::ids::local_group_id(
            "org.briarproject.bramble.versioning",
            0
        )),
        v["group_id_local_versioning"]
    );
    let body = b"hallo welt";
    assert_eq!(
        to_hex(&briarkern::ids::message_id(&group, 1700000000000, body)),
        v["message_id"]
    );
    assert_eq!(
        to_hex(&briarkern::ids::raw_message(&group, 1700000000000, body)),
        v["message_raw"]
    );
    let author_pub = from_hex(&v["author_pub"]).unwrap();
    assert_eq!(
        to_hex(&briarkern::ids::author_id("Sebastian", &author_pub)),
        v["author_id"]
    );
}

#[test]
fn handshake_and_exchange_match() {
    let v = vectors();
    let our_static_priv = key(&v, "hs_priv_0");
    let our_static_pub = key(&v, "hs_pub_0");
    let their_static_pub = key(&v, "hs_pub_1");
    let our_eph_priv = key(&v, "hs_priv_2");
    let our_eph_pub = key(&v, "hs_pub_2");
    let their_eph_pub = key(&v, "hs_pub_3");
    for (alice, name) in [(true, "hs_master_alice"), (false, "hs_master_bob")] {
        let master = briarkern::handshake::derive_master_key(
            &their_static_pub,
            &their_eph_pub,
            &our_static_priv,
            &our_static_pub,
            &our_eph_priv,
            &our_eph_pub,
            alice,
        )
        .unwrap();
        assert_eq!(to_hex(&master), v[name], "master key for alice={}", alice);
    }
    let master = key(&v, "hs_master_alice");
    assert_eq!(
        to_hex(&briarkern::handshake::prove_ownership(&master, true)),
        v["hs_proof_alice"]
    );
    assert_eq!(
        to_hex(&briarkern::handshake::prove_ownership(&master, false)),
        v["hs_proof_bob"]
    );
    assert!(briarkern::handshake::verify_ownership(
        &master,
        true,
        &from_hex(&v["hs_proof_alice"]).unwrap()
    ));

    assert_eq!(
        to_hex(&briarkern::exchange::derive_header_key(&master, true)),
        v["ex_header_alice"]
    );
    assert_eq!(
        to_hex(&briarkern::exchange::derive_header_key(&master, false)),
        v["ex_header_bob"]
    );
    let seed = key(&v, "sign_seed");
    let signature = briarkern::exchange::sign_nonce(&seed, &master, true);
    assert_eq!(to_hex(&signature), v["ex_sig_alice"]);
    let public = briarkern::crypto::signature_public_key(&seed);
    assert!(briarkern::exchange::verify_nonce(&public, &master, true, &signature));
}

#[test]
fn links_match() {
    let v = vectors();
    let public = key(&v, "hs_pub_0");
    let link = briarkern::ids::handshake_link(&public);
    assert_eq!(link, v["link"]);
    assert_eq!(briarkern::ids::parse_handshake_link(&link), Some(public));
    // Prefix optional, surrounding text ignored -- as in Briar
    let bare = link.trim_start_matches("briar://").to_string();
    assert_eq!(briarkern::ids::parse_handshake_link(&bare), Some(public));
    assert_eq!(
        briarkern::ids::parse_handshake_link(&format!("davor {} danach", link)),
        Some(public)
    );
    assert_eq!(briarkern::ids::parse_handshake_link("briar://kartoffel"), None);
    assert_eq!(
        to_hex(&briarkern::ids::pending_contact_id(&public)),
        v["link_pending_id"]
    );
}
