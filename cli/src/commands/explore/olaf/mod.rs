use crate::commands::explore::pallets::{
    calls_to_string, get_calls_enum_type, value_into_composite,
};
use crate::utils::{parse_string_into_scale_value, FileOrUrl};
use clap::{Args, Subcommand};
use indoc::formatdoc;
use scale_value::Value;
use schnorrkel::olaf::frost::{aggregate, SigningCommitments, SigningNonces, SigningPackage};
use schnorrkel::olaf::simplpedpop::{AllMessage, SPPOutputMessage};
use schnorrkel::{olaf::SigningKeypair, Keypair, PublicKey, SecretKey};
use serde_json::from_str;
use std::fs::File;
use std::io::Write;
use std::{fs, path::Path};
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::book::usage;
use subxt::config::polkadot::PolkadotExtrinsicParamsBuilder;
use subxt::utils::{AccountId32, MultiAddress, MultiSignature};
use subxt::{tx, Metadata, OnlineClient, PolkadotConfig};
use subxt_metadata::PalletMetadata;
use subxt_signer::sr25519;

const CONTEXT: &[u8] = b"substrate";

#[derive(Debug, Clone, Subcommand)]
pub enum OlafSubcommand {
    SimplpedpopRound1(SimplpedpopRound1Subcommand),
    SimplpedpopRound2(SimplpedpopRound2Subcommand),
    FrostRound1(SimplpedpopRound2Subcommand),
    FrostRound2(FrostRound2Subcommand),
    FrostAggregate(FrostRound2Subcommand),
}

#[derive(Debug, Clone, Args)]
pub struct SimplpedpopRound1Subcommand {
    threshold: u16,
    files: String,
}

#[derive(Debug, Clone, Args)]
pub struct SimplpedpopRound2Subcommand {
    files: String,
}

#[derive(Debug, Clone, Args)]
pub struct FrostRound1Subcommand {
    //call: String,
    files: String,
}

#[derive(Debug, Clone, Args)]
pub struct FrostRound2Subcommand {
    files: String,
    pallet: String,
    call: String,
    #[clap(required = false)]
    trailing_args: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct FrostAggregateSubcommand {
    files: String,
    pallet: String,
    call: String,
    #[clap(required = false)]
    trailing_args: Vec<String>,
}

pub async fn run<'a>(
    subcommand: Option<OlafSubcommand>,
    //pallet_metadata: PalletMetadata<'a>,
    metadata: &'a Metadata,
    file_or_url: FileOrUrl,
    output: &mut impl std::io::Write,
) -> color_eyre::Result<()> {
    //let Some(subcommand) = subcommand else {
    //return Ok(());
    //};

    match subcommand.unwrap() {
        OlafSubcommand::SimplpedpopRound1(command) => {
            let secret_key_string =
                fs::read_to_string(Path::new(&command.files).join("contributor_secret_key.json"))
                    .unwrap();

            let secret_key_bytes: Vec<u8> = from_str(&secret_key_string).unwrap();

            let keypair = Keypair::from(SecretKey::from_bytes(&secret_key_bytes).unwrap());

            let recipients_string =
                fs::read_to_string(Path::new(&command.files).join("recipients.json")).unwrap();

            let recipients_bytes: Vec<Vec<u8>> = from_str(&recipients_string).unwrap();

            let recipients: Vec<PublicKey> = recipients_bytes
                .iter()
                .map(|recipient| PublicKey::from_bytes(recipient).unwrap())
                .collect();

            let all_message: AllMessage = keypair
                .simplpedpop_contribute_all(command.threshold, recipients)
                .unwrap();

            let all_message_bytes: Vec<u8> = all_message.to_bytes();

            let all_message_vec: Vec<Vec<u8>> = vec![all_message_bytes];

            let all_message_json = serde_json::to_string_pretty(&all_message_vec).unwrap();

            let mut all_message_file =
                File::create(Path::new(&command.files).join("all_messages.json")).unwrap();

            all_message_file
                .write_all(&all_message_json.as_bytes())
                .unwrap();

            Ok(())
        }
        OlafSubcommand::SimplpedpopRound2(command) => {
            let secret_key_string =
                fs::read_to_string(Path::new(&command.files).join("recipient_secret_key.json"))
                    .unwrap();

            let secret_key_bytes: Vec<u8> = from_str(&secret_key_string).unwrap();

            let keypair = Keypair::from(SecretKey::from_bytes(&secret_key_bytes).unwrap());

            let all_messages_string =
                fs::read_to_string(Path::new(&command.files).join("all_messages.json")).unwrap();

            let all_messages_bytes: Vec<Vec<u8>> = from_str(&all_messages_string).unwrap();

            let all_messages: Vec<AllMessage> = all_messages_bytes
                .iter()
                .map(|all_message| AllMessage::from_bytes(all_message).unwrap())
                .collect();

            let simplpedpop = keypair.simplpedpop_recipient_all(&all_messages).unwrap();

            let spp_output = simplpedpop.0.clone();

            let output_json = serde_json::to_string_pretty(&spp_output.to_bytes()).unwrap();

            let mut output_file =
                File::create(Path::new(&command.files).join("spp_output.json")).unwrap();

            output_file.write_all(&output_json.as_bytes()).unwrap();

            let signing_share = simplpedpop.1;

            let signing_share_json =
                serde_json::to_string_pretty(&signing_share.to_bytes().to_vec()).unwrap();

            let mut signing_share_file =
                File::create(Path::new(&command.files).join("signing_share.json")).unwrap();

            signing_share_file
                .write_all(&signing_share_json.as_bytes())
                .unwrap();

            let threshold_public_key = simplpedpop.0.spp_output().threshold_public_key();

            let threshold_public_key_json =
                serde_json::to_string_pretty(&threshold_public_key.0.to_bytes()).unwrap();

            let mut threshold_public_key_file =
                File::create(Path::new(&command.files).join("threshold_public_key.json")).unwrap();

            threshold_public_key_file
                .write_all(threshold_public_key_json.as_bytes())
                .unwrap();

            Ok(())
        }
        OlafSubcommand::FrostRound1(command) => {
            let signing_share_string =
                fs::read_to_string(Path::new(&command.files).join("signing_share.json")).unwrap();

            let signing_share_bytes: Vec<u8> = from_str(&signing_share_string).unwrap();

            let signing_share = SigningKeypair::from_bytes(&signing_share_bytes).unwrap();

            let (signing_nonces, signing_commitments) = signing_share.commit();

            let signing_nonces_json =
                serde_json::to_string_pretty(&signing_nonces.to_bytes().to_vec()).unwrap();

            let mut signing_nonces_file =
                File::create(Path::new(&command.files).join("signing_nonces.json")).unwrap();

            signing_nonces_file
                .write_all(&signing_nonces_json.as_bytes())
                .unwrap();

            let signing_commitments_vec = vec![signing_commitments.to_bytes().to_vec()];

            let signing_commitments_json =
                serde_json::to_string_pretty(&signing_commitments_vec).unwrap();

            let mut signing_commitments_file =
                File::create(Path::new(&command.files).join("signing_commitments.json")).unwrap();

            signing_commitments_file
                .write_all(&signing_commitments_json.as_bytes())
                .unwrap();

            Ok(())
        }
        OlafSubcommand::FrostRound2(command) => {
            let signing_commitments_string =
                fs::read_to_string(Path::new(&command.files).join("signing_commitments.json"))
                    .unwrap();

            let signing_commitments_bytes: Vec<Vec<u8>> =
                from_str(&signing_commitments_string).unwrap();

            let signing_commitments: Vec<SigningCommitments> = signing_commitments_bytes
                .iter()
                .map(|signing_commitments| {
                    SigningCommitments::from_bytes(signing_commitments).unwrap()
                })
                .collect();

            let signing_nonces_string =
                fs::read_to_string(Path::new(&command.files).join("signing_nonces.json")).unwrap();

            let signing_nonces_bytes: Vec<u8> = from_str(&signing_nonces_string).unwrap();

            let signing_nonces = SigningNonces::from_bytes(&signing_nonces_bytes).unwrap();

            let signing_share_string =
                fs::read_to_string(Path::new(&command.files).join("signing_share.json")).unwrap();

            let signing_share_bytes: Vec<u8> = from_str(&signing_share_string).unwrap();

            let signing_share = SigningKeypair::from_bytes(&signing_share_bytes).unwrap();

            let output_string =
                fs::read_to_string(Path::new(&command.files).join("spp_output.json")).unwrap();

            let output_bytes: Vec<u8> = from_str(&output_string).unwrap();

            let spp_output = SPPOutputMessage::from_bytes(&output_bytes).unwrap();

            let threshold_public_key_string =
                fs::read_to_string(Path::new(&command.files).join("threshold_public_key.json"))
                    .unwrap();

            let threshold_public_key_bytes: Vec<u8> =
                from_str(&threshold_public_key_string).unwrap();

            let threshold_public_key = PublicKey::from_bytes(&threshold_public_key_bytes).unwrap();

            let client = OnlineClient::<PolkadotConfig>::new().await?;

            let rpc_client = RpcClient::from_url("ws://127.0.0.1:9944").await?;

            let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client);

            //let call =
            //subxt::dynamic::tx("System", "remark", vec![Value::from_bytes("Hello there")]);

            let account_id = AccountId32(threshold_public_key.to_bytes());

            let nonce = legacy_rpc.system_account_next_index(&account_id).await?;

            let params = PolkadotExtrinsicParamsBuilder::new().nonce(nonce).build();

            // collect all the trailing arguments into a single string that is later into a scale_value::Value
            let trailing_args = command.trailing_args.join(" ");

            let pallet_name = command.pallet;

            // parse scale_value from trailing arguments and try to create an unsigned extrinsic with it:
            let value = parse_string_into_scale_value(&trailing_args)?;
            let value_as_composite = value_into_composite(value);
            //let offline_client = mocked_offline_client(metadata.clone());

            let pallet_metadata = metadata
                .pallets()
                .find(|e| e.name().eq_ignore_ascii_case(&pallet_name))
                .unwrap();

            // get the enum that stores the possible calls:
            let (calls_enum_type_def, _calls_enum_type) =
                get_calls_enum_type(pallet_metadata, metadata.types())?;

            let usage = || {
                let calls = calls_to_string(calls_enum_type_def, &pallet_name);
                formatdoc! {"
                Usage:
                    subxt explore pallet {pallet_name} calls <CALL>
                        explore a specific call of this pallet

                {calls}
                "}
            };

            // if no call specified, show user the calls to choose from:
            //let Some(call_name) = command.call else {
            //writeln!(output, "{}", usage())?;
            //return Ok(());
            //};

            let call_name = command.call;

            let call = tx::dynamic(pallet_name, call_name, value_as_composite);

            let partial_tx = client.tx().create_partial_signed_offline(&call, params)?;

            let payload = partial_tx.signer_payload();

            let signing_package = signing_share
                .sign(
                    CONTEXT.to_vec(),
                    payload,
                    spp_output.spp_output(),
                    signing_commitments,
                    &signing_nonces,
                )
                .unwrap();

            let signing_packages_vec = vec![signing_package.to_bytes()];

            let signing_package_json = serde_json::to_string_pretty(&signing_packages_vec).unwrap();

            let mut signing_package_file =
                File::create(Path::new(&command.files).join("signing_packages.json")).unwrap();

            signing_package_file
                .write_all(&signing_package_json.as_bytes())
                .unwrap();

            Ok(())
        }
        OlafSubcommand::FrostAggregate(command) => {
            let threshold_public_key_string =
                fs::read_to_string(Path::new(&command.files).join("threshold_public_key.json"))
                    .unwrap();

            let threshold_public_key_bytes: Vec<u8> =
                from_str(&threshold_public_key_string).unwrap();

            let threshold_public_key = PublicKey::from_bytes(&threshold_public_key_bytes).unwrap();

            let account_id = AccountId32(threshold_public_key.to_bytes());

            println!("pk: {:?}", account_id.to_string());

            let signing_packages_string =
                fs::read_to_string(Path::new(&command.files).join("signing_packages.json"))
                    .unwrap();

            let signing_packages_bytes: Vec<Vec<u8>> = from_str(&signing_packages_string).unwrap();

            let signing_packages: Vec<SigningPackage> = signing_packages_bytes
                .iter()
                .map(|signing_commitments| SigningPackage::from_bytes(signing_commitments).unwrap())
                .collect();

            let group_signature = aggregate(&signing_packages).unwrap();

            let signature_json =
                serde_json::to_string_pretty(&group_signature.to_bytes().to_vec()).unwrap();

            let mut signature_file =
                File::create(Path::new(&command.files).join("signature.json")).unwrap();

            signature_file
                .write_all(&signature_json.as_bytes())
                .unwrap();

            let client = OnlineClient::<PolkadotConfig>::new().await?;

            // TODO: user input
            let rpc_client = RpcClient::from_url("ws://127.0.0.1:9944").await?;

            let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client);

            let nonce = legacy_rpc.system_account_next_index(&account_id).await?;

            let params = PolkadotExtrinsicParamsBuilder::new().nonce(nonce).build();

            //let call =
            //subxt::dynamic::tx("System", "remark", vec![Value::from_bytes("Hello there")]);

            // collect all the trailing arguments into a single string that is later into a scale_value::Value
            let trailing_args = command.trailing_args.join(" ");

            let pallet_name = command.pallet;

            // parse scale_value from trailing arguments and try to create an unsigned extrinsic with it:
            let value = parse_string_into_scale_value(&trailing_args)?;
            let value_as_composite = value_into_composite(value);
            //let offline_client = mocked_offline_client(metadata.clone());

            let pallet_metadata = metadata
                .pallets()
                .find(|e| e.name().eq_ignore_ascii_case(&pallet_name))
                .unwrap();

            // get the enum that stores the possible calls:
            let (calls_enum_type_def, _calls_enum_type) =
                get_calls_enum_type(pallet_metadata, metadata.types())?;

            let usage = || {
                let calls = calls_to_string(calls_enum_type_def, &pallet_name);
                formatdoc! {"
                Usage:
                    subxt explore pallet {pallet_name} calls <CALL>
                        explore a specific call of this pallet

                {calls}
                "}
            };

            // if no call specified, show user the calls to choose from:
            //let Some(call_name) = command.call else {
            //writeln!(output, "{}", usage())?;
            //return Ok(());
            //};

            let call_name = command.call;

            let call = tx::dynamic(pallet_name, call_name, value_as_composite);

            let partial_tx = client.tx().create_partial_signed_offline(&call, params)?;

            let signature = sr25519::Signature(group_signature.to_bytes());

            let public_key: MultiAddress<AccountId32, _> =
                AccountId32(threshold_public_key.to_bytes()).into();

            let tx = partial_tx.sign_with_address_and_signature(
                &public_key,
                &MultiSignature::Sr25519(signature.0),
            );

            tx.submit().await?;

            Ok(())
        }
    }
}
