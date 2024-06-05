use crate::utils::FileOrUrl;
use clap::{Args, Subcommand};
use schnorrkel::olaf::simplpedpop::AllMessage;
use schnorrkel::Keypair;
use schnorrkel::PublicKey;
use schnorrkel::SecretKey;
use serde_json::from_str;
use std::fs::File;
use std::io::Write;
use std::{fs, path::Path};

#[derive(Debug, Clone, Subcommand)]
pub enum PalletSubcommand {
    SimplpedpopRound1(Command1),
    SimplpedpopRound2(Command1),
    FrostRound1(Command1),
    FrostRound2(Command2),
    FrostAggregate(Command1),
}

#[derive(Debug, Clone, Args)]
pub struct Command1 {
    threshold: u16,
    files: String,
}

#[derive(Debug, Clone, Args)]
pub struct Command2 {
    files: String,
}

#[derive(Debug, Clone, Args)]
pub struct Command3 {
    call: String,
    files: String,
}

pub async fn run<'a>(subcommand: Option<PalletSubcommand>) -> color_eyre::Result<()> {
    let Some(subcommand) = subcommand else {
        return Ok(());
    };

    match subcommand {
        PalletSubcommand::SimplpedpopRound1(command) => {
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
        PalletSubcommand::SimplpedpopRound2(command) => Ok(()),
        PalletSubcommand::FrostRound1(command) => Ok(()),
        PalletSubcommand::FrostRound2(command) => Ok(()),
        PalletSubcommand::FrostAggregate(command) => Ok(()),
    }
}
