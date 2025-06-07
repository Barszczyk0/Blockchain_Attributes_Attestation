use attributes_attestation::blockchain::{Block, Blockchain};
use attributes_attestation::credential::{Attribute, Credential, Issuer, Subject, ValidDuration};
use chrono::NaiveDate;

fn main() {
    let (issuer_a, issuer_a_signing) = Issuer::new("Issuer A".to_owned());
    let (issuer_b, issuer_b_signing) = Issuer::new("Issuer B".to_owned());
    let subject_a = Subject::new("Robert".to_owned(), "Lewnadowski".to_owned());
    let subject_b = Subject::new("Jan".to_owned(), "Kowalski".to_owned());
    let mut blockchain = Blockchain::new();
    let attribute = Attribute::new("Prawo jazdy".to_owned(), "Tak".to_owned(), "".to_owned());
    let valid = ValidDuration::new(
        NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        NaiveDate::from_ymd_opt(2030, 12, 31),
    );
    let mut block = Block::new(issuer_a.clone());
    let mut credential = Credential::new(attribute, issuer_a.clone(), subject_a.clone(), valid);
    let signed = credential.sign(&issuer_a_signing, false);
    credential.print_json();
    block.add_credential(signed, false);
    blockchain.add_block(block, &issuer_a_signing);
    let mut block = Block::new(issuer_b);
    let signed = credential.sign(&issuer_a_signing, true);
    block.add_credential(signed, true);
    blockchain.add_block(block, &issuer_b_signing);
    let result = blockchain.check_credential(&credential);
    println!("Check result: {result}");
    blockchain.print_json();
}
