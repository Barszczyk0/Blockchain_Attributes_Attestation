# Blockchain Attributes Attestation
# Introduction
This project demostrate blockchain-based attestation system for managing attributes.

# Description
## Project assumptions

- **Entity**: Issuing Authority (e.g., local government) – issues the credential.
- **User**: Citizen – stores the credential.
- **Verifier**: Third party – verifies the authenticity of the credential.
- **Blockchain**: Credentials ledger - Used for registering hashes/digests of credentials (not personal data).

## Key Actors
| Role    | Description |
| :--------: | :-------: |
| Issuer (QTSP) | A trusted authority (e.g., government agency) that issues attribute credentials to users. |
| Holder | The end user (citizen or company) who holds the Verifiable Credential |
| Verifier | A relying party (e.g., service provider) that needs to verify a user's attribute|
| Blockchain Network | A distributed ledger used to anchor cryptographic proofs (e.g., hashes of credentials), not to store personal data. |

## Structure graph
```mermaid
flowchart LR
    Blockchain --Hashing&Signing --- Block0["Block"]

    Block0["Block"] --- new_credentials["NewCredentialsList"]
    Block0 --- revoked_credentials["RevokedCredentialsList"]
    Block0 --- timestamp["Timestamp"]
    Block0 --- hash["Current Block Hash"]
    Block0 --- previous_hash["Previous Block Hash"]
    Block0 --- signer["Signer"]
    Block0 --- signature["SignedCredential"]

    new_credentials["NewCredentialsList"] --- SignedCredential0["SignedCredential"]
    new_credentials --- SignedCredential1["SignedCredential"]
    new_credentials --- SignedCredential2["..."]

    revoked_credentials["RevokedCredentialsList"] --- SignedCredential3["SignedCredential"]
    revoked_credentials --- SignedCredential4["SignedCredential"]
    revoked_credentials --- SignedCredential5["..."]

    SignedCredential0 --Hashing&Signing --- Credential0["Credential"]
    Credential0 --- Uuid0["Uuid"]
    Credential0 --- Attribute0["Attribute"]
    Credential0 --- Issuer0["Issuer"]
    Credential0 --- Subject0["Subject"]
    Credential0 --- ValidDuration0["ValidDuration"]

    SignedCredential3 --Revoking&Hashing&Signing --- Credential1["Credential"]
    Credential1 --- Uuid1["Uuid"]
    Credential1 --- Attribute1["Attribute"]
    Credential1 --- Issuer1["Issuer"]
    Credential1 --- Subject1["Subject"]
    Credential1 --- ValidDuration1["ValidDuration"]
```

# Runnging project
## Building project
```
cargo build --all-features
```

## Testing project
```
cargo test
// OR
cargo tarpaulin --skip-clean
```

## Runing program
```
attributes_attestation --help
```

### Blockchain initialization
```
attributes_attestation blockchain init
```
|![](Images/blockchaininit.png)|
|:--:| 
| *Blockchain initialization* |

### Issuer creation 
```
attributes_attestation issuers add <issuer_name>
```

|![](Images/addissuer.png)|
|:--:| 
| *Issuer creation* |


### Subject creation
```
attributes_attestation subjects add <name> <surname>
```

|![](Images/addsubject.png)|
|:--:| 
| *Subject creation* |

### Credential creation
```
attributes_attestation credentials add <issuer_index> <subject_index> <credential_name> <credential_value> <from> <to>
```

|![](Images/addsubject.png)|
|:--:| 
| *Credential creation* |


### Block creation
```
attributes_attestation block new <issuer_index>
attributes_attestation block add <credential_index>
```

|![](Images/addblock.png)|
|:--:| 
| *Block creation* |


### Adding  block to blockchain (finalize)
```
attributes_attestation block finalize
```

|![](Images/finalizeblock.png)|
|:--:| 
| *Adding  block to blockchain* |

### Credential verification
```
attributes_attestation blockchain verify <credential_index>
```

|![](Images/verification.png)|
|:--:| 
| *Credential verification* |


### Credential revokation
```
attributes_attestation blockchain revoke <credential_index>
```

### List contents of Issuer, Subject, Credential, Block, Blockchain
```
attributes_attestation issuers list
attributes_attestation subjects list
attributes_attestation credentials list
attributes_attestation block display
attributes_attestation blockchain display
```

