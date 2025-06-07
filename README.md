# Blockchain Attributes Attestation

# Introduction

# Runnging project
## Building project
```
cargo build
```

## Runing program
```
cargo run
```

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
### Full Graph
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
