# RUXMSG/1

Terminal Messaging Protocol
Cryptographic & Systems Design Specification
Protocol: RUXMSG/1
Specification: RUXMSG/1 Normative Baseline, Version 1.0
Status: Normative Wire Specification — Implementation Gate
Architecture: Peer-to-Peer E2EE
Primary Transport: Tailscale
Interface: Terminal / CLI

## 1. Purpose, Scope, and Security Model

RUXMSG is a terminal-oriented peer-to-peer messaging protocol designed for communication between explicitly trusted peers.
RUXMSG provides:

application-layer end-to-end encryption
persistent cryptographic peer identities
human-verifiable first-contact authentication
ephemeral X25519 session establishment
session-level forward secrecy
symmetric per-message key ratcheting
automatic cryptographic session rekeying
replay protection
bounded reordering support
deterministic wire encoding
bounded resource consumption
transport independence
terminal-native operation
RUXMSG does not require a central server.
The underlying transport is considered untrusted from the perspective of RUXMSG.
A transport MAY:

observe traffic
capture traffic
replay frames
reorder frames
duplicate frames
drop frames
modify frames
inject frames
disconnect and reconnect
RUXMSG security MUST NOT depend on the confidentiality or authentication properties of the transport.
Tailscale is therefore a transport implementation, not a RUXMSG trust mechanism.
A Tailscale IP address, hostname, username, device name, or network identity MUST NOT be treated as cryptographic proof of peer identity.
RUXMSG's security boundary is:

Persistent Ed25519 Identity
        │
        ▼
Fresh X25519 Session
        │
        ▼
Authenticated Transcript
        │
        ├── Human SAS verification
        │
        ▼
HKDF-SHA-256 Key Schedule
        │
        ▼
Per-Direction Symmetric Chains
        │
        ▼
Per-Message Keys
        │
        ▼
ChaCha20-Poly1305
        │
        ▼
Encrypted DATA
RUXMSG/1 does not claim:

anonymity
metadata confidentiality
complete traffic-analysis resistance
deniability
full post-compromise security
protection against a compromised endpoint
protection against persistent malware controlling an endpoint
automatic recovery from lost identity keys
trust in the underlying transport
2. Cryptographic Suite
RUXMSG/1 uses the following fixed cryptographic suite:
FunctionAlgorithmPersistent identityEd25519Ephemeral key agreementX25519HashSHA-256KDFHKDF-SHA-256Message AEADChaCha20-Poly1305Authentication confirmationHMAC-SHA-256Structured encodingDeterministic CBORSAS dictionaryBIP-0039 English word list
Implementations MUST use established, reviewed cryptographic libraries.
Implementations MUST NOT implement cryptographic primitives from scratch.

2.1 Ed25519 Identity
Each installation generates one persistent Ed25519 keypair:

IdentityPrivateKey
IdentityPublicKey
The private key MUST remain local to the installation.
The public key is the persistent RUXMSG identity.
A RUXMSG identity is exactly one 32-byte Ed25519 public key.
Ed25519 is used exclusively for persistent identity authentication and signatures.
Ed25519 keys MUST NOT be directly reused as X25519 keys.

2.2 X25519 Sessions
Every cryptographic session generates a fresh X25519 keypair.
The shared secret is:

DH = X25519(
    LocalEphemeralPrivateKey,
    RemoteEphemeralPublicKey
)
Implementations MUST reject an all-zero X25519 shared secret.
Ephemeral private keys MUST NOT be reused across independent cryptographic sessions.
After a cryptographic session is destroyed, its ephemeral private material SHOULD be securely erased.

2.3 HKDF
RUXMSG uses HKDF-SHA-256.
All protocol-specific HKDF labels MUST use the domain:

RUXMSG/1/
This provides domain separation between independently derived values.
3. Identity and Trust Model
The cryptographic identity of a peer is:

PeerIdentity = Ed25519PublicKey
Human-readable metadata is associated with the identity but does not define it.
Example:

peer:
    name: alice
    identity_key: <32-byte Ed25519 public key>
    trust_state: TRUSTED
    first_seen: `timestamp`
A hostname or network address MUST NOT replace the identity key.

3.1 Trust States
Implementations MUST support at least:

UNKNOWN
TRUSTED
REVOKED
REPLACED
An identity MUST NOT become TRUSTED merely because its public key was received.

3.2 First Contact
First contact establishes both:

possession of the same authenticated ephemeral session
ownership of the presented persistent identities
The sequence is:

Identity exchange
        ↓
Fresh X25519 exchange
        ↓
Fresh handshake nonces
        ↓
Canonical transcript
        ↓
TranscriptHash
        ↓
SAS
        ↓
Human verification
        ↓
Ed25519 transcript signatures
        ↓
Session key derivation
        ↓
Session confirmation
        ↓
Trust enrollment
        ↓
ACTIVE
A first-contact identity becomes trusted only after:

the X25519 handshake succeeds
the SAS is independently verified
the appropriate Ed25519 signature validates
session confirmation succeeds
An SAS mismatch MUST abort the handshake.

3.3 Previously Trusted Identities
After an identity has been explicitly trusted, future sessions do not require human SAS verification during normal operation.
The trusted Ed25519 identity MUST authenticate every subsequent session through a signature over the new session transcript.
The receiver MUST verify that the signing identity exactly matches the stored trusted identity.
4. Handshake, Transcript, and SAS
4.1 Handshake Nonces
Each participant generates a fresh cryptographically random 128-bit nonce:

InitiatorNonce
ResponderNonce
Nonces MUST be generated using a CSPRNG.
They MUST be unique with overwhelming probability.

4.2 Handshake Transcript
The transcript MUST contain all security-relevant handshake inputs.
At minimum:

ProtocolVersion
CipherSuite
HandshakeType
InitiatorRole
ResponderRole
PreviousSessionID
InitiatorIdentityPublicKey
ResponderIdentityPublicKey
InitiatorEphemeralPublicKey
ResponderEphemeralPublicKey
InitiatorNonce
ResponderNonce
PreviousSessionID is zero/absent for an initial session and contains the existing session identifier during rekeying.
The transcript MUST be encoded using deterministic CBOR.
The transcript hash is:

TranscriptHash =
    SHA-256(
        "RUXMSG/1/TRANSCRIPT" ||
        LengthDelimitedTranscript
    )
The transcript encoding MUST be unambiguous.
Variable-length fields MUST be represented using explicit lengths or CBOR's deterministic structure.
Implementations MUST NOT construct security transcripts through ambiguous raw concatenation.

4.3 SAS
RUXMSG/1 defines a three-word Short Authentication String.
The SAS dictionary is the exact BIP-0039 English word list containing 2048 words in its specified order. The pinned artifact is `english.txt` from the Bitcoin BIPs repository at `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt`, containing exactly 2048 LF-delimited lowercase ASCII words. Its SHA-256 is `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. Implementations MUST verify this artifact before using it.
RUXMSG uses only the ordered word list.
The BIP-0039 mnemonic checksum and mnemonic-generation procedure are not used.
Let:

H = TranscriptHash
The first 33 bits of H are divided into three consecutive 11-bit values:

W0 = bits  0..10
W1 = bits 11..21
W2 = bits 22..32
Bits are interpreted most-significant-bit first.
Therefore:

H[0] bit 7 = bit 0
H[0] bit 6 = bit 1
...
H[1] bit 7 = bit 8
...
Equivalently:

S =
    (H[0] << 25) |
    (H[1] << 17) |
    (H[2] << 9)  |
    (H[3] << 1)  |
    (H[4] >> 7)
Only the first 33 bits are significant.
Each 11-bit value directly indexes the 2048-word dictionary:

WORD[W0]
WORD[W1]
WORD[W2]
The SAS is:

WORD[W0] WORD[W1] WORD[W2]
Because:

2048 = 2^11
there is no modulo operation and therefore no modulo bias.
The SAS contains 33 bits of authentication information.
A randomly incorrect session has probability:

1 / 2^33
of producing the same SAS.
The implementation MUST display all three words.

4.4 Human Verification
The terminal MUST clearly identify the value as an SAS.
Example:

SHORT AUTHENTICATION STRING

APPLE HORSE STAPLE
The displayed value is derived from the current transcript.
Users MUST compare the SAS through an independent human channel.
If the values differ:

ABORT
DESTROY EPHEMERAL SESSION STATE
DO NOT TRUST IDENTITY
The implementation MUST NOT silently continue.
5. Identity Authentication and Session Key Establishment
After the transcript has been constructed, each peer authenticates the transcript with its persistent identity key.
The initiator computes:

Sig_I =
    Ed25519.Sign(
        InitiatorIdentityPrivateKey,
        "RUXMSG/1/initiator" || TranscriptHash
    )
The responder computes:

Sig_R =
    Ed25519.Sign(
        ResponderIdentityPrivateKey,
        "RUXMSG/1/responder" || TranscriptHash
    )
Each signature MUST be verified against the corresponding Ed25519 public key contained in the transcript.
A signature failure MUST terminate the handshake.

5.1 Key Schedule
After validating the handshake:

PRK =
    HKDF-Extract(
        salt = TranscriptHash,
        IKM = DH
    )
The following values are derived:

RootKey =
    HKDF-Expand(
        PRK,
        "RUXMSG/1/root",
        32
    )

InitiatorToResponder =
    HKDF-Expand(
        PRK,
        "RUXMSG/1/I-to-R",
        32
    )

ResponderToInitiator =
    HKDF-Expand(
        PRK,
        "RUXMSG/1/R-to-I",
        32
    )

SessionID =
    HKDF-Expand(
        PRK,
        "RUXMSG/1/session-id",
        16
    )

ConfirmationKey =
    HKDF-Expand(
        PRK,
        "RUXMSG/1/session-confirm",
        32
    )
RootKey is reserved for protocol-level session state and MUST NOT be used directly as a message-encryption key.
Directional keys MUST NOT be used interchangeably.

5.2 Session Confirmation
The initiator sends:

Confirm_I =
    HMAC-SHA-256(
        ConfirmationKey,
        "RUXMSG/1/confirm/I" || TranscriptHash
    )
The responder sends:

Confirm_R =
    HMAC-SHA-256(
        ConfirmationKey,
        "RUXMSG/1/confirm/R" || TranscriptHash
    )
Each confirmation MUST be verified before the cryptographic session becomes active.
Failure MUST terminate the candidate session.
Only after successful confirmation may the session enter:

ACTIVE
6. Session Lifecycle and Process Restart
A RUXMSG cryptographic session and its underlying transport connection have independent lifetimes.
A session contains:

SessionID
ChainState
MessageCounters
ReplayWindows
SkippedMessageKeys
SessionCreationTime
SessionMessageCount
SessionState
6.1 Session States
A session MUST support:

HANDSHAKING
ACTIVE
REKEYING
DRAINING
CLOSED
Only ACTIVE sessions may originate ordinary DATA.
DRAINING sessions may receive eligible in-flight DATA but MUST NOT originate new DATA.

6.2 Process Restart
An active cryptographic session MUST NOT survive process termination unless a future protocol revision explicitly defines secure persistent session state.
Therefore, when the RUXMSG process exits, crashes, or loses its in-memory cryptographic state:

EphemeralPrivateKey
ChainKeys
MessageKeys
SkippedKeys
ReplayState
SessionState
MUST be destroyed.
On process restart, the implementation MUST establish a fresh cryptographic session.
The persistent Ed25519 identity remains unchanged.
For a previously trusted peer:

process restart
      ↓
new X25519
      ↓
new nonces
      ↓
new transcript
      ↓
trusted Ed25519 authentication
      ↓
new session
      ↓
ACTIVE
Human SAS verification is not required for a previously trusted identity unless trust has been revoked, replaced, or otherwise invalidated.
The implementation SHOULD automatically initiate a new handshake when connectivity becomes available.
Incoming DATA belonging to a destroyed session MUST NOT be accepted.
The implementation MUST NOT reuse message counters or nonce state from the destroyed session.

6.3 Transport Reconnection
A transport disconnect alone MUST NOT destroy the cryptographic session.
For example:

TCP/Tailscale
    ↓
disconnect
    ↓
reconnect
    ↓
same SessionID
    ↓
same cryptographic state
Transport reconnection MUST NOT:

reset counters
reset replay windows
reset chain keys
reuse a nonce
automatically create a new cryptographic session
The existing session remains valid until it is explicitly closed, expires, or reaches its rekey condition.
7. Message Ratchet and AEAD Protection
RUXMSG/1 maintains independent symmetric sending chains:

Initiator → Responder:
    ChainKey_I

Responder → Initiator:
    ChainKey_R
7.1 Message-Key Derivation
For each chain key CK_n:

PRK_n =
    HKDF-Extract(
        salt = 32 zero bytes,
        IKM = CK_n
    )
The message key is:

MK_n =
    HKDF-Expand(
        PRK_n,
        "RUXMSG/1/message-key" || DirectionID,
        32
    )
The next chain key is:

CK_n+1 =
    HKDF-Expand(
        PRK_n,
        "RUXMSG/1/chain-key" || DirectionID,
        32
    )
The previous chain key SHOULD be securely erased after advancement.
Message keys SHOULD be securely erased after use.
A message key MUST NOT be reused.

7.2 Counters and Nonces
Each direction maintains an unsigned 64-bit message counter.
Counters begin at:

0
Direction identifiers are:

0x00000001 = Initiator → Responder
0x00000002 = Responder → Initiator
The ChaCha20-Poly1305 nonce is exactly 96 bits:

BE32(DirectionID) || BE64(MessageCounter)
The nonce MUST be unique for every encryption performed with a given session key.
Counter overflow MUST NOT occur.
A session MUST be rekeyed before a direction's counter would overflow.

7.3 Associated Data
AEAD associated data contains:

ProtocolVersion
SessionID
MessageType
DirectionID
MessageCounter
The encoding MUST be deterministic and unambiguous.
Modification of any authenticated field MUST cause AEAD verification to fail.
8. Replay Protection, Reordering, and Resource Limits
8.1 Replay Window
Each direction maintains a 64-message replay window.
Conceptually:

bit 0  = highest accepted counter
bit 1  = highest accepted counter - 1
...
bit 63 = highest accepted counter - 63
A received counter MUST be classified before message-key use.
Counters already accepted MUST be rejected as duplicates.
Counters outside the replay window MUST be rejected.
New counters advance the window as necessary.
The replay window MUST be bounded.

8.2 Skipped Message Keys
RUXMSG operates over transports where DATA may arrive out of order.
An implementation MUST support bounded skipped-message keys.
The maximum is:

MAX_SKIPPED_KEYS = 64
When a message arrives ahead of the current chain position, the receiver MAY derive intermediate message keys.
Derived keys MUST be stored only until the corresponding message arrives or the key becomes invalid.
An implementation MUST NOT derive an unbounded number of keys in response to a single attacker-controlled counter.
If the gap exceeds the permitted skipped-key limit, the message MUST be rejected or the session MUST be re-established according to implementation policy.
No attacker-controlled counter may cause unbounded:

CPU consumption
memory allocation
key derivation
state growth
8.3 Ordering
RUXMSG does not require globally ordered DATA delivery.
Applications requiring ordered delivery MUST implement ordering semantics above the cryptographic message layer.
The cryptographic layer guarantees authentication of each accepted message and protection against accepted duplicates.
9. Rekeying and Rekey Collision
RUXMSG/1 periodically replaces cryptographic sessions with fresh X25519 sessions.
A rekey MUST begin when the first of the following occurs:

24 hours since session establishment
OR
1,000,000 DATA messages sent in either direction
OR
application explicitly requests rekey
The protocol does not implement a full asymmetric Double Ratchet.
Periodic rekeying therefore limits the lifetime of a symmetric cryptographic session but does not provide continuous post-compromise recovery.

9.1 Rekey Handshake
A rekey establishes:

fresh X25519 keys
fresh handshake nonces
fresh transcript
fresh SessionID
fresh directional chains
fresh confirmation key
The existing SessionID is included in the new transcript as PreviousSessionID.
The old and new sessions MAY coexist temporarily.
During rekeying:

OLD SESSION:
    may receive DATA
    may send DATA until transition
    retains independent replay/ratchet state

NEW SESSION:
    performs handshake
    remains candidate until confirmation
After the new session successfully processes SESSION_CONFIRM:

NEW SESSION → ACTIVE
OLD SESSION → DRAINING
The old session then:

MUST NOT originate new DATA
MAY accept already in-flight DATA
MUST NOT generate additional outbound message keys
MUST retain state only for the bounded drain period
The drain timeout is:

REKEY_DRAIN_TIMEOUT = 15 seconds
After the timeout, the old session MUST be destroyed.
Its:

chain keys
message keys
skipped keys
replay state
ephemeral keys
session metadata
MUST be destroyed.
If the old session has no remaining in-flight traffic, it SHOULD be destroyed immediately.

9.2 Failed Rekey
Failure of a candidate rekey MUST NOT invalidate the existing authenticated session.
A failed rekey attempt is discarded.
The current session remains ACTIVE unless the failure independently demonstrates corruption or compromise of the current session.

9.3 Rekey Glare
Both peers MAY initiate rekeying simultaneously.
A rekey collision is resolved using the persistent Ed25519 public keys.
Compare the raw 32-byte public keys using unsigned lexicographic byte ordering.
The peer with the lexicographically greater public key is the rekey initiator.
The peer with the lexicographically smaller public key is the responder.
This comparison MUST use the raw public keys.
It MUST NOT use:

display names
hostnames
Tailscale addresses
fingerprints
usernames
If a peer receives a valid competing rekey while its own rekey is pending:

received initiator > local identity
then:

abandon local rekey
respond to received rekey
retain current session
If:

local identity > received initiator
then:

retain local rekey
reject competing attempt
The abandoned handshake MUST NOT create a second session.
The existing session MUST remain operational until the winning rekey reaches SESSION_CONFIRM.
The state machine MUST permit a node to abandon its candidate initiator state and immediately become the responder without losing queued application DATA.
10. Wire Format, CBOR, Padding, and Message Types
Every RUXMSG frame uses:

+---------+------+----------------+-------------------+
| Version | Type | Payload Length | CBOR Payload      |
| 1 byte  | 1 B  | 4 bytes BE     | N bytes           |
+---------+------+----------------+-------------------+
The four-byte length field defines frame payload length.
It does NOT authorize arbitrary allocation.

10.1 Maximum Frame Size
RUXMSG/1 defines:

MAX_FRAME_SIZE = 1 MiB
A frame whose declared payload exceeds this limit MUST be rejected.
The implementation MUST validate the declared length before allocating the complete payload.
Implementations SHOULD impose additional environment-specific limits.
The implementation MUST NOT treat the 32-bit length field as permission to allocate up to 4 GiB.

10.2 Message Types
The base protocol defines at minimum:

HANDSHAKE
SESSION_CONFIRM
DATA
REKEY
CLOSE
Message-type values MUST be assigned by the protocol registry used by the implementation.
Unknown message types MUST NOT be interpreted as known message types.

10.3 Deterministic CBOR
Structured messages MUST use deterministic CBOR according to RFC 8949.
Implementations MUST:

use definite-length containers
use deterministic encoding
reject duplicate map keys
use the protocol-defined integer map keys
reject malformed CBOR
reject unsupported mandatory fields
use RFC-defined deterministic map-key ordering
RUXMSG MUST NOT define its own map-key sorting algorithm.

10.4 DATA Padding
Padding exists only to reduce plaintext-length precision.
A DATA plaintext conceptually contains:

{
    content: `application data`,
    padding: `zero bytes`
}
The entire structure is encrypted.
Padding MUST consist entirely of 0x00 bytes.
Padding is calculated against the serialized encrypted plaintext size, including CBOR structure and padding-field overhead.
It MUST NOT be calculated from the raw application content alone.
For a selected padding quantum Q:

target = smallest multiple of Q
         greater than or equal to
         serialized plaintext length
The sender MUST account for the CBOR encoding overhead introduced by the padding field itself before finalizing the padding length.
The recommended default quantum is:

256 bytes
Implementations MAY use:

1024 bytes
4096 bytes
or another fixed implementation-defined quantum, provided the policy is deterministic and bounded.
After successful AEAD authentication, the receiver MUST:

parse the DATA plaintext
validate the padding field
validate its declared length
verify every padding byte is 0x00
remove the padding
deliver application content
Padding MUST NOT be interpreted before AEAD authentication succeeds.
Non-zero padding bytes MUST cause the DATA message to be rejected.
Padding does not provide complete traffic-analysis resistance.
11. Transport, Discovery, and File Transfer
RUXMSG defines a transport abstraction:

connect()
send(frame)
receive()
close()
The cryptographic protocol MUST remain independent of the transport implementation.

11.1 Tailscale
The initial implementation SHOULD use Tailscale as its primary transport.
A configurable TCP port MAY be used.
Example:

RUXMSG TCP/43777
The exact port is implementation configuration and is not itself a security primitive.
Peers MAY be addressed through:

Tailscale IP
Tailscale DNS hostname
For example:

ruxmsg connect alice@`100.x.y.z`
or:

ruxmsg connect alice@`alice.tailnet-name.ts.net`
The supplied address is used only to establish transport connectivity.
RUXMSG then performs its own cryptographic authentication.

11.2 Discovery
Automatic discovery is not required.
The initial implementation SHOULD support explicit addressing:

ruxmsg connect `address`
Future discovery mechanisms MAY include:

mDNS
Tailscale DNS
LAN discovery
QR codes
invitation files
Discovered addresses MUST NEVER constitute identity proof.

11.3 Relay Operation
A Tailscale relay or intermediary is treated as an untrusted transport component.
It MUST NOT receive:

plaintext messages
RUXMSG message keys
Ed25519 private keys
X25519 private keys
All application encryption occurs above the transport layer.

11.4 Large Data
The base protocol does not define file-transfer semantics.
Applications requiring large transfers MUST divide data into multiple authenticated DATA messages.
A future extension MAY define:

transfer_id
chunk_index
total_chunks
total_size
file_hash
Each DATA message remains independently authenticated and encrypted.
12. Identity Changes, Security Properties, Testing, and Conformance
12.1 Identity Changes
If a previously trusted peer presents a different Ed25519 identity key, the implementation MUST NOT silently replace the stored identity.
The terminal SHOULD display:

IDENTITY CHANGE DETECTED

Peer: Alice

Trusted identity:
    SHA256:AB:CD:...

Presented identity:
    SHA256:12:34:...

Possible causes:
    new device
    intentional key rotation
    lost/replaced device
    impersonation attempt
The connection MUST NOT become trusted automatically.
A new installation creates a new Ed25519 identity.
RUXMSG cannot cryptographically determine whether two identity keys belong to the same human.
Therefore a new device requires explicit re-pairing:

fresh X25519
      ↓
fresh SAS
      ↓
human verification
      ↓
Ed25519 authentication
      ↓
explicit trust decision
The old identity SHOULD remain recorded as:

REVOKED
REPLACED
UNKNOWN
rather than being silently deleted.

12.2 Security Properties
When correctly implemented, RUXMSG/1 provides:

Confidentiality
DATA is encrypted with ChaCha20-Poly1305.

Integrity
AEAD authentication detects modification.

Persistent Identity Authentication
Ed25519 authenticates trusted peer identities.

First-Contact Authentication
Human SAS verification authenticates the initial ephemeral session.

Session Forward Secrecy
Fresh X25519 ephemeral keys provide forward secrecy between independently established sessions when ephemeral private material is properly erased.

Symmetric Message Forward Secrecy
Erasing previous chain and message keys prevents later chain-state compromise from directly recovering already-erased message keys.

Replay Protection
Counters and replay windows prevent accepted duplicate messages.

Reordering Tolerance
Bounded skipped-message keys permit limited out-of-order delivery.

Session Separation
Each cryptographic session derives a new SessionID and independent cryptographic state.

Directional Separation
Traffic directions use independent chain and nonce domains.

Transport Independence
Security does not depend on Tailscale.

Rekey Damage Limitation
Periodic X25519 rekeying limits the lifetime of compromised symmetric session state.
RUXMSG/1 does not provide a full Double Ratchet or continuous post-compromise recovery.
If an attacker retains active endpoint control, rekeying does not protect future communications.
If an attacker obtains the persistent Ed25519 private key, they may impersonate that identity in future sessions.

12.3 Mandatory Test Vectors
The implementation MUST include deterministic test vectors for:

Ed25519 identity keys
X25519 ephemeral keys
X25519 shared secret
handshake nonces
canonical transcript
TranscriptHash
SAS source bits
W0
W1
W2
SAS words
Ed25519 signatures
HKDF PRK
RootKey
directional session keys
SessionID
confirmation MACs
initial chain keys
message keys
next chain keys
message nonce
AAD
plaintext
padding
ciphertext
authentication tag
Binary values SHOULD be represented in hexadecimal.
SAS test vectors MUST explicitly include:

TranscriptHash
first 33 bits
W0
W1
W2
word[W0]
word[W1]
word[W2]
Tests MUST explicitly exercise bit boundaries crossing:

H[0] → H[1]
H[1] → H[2]
H[2] → H[3]
H[3] → H[4]
Two independent implementations MUST produce identical results from identical test vectors.

12.4 Required Behavioral Tests
Implementations MUST test:

identity generation
all-zero X25519 rejection
nonce generation
transcript construction
transcript determinism
SAS endianness
SAS extraction
identity signatures
signature failure
HKDF derivation
session confirmation
message-key derivation
chain advancement
nonce construction
AEAD encryption/decryption
AEAD authentication failure
AAD modification
replay detection
replay-window advancement
packet reordering
skipped-message handling
skipped-key limit
frame-size enforcement
malformed CBOR
duplicate CBOR keys
identity mismatch
process restart
transport reconnect
normal rekey
failed rekey
simultaneous rekey
deterministic rekey tie-breaking
old/new session coexistence
drain timeout
padding generation
padding CBOR overhead
padding authentication
non-zero padding rejection
12.5 Fuzzing and Resource Safety
The following MUST be fuzz-tested:

frame parser
CBOR parser
handshake parser
message parser
counter handling
replay window
skipped-key handling
identity records
rekey state machine
transport reconnect handling
padding handling
Malformed input MUST NOT cause unbounded memory allocation or computational work.
All attacker-controlled lengths, counters, indexes, and collection sizes MUST be range-checked before use.

12.6 Security Review
RUXMSG/1 MUST NOT be considered production-secure solely because it uses established cryptographic primitives.
Before serious external deployment, the protocol and implementation SHOULD receive independent review covering:

handshake composition
transcript binding
SAS construction
identity authentication
key schedule
symmetric ratchet
replay protection
skipped-key handling
rekey state machine
rekey collision handling
deterministic CBOR schemas
padding semantics
process restart behavior
identity lifecycle
resource limits
memory erasure
implementation-specific concurrency
The primary remaining security risk is protocol composition and implementation correctness rather than the underlying cryptographic primitives.
Appendix A — Protocol State Model
                    ┌──────────────┐
                    │ HANDSHAKING  │
                    └──────┬───────┘
                           │
                  authentication
                    + confirmation
                           │
                           ▼
                    ┌──────────────┐
                    │    ACTIVE    │
                    └──────┬───────┘
                           │
                    rekey condition
                           │
                           ▼
                    ┌──────────────┐
                    │   REKEYING   │
                    └──────┬───────┘
                           │
                    new confirmation
                           │
                           ▼
                    ┌──────────────┐
                    │ NEW ACTIVE   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   DRAINING   │
                    └──────┬───────┘
                           │
                      15 seconds
                           │
                           ▼
                    ┌──────────────┐
                    │    CLOSED    │
                    └──────────────┘
A failed candidate handshake does not terminate the existing ACTIVE session.
Appendix B — Cryptographic Architecture
             PERSISTENT IDENTITY
                    │
                 Ed25519
                    │
                    ▼
          Identity Authentication
                    │
                    ▼
          FRESH X25519 EPHEMERAL
                    │
                    ▼
               DH SHARED
                 SECRET
                    │
                    ▼
             TRANSCRIPT HASH
               │          │
               │          └──────► SAS
               │                    │
               │               HUMAN VERIFY
               │
               ▼
            HKDF-SHA256
               │
       ┌───────┼────────┐
       │       │        │
       ▼       ▼        ▼
   Session   I→R      R→I
     ID     Chain     Chain
               │
               ▼
        Message Ratchet
               │
               ▼
          Message Key
               │
               ▼
      ChaCha20-Poly1305
               │
               ▼
        Encrypted DATA
Appendix C — Session vs. Transport Lifetime
TRANSPORT

TCP/Tailscale
     │
 disconnect
     │
 reconnect
     │
     ▼
same cryptographic session
versus:

CRYPTOGRAPHIC SESSION

X25519
   │
HKDF
   │
SessionID
   │
message chains
   │
24h / 1M DATA
   │
fresh X25519
   │
new SessionID
   │
new message chains
Transport reconnection MUST NOT reset cryptographic state.
Process termination MUST destroy in-memory cryptographic state and require a fresh cryptographic session.
Appendix D — Design Boundary
RUXMSG/1 deliberately does not contain:

PairingSecret
CPace
password-derived authentication
Argon2id
central rendezvous authentication
custom cryptographic primitives
full Double Ratchet
automatic identity recovery
The intended security model is:

"Are we communicating over the same authenticated
ephemeral cryptographic session?"
                    │
                    ▼
                   SAS

"Which persistent identity authenticated that session?"
                    │
                    ▼
                Ed25519

"How are messages protected?"
                    │
                    ▼
            X25519 + HKDF
                    │
                    ▼
          symmetric chain keys
                    │
                    ▼
             message keys
                    │
                    ▼
         ChaCha20-Poly1305
This separation is intentional.
RUXMSG/1 prioritizes:

small cryptographic surface
explicit state
deterministic encoding
bounded resource usage
persistent identity
fresh ephemeral sessions
simple message ratcheting
transport independence
over protocol complexity such as a full asymmetric Double Ratchet.
End of RUXMSG/1 Specification

Appendix E — Normative Wire Contract

This appendix is part of the RUXMSG/1 specification. It resolves all wire-level
assignments required for interoperable implementations. A conforming
implementation MUST implement this appendix together with the preceding
requirements. The protocol identifier is the single byte value 0x01 and the
ASCII protocol name is `RUXMSG/1`.

E.1 Version and message registry

The outer frame version byte MUST be 0x01. A receiver MUST reject any other
version before interpreting the type or payload. Version negotiation is not
defined in RUXMSG/1; a peer that does not support version 0x01 MUST close the
transport without sending a protocol response. Implementations MUST NOT
downgrade a connection after receiving an unsupported version.

The message-type byte registry is:

| Value | Name | Meaning |
| ---: | --- | --- |
| 0x01 | HANDSHAKE | Initial-session or rekey transcript authentication |
| 0x02 | SESSION_CONFIRM | Confirmation of a candidate session |
| 0x03 | DATA | Encrypted application data |
| 0x04 | REKEY | Rekey transcript authentication |
| 0x05 | CLOSE | Session or transport shutdown |
| 0x00, 0x06–0xff | Reserved | Not valid in RUXMSG/1 |

A receiver MUST reject reserved or unknown message types. Message types are
not negotiated and MUST NOT be reassigned by an implementation.

The cipher-suite registry contains exactly one value:

| Value | Name | Algorithms |
| ---: | --- | --- |
| 0x01 | RUXMSG-1-ED25519-X25519-HKDF-SHA256-CHACHA20POLY1305 | Ed25519, X25519, SHA-256, HKDF-SHA-256, ChaCha20-Poly1305, HMAC-SHA-256 |

The `CipherSuite` transcript field is the unsigned integer 0x01 encoded as a
CBOR unsigned integer. No alternative suite is valid in this version.

E.2 Outer frame

Every frame is exactly:

| Offset | Size | Field | Encoding |
| ---: | ---: | --- | --- |
| 0 | 1 | Version | 0x01 |
| 1 | 1 | Type | Registry value above |
| 2 | 4 | PayloadLength | Unsigned big-endian byte count |
| 6 | N | Payload | Deterministic CBOR map |

`PayloadLength` MUST be at most 1,048,576 (1 MiB). A receiver MUST reject the
length before allocating the payload. A streaming receiver MUST read exactly N
bytes, reject EOF before N bytes, and reject trailing bytes only when they are
not the beginning of the next frame. A frame payload MUST contain exactly one
definite-length CBOR map and no trailing bytes. A malformed, truncated, or
oversized frame MUST terminate the candidate session; an implementation MAY
also close the transport.

E.3 Common CBOR rules

All payloads are CBOR maps with unsigned integer keys. Keys are encoded using
their shortest CBOR representation and sorted according to RFC 8949
deterministic encoding. Maps and arrays MUST use definite lengths. Byte strings
and text strings MUST use definite lengths. Duplicate keys MUST be rejected,
including duplicates that would compare equal after decoding. Unknown keys are
rejected for every base-protocol message; extension keys are not defined in
RUXMSG/1. Unsupported mandatory fields are a protocol error. Implementations
MUST validate map shape, key type, value type, and byte length before using a
field.

The following fixed-size types are used throughout this appendix:

| Type | Encoding |
| --- | --- |
| IdentityPublicKey | CBOR byte string, exactly 32 bytes |
| EphemeralPublicKey | CBOR byte string, exactly 32 bytes |
| Nonce | CBOR byte string, exactly 16 bytes |
| SessionID | CBOR byte string, exactly 16 bytes |
| TranscriptHash | CBOR byte string, exactly 32 bytes |
| Signature | CBOR byte string, exactly 64 bytes |
| ConfirmationMAC | CBOR byte string, exactly 32 bytes |
| Ciphertext | CBOR byte string, at least 16 bytes; final 16 bytes are the AEAD tag |

Unsigned integer fields MUST use the smallest CBOR representation and MUST be
range-checked against the specified width. Boolean and null values are not
valid where an integer, byte string, or text string is specified.

E.4 Handshake HELLO and transcript wire schema

The first `HANDSHAKE` frame from each peer is a symmetric `HELLO`. Each peer
MUST generate its own fresh X25519 ephemeral key and 128-bit CSPRNG nonce before
sending its HELLO. A HELLO contains only the sender's values; it MUST NOT
contain a responder field in an initiator HELLO or an initiator field in a
responder HELLO.

HELLO payload keys are:

| Key | Field | Type | Required |
| ---: | --- | --- | --- |
| 0 | protocol_version | uint, exactly 1 | yes |
| 1 | cipher_suite | uint, exactly 1 | yes |
| 2 | handshake_purpose | uint, 0=initial, 1=rekey | yes |
| 3 | role | uint, 0=initiator, 1=responder | yes |
| 4 | identity_public_key | IdentityPublicKey | yes |
| 5 | ephemeral_public_key | EphemeralPublicKey | yes |
| 6 | nonce | Nonce | yes |
| 7 | previous_session_id | SessionID | initial: absent; rekey: required |

The initiator sends an initiator HELLO, the responder independently generates
and sends a responder HELLO, and only then do both peers construct the complete
transcript. Both HELLOs MUST agree on protocol version, cipher suite, handshake
purpose, and previous session ID. The two roles MUST be different and must be
exactly one initiator and one responder.

After both HELLOs are available, the transcript fields are populated as:

`ProtocolVersion` and `CipherSuite` from either HELLO; `HandshakeType` from
`handshake_purpose`; `InitiatorRole=0`; `ResponderRole=1`; identities,
ephemerals, and nonces from the corresponding role's HELLO; and
`PreviousSessionID` from both matching HELLOs. The transcript is then encoded
using the transcript-only map defined below. No signature is calculated before
both HELLOs have been received.

After transcript construction and SAS handling, the authenticated handshake
stage carries the initiator signature and responder signature using the
existing signature fields (keys 10 and 11) in a subsequent HANDSHAKE payload.
The responder MUST verify the initiator signature before sending its signature;
both peers MUST verify the appropriate signatures before deriving or accepting
the candidate session.

The transcript is the deterministic CBOR encoding of map keys 0 through 9,
excluding keys 10 and 11. Its map has exactly the required keys for the
selected handshake type. `ProtocolVersion` is the fixed byte 0x01 and
`HandshakeType` is the value of key 0. `InitiatorRole` and `ResponderRole` are
the fixed unsigned values 0 and 1 and are included in the transcript as keys
12 and 13 in the transcript-only map:

| Key | Transcript field | Type |
| ---: | --- | --- |
| 0 | protocol_version | uint, 1 |
| 1 | cipher_suite | uint, 1 |
| 2 | handshake_type | uint, 0 or 1 |
| 3 | initiator_role | uint, 0 |
| 4 | responder_role | uint, 1 |
| 5 | previous_session_id | SessionID, or absent for initial |
| 6 | initiator_identity | IdentityPublicKey |
| 7 | responder_identity | IdentityPublicKey |
| 8 | initiator_ephemeral | EphemeralPublicKey |
| 9 | responder_ephemeral | EphemeralPublicKey |
| 10 | initiator_nonce | Nonce |
| 11 | responder_nonce | Nonce |

The transcript map uses keys 0–4 and 6–11 for an initial handshake and keys
0–11 for a rekey. Keys 3 and 4 carry the fixed initiator and responder role
values; no additional role keys are present. This transcript-only map is not
itself sent as a payload.
The transcript hash input is `ASCII("RUXMSG/1/TRANSCRIPT") || BE32(L) || T`,
where T is the canonical CBOR transcript and L is its byte length. Signature
inputs are `ASCII("RUXMSG/1/initiator") || H` and
`ASCII("RUXMSG/1/responder") || H`, where H is the 32-byte transcript hash.

E.5 SESSION_CONFIRM schema

`SESSION_CONFIRM` payload keys are:

| Key | Field | Type | Required |
| ---: | --- | --- | --- |
| 0 | session_id | SessionID | yes |
| 1 | role | uint, 0=initiator or 1=responder | yes |
| 2 | confirmation | ConfirmationMAC | yes |

The confirmation input is `ASCII("RUXMSG/1/confirm/I") || H` for role 0 and
`ASCII("RUXMSG/1/confirm/R") || H` for role 1. The confirmation key is derived
as specified in section 5.1. Each side MUST verify the received confirmation
before entering ACTIVE. A confirmation with an unknown session ID, wrong role,
wrong length, or invalid MAC is rejected without changing the active session.

E.6 DATA schema, AAD, and padding

`DATA` payload keys are:

| Key | Field | Type | Required |
| ---: | --- | --- | --- |
| 0 | session_id | SessionID | yes |
| 1 | direction_id | uint, 1 or 2 | yes |
| 2 | message_counter | uint, 0 through 2^64-1 | yes |
| 3 | ciphertext | Ciphertext | yes |

The direction ID MUST match the sender's role: 1 is initiator-to-responder and
2 is responder-to-initiator. AAD is the canonical CBOR encoding of the map
`{0: 1, 1: session_id, 2: 3, 3: direction_id, 4: message_counter}`. Here 1
is the protocol version and 3 is the DATA message type. The nonce is
`BE32(direction_id) || BE64(message_counter)`. The ciphertext includes the
16-byte ChaCha20-Poly1305 authentication tag.

After successful AEAD authentication, plaintext MUST be a map with exactly:

| Key | Field | Type |
| ---: | --- | --- |
| 0 | content | Definite byte string |
| 1 | padding | Definite byte string of zero bytes |

The default padding quantum is 256 bytes. The sender MUST choose the smallest
non-negative padding length for which the complete canonical plaintext map is a
multiple of 256 bytes, recalculating the map and padding-field overhead until
the result is exact. Plaintext and padding together MUST fit within the frame
limit after encryption overhead. The maximum padding length is 1 MiB minus 16
bytes and minus the encoded map overhead. A receiver MUST authenticate first,
then parse the map, require both keys exactly once, validate the padding length,
and verify every padding byte is 0x00 before delivering content.

E.7 REKEY schema

`REKEY` begins with the same HELLO schema, using `handshake_purpose=1` and a
required `previous_session_id`. After both rekey HELLOs are received, the
authenticated signature stage uses the existing signature fields. The previous
session ID MUST identify the currently ACTIVE session.
The candidate session remains non-active until both SESSION_CONFIRM messages
are successfully verified. A failed candidate is discarded and MUST NOT alter
the active session.

When simultaneous offers exist, compare the raw initiator identity keys as
unsigned 32-byte strings. The lexicographically greater key wins initiator
status. The losing candidate MUST be discarded; the active session and queued
application data remain available. A peer MUST reject a losing competing offer
without creating a candidate session.

E.8 CLOSE schema and reason registry

`CLOSE` payload keys are:

| Key | Field | Type | Required |
| ---: | --- | --- | --- |
| 0 | session_id | SessionID | no, required when session exists |
| 1 | reason | uint | yes |
| 2 | detail | text string, maximum 128 UTF-8 bytes | no |

Reason values are:

| Value | Name |
| ---: | --- |
| 0 | normal |
| 1 | protocol_error |
| 2 | authentication_failed |
| 3 | identity_changed |
| 4 | resource_limit |
| 5 | shutdown |

Unknown reasons are rejected. `detail` is diagnostic only, MUST NOT contain
key material or plaintext application content, and MUST NOT be required for
interoperability. A CLOSE transitions the identified session to CLOSED after
any eligible in-flight processing; a malformed or unauthenticated CLOSE MUST
not destroy a different active session.

E.9 Error behavior

Errors are local outcomes and are not an additional wire message type in
RUXMSG/1. Implementations MUST use the CLOSE reason registry when notifying a
peer and MUST avoid sending secret-bearing diagnostics. The following outcomes
are protocol errors: unsupported version/type, malformed frame, malformed or
non-canonical CBOR, duplicate key, unknown key, missing/invalid field, invalid
signature, invalid confirmation, SAS rejection, identity mismatch, invalid
state, replay, counter outside the replay window, skipped-key limit exceeded,
counter overflow, invalid padding, and frame/resource limit exceeded.

Before key derivation, a receiver MUST classify the counter against the replay
window. It MUST reject duplicates and counters outside the 64-message window.
It MUST derive no more than 64 skipped keys for one packet and MUST reject a
larger gap. Failed authentication MUST NOT mark a counter as accepted.

E.10 State-transition contract

| Current state | Event | Required result |
| --- | --- | --- |
| HANDSHAKING | Valid handshake and accepted SAS/signatures | Candidate remains HANDSHAKING until |
| CLOSED | SESSION_CONFIRM is received and verified | Candidate destroyed; CLOSED |
| HANDSHAKING | Both confirmations valid | ACTIVE |
| HANDSHAKING | Any authentication, SAS, schema, or limit failure | Candidate destroyed; CLOSED |
| ACTIVE | Valid DATA | Deliver once after replay, ratchet, AEAD, and padding checks |
| ACTIVE | Rekey trigger or valid REKEY | REKEYING; current session remains usable |
| ACTIVE | Transport disconnect | Preserve session state |
| REKEYING | Candidate confirmation succeeds | New session ACTIVE; old session DRAINING |
| REKEYING | Candidate fails | Discard candidate; old session remains ACTIVE |
| DRAINING | Eligible in-flight DATA | Receive only; never originate new DATA |
| DRAINING | 15-second timeout or no in-flight traffic | CLOSED and destroy all session state |
| Any non-CLOSED | Valid CLOSE | CLOSED and destroy associated session state |

Only ACTIVE sessions may originate ordinary DATA. A process restart destroys
all in-memory session state and requires a fresh handshake. A transport
reconnect preserves the existing session, counters, replay windows, and chain
keys. DATA referencing a destroyed or unknown session ID MUST be rejected.

E.11 Base-protocol conformance boundary

RUXMSG/1 does not define automatic discovery, file-transfer metadata, central
rendezvous, password pairing, persistent session state, identity recovery, or a
full Double Ratchet. An implementation claiming RUXMSG/1 conformance MUST
implement the base registry and schemas above and MUST NOT interpret transport
addresses or Tailscale identities as peer authentication. Extensions require a
new protocol version or a separately registered message type; they MUST NOT
reuse reserved values or alter the meaning of base fields.
End of normative Appendix E
