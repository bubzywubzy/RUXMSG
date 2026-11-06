# RUXMSG/1 deterministic test vector

This vector is normative input/output material for independent
implementations. All values are lowercase hexadecimal. It is also asserted in
`crates/ruxmsg-core/tests/conformance.rs`.

| Input / output | Value |
| --- | --- |
| Ed25519 initiator seed | `10` repeated 32 times |
| Ed25519 responder seed | `20` repeated 32 times |
| X25519 initiator secret | `30` repeated 32 times |
| X25519 responder secret | `40` repeated 32 times |
| Initiator identity public key | `5c9c6df261c9cb840475776aaefcd944b405328fab28f9b3a95ef40490d3de84` |
| Responder identity public key | `4ed32f63bf35f0eeefcb25f28a2e1fbdc873ae2835671b0c9460f5f12e4556a8` |
| Initiator ephemeral public key | `e50c239bc204f1341664c9d9c50c6a0d0fff6fc79d9301f1e713aab2e0344b3f` |
| Responder ephemeral public key | `d7b5e81d336e578b13b8d706e82d061e3038c96bce66cdcf50d566b96ddbba10` |
| X25519 shared secret | `2ffc24cce9eed2a0d0357986878c0691154eb70589bef1afeb4fbf513170fa33` |
| Initiator nonce | `55` repeated 16 times |
| Responder nonce | `66` repeated 16 times |
| Initial HELLO payload | `a700010101020003000458205c9c6df261c9cb840475776aaefcd944b405328fab28f9b3a95ef40490d3de84055820e50c239bc204f1341664c9d9c50c6a0d0fff6fc79d9301f1e713aab2e0344b3f065055555555555555555555555555555555` |
| COMMIT | `99c899c4c5fc9c9fa8bdd59a1ac874724fb7ca8cdbb450c8550672837b686ed7` |
| Canonical transcript | `ab000101010200030004010658205c9c6df261c9cb840475776aaefcd944b405328fab28f9b3a95ef40490d3de840758204ed32f63bf35f0eeefcb25f28a2e1fbdc873ae2835671b0c9460f5f12e4556a8085820e50c239bc204f1341664c9d9c50c6a0d0fff6fc79d9301f1e713aab2e0344b3f095820d7b5e81d336e578b13b8d706e82d061e3038c96bce66cdcf50d566b96ddbba100a50555555555555555555555555555555550b5066666666666666666666666666666666` |
| Transcript hash | `89fa686e4361198f1fc6e5423c2d47093ff35767d0e4d82ecc987c3d870ba910` |
| HKDF extract PRK | `e925793d911328f51dcb16563945f3af5ff0190c96f3e2b05b1cfd23f6563140` |
| Initiator signature | `482810706bc520efd5226bc7d3335e8215be494bdcbd7e395ecadd9261827af1c8bf8fcda4f8d00b18c9661daab04e63bce1da3c47b136420b3f3e3fdc652305` |
| Responder signature | `cb74a429ee682e5d6bb0d0db40d0edbb33e9966a84351641d7ef78e0c7b1c7386896ed45ebff592426fc77cfcf3670ea1ed0e2b6bf16d931d1e0c62d6f523707` |
| Root key | `cbfc08b0b02adcc9822f57cff838a64fd296f9b41ff43a911b8fa17244ee6a4b` |
| Initiator-to-responder chain key | `1566950c0fee039df5f2e7fd3fa9872df0596b72d6fe989c5a0301970524dfce` |
| Responder-to-initiator chain key | `3cec6a7852d1a00656cb7dce6367d82536f26698b0fa4d7caecec5aa1c0af002` |
| Session ID | `f9a69f3a26c7fd39528449beee9276b6` |
| Confirmation key | `702f701bdca427b87322a788c91e96c59aa07d0881df1b2d05ccd5a9a6e9dba1` |
| Confirm initiator | `43fadc097ee1f4d8af90ab599108d41346ed0bb602fdf74c65eda43264229e7e` |
| Confirm responder | `1583e4e8adc63d1c0b3c3fcc041d429902cbbc0c7c8e82fd5336d200426f80ac` |
| Message key 0, direction 1 | `c005254c307357b6e07e7c7c5d185f78c6a5791ffdb07e6cc5c2b5bd823645b9` |
| Chain key 1, direction 1 | `31b8b28b3b55f547c358a1febf3adb7fff78c6e776a7c3bd496ec8424155b712` |
| Nonce, direction 1 counter 0 | `000000010000000000000000` |
| DATA AAD | `a500010150f9a69f3a26c7fd39528449beee9276b6020303010400` |

The DATA plaintext input is UTF-8 `vector`. Its canonical padded plaintext is
the map prefix `a20046766563746f720158e4` followed by exactly 228 zero bytes;
the resulting ciphertext is 256 bytes (including the 16-byte tag):

```text
20cb2b8c50b768be87558e1a9d3f4d24feb2543461b80d2527281cc0f4d7c6a99b30bffa9d9a9f4e37d7d5a5a018e1eecd7cd3e7d3a2791b75ded16d6b4150919c26de7942c4c1e3a90ad8dc27c3511c5f7055156b85e28e9ae8e9eed0ac675f19078c9d3e2334c07f8922be0bab3269d8b6eefaad282325b832c725efc08b6a91105624e94e615f36d95a42d591ba26182cdf400c8938b6177f06d4ffe3b4d58b3dd027ac71e869f5ecaf1239544e623023759ce9a60ded4eff371ffa50311e02a7d27f7767c7169c3551569122f5a361c94d060e973d14eb5ee63d8310eceb70d87a694a18738233a13d12271cbd0e971f748b33d7eddfe80046a9dc935f43
```

SAS boundary vectors are asserted separately in `conformance.rs`; they cover
each extraction boundary through `H[4]` and the ignored low seven bits.
