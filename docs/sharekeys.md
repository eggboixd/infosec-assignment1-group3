# Share keys: how `internal/sharekey` works

Assignment 2, part 2 (`feature/share-keys`). `internal/sharing` decides **who may see whose data, and until when**
([sharing.md](sharing.md)). This package decides **how the data is opened**: it makes the share key, re-wraps the
owner's keys under it, encrypts it to the requester, and opens the data after the requester imports it. The reasons
are in [decisions.md](decisions.md) D58–D63.

## The flow

```text
owner (bob)                                   server                                   requester (alice)
───────────                                   ──────                                   ─────────────────
clicks Approve ─────────────▶ Grant:
                              1. K = 32 random bytes (crypto/rand)
                              2. for every profile field and file, every algorithm:
                                 DEK, MAC key = Unwrap(master, meta)
                                 store Wrap(K, DEK), Wrap(K, MAC key)
                              3. C = RSA-OAEP-SHA256(alice's encryption key, K,
                                     label "securestore/share-key/v1:<request id>")
                              4. store C, KeyCheck = HMAC(K, request id); forget K
opens "Show encrypted key" ◀─ base64(C) and alice's key fingerprint
sends base64(C) over WhatsApp ─────────────────────────────────────────────────────▶ receives it
                                                                                     checks the fingerprint
                              Import: ◀──────────────────── pastes C + types her password
                              sharing.Active(request, alice) must succeed
                              priv = Unlock(alice, password)    (rate-limited)
                              K = RSA-OAEP-decrypt(priv, C, label)
                              HMAC(K, request id) == KeyCheck ?
                              store AES-256-GCM(DeriveKey(master, "share-key-import"), K,
                                                aad = request id)
                              Open / Download: ◀────────────── views the data, downloads files
                              sharing.Active(...) again, on every request
                              K = unwrap imported key; DEK, MAC key = Unwrap(K, …)
                              verify HMAC over the ciphertext, then decrypt
revokes, or it expires ──────▶ Destroy: delete the share_keys document
```

## What is stored (`share_keys`, one document per request)

```text
{ _id, request_id (unique), owner_id, requester_id, created_at,
  encrypted_key:         RSA-OAEP ciphertext of K (384 B for RSA-3072): what the owner sends,
  requester_fingerprint: SHA-256 of the public key it was made for,
  key_check:             HMAC-SHA256(K, "securestore/share-key-check/v1:" + request id),
  imported_key:          nonce ‖ AES-256-GCM(import key, K) ‖ tag   (only after import),
  imported_at,
  profile: { full_name: { aes: { sealed: {ct, meta}, keys: {dek, mac_key} }, des: …, rc4: … }, nik: …, … },
  files:   [ { file_id, kind, slot, mime_type, size, created_at,
               file_name: { aes: {sealed, keys}, … },
               variants:  { aes: { object_key, meta, keys: {dek, mac_key} }, des: …, rc4: … } } ] }
```

- `keys.dek` and `keys.mac_key` are `crypto.WrapKey(K, …)`: AES-256-GCM under an HKDF subkey of K. The master key
  can't open them.
- `sealed.meta` is the **original** `Meta`, master-wrapped keys included. The HMAC header covers those wrapped keys, so
  they stay as they are and are only used to recompute the tag (`crypto.DecryptWithKeys`).
- Profile ciphertexts are copied. File ciphertexts stay in MinIO; only their keys are re-wrapped.
- Nothing here is a plaintext key, DEK, MAC key or private datum.

## Who can open what

| Holder | Can open the shared data? |
|---|---|
| The server before import (has the master key) | No: K exists only as `encrypted_key`, which needs alice's private key, which needs her password. |
| Someone who reads the WhatsApp message | No: `encrypted_key` needs alice's private key. |
| Alice after import, request approved and unexpired | Yes. |
| Alice after revoke or expiry | No: `sharing.Active` refuses first, and `Destroy` deletes the document. |
| Another user who gets alice's key text | No: the document is looked up by request ID **and** requester ID, and their private key can't decrypt it. |

## Routes

| Route | Who | What |
|---|---|---|
| `GET /shares/requests/:id/key` | owner | the encrypted share key (base64) and the requester's fingerprint |
| `GET /shares/requests/:id/data?alg=` | requester | import form until imported, then the profile and file list |
| `POST /shares/requests/:id/import` | requester | `key`, `password`; 10 attempts per 15 minutes per user |
| `GET /shares/requests/:id/files/:file?alg=` | requester | streams the decrypted file as an attachment |

The three requester routes call `sharing.Service.Active` first, in the same HTTP request (rule 1 of
[sharing.md](sharing.md)). The service methods take the `*sharing.Request` that `Active` returned, so they can't be
called without it.

## Rules

1. Never log the pasted key, the password, K, a DEK or a MAC key. Log request and user IDs.
2. Never return or render K. The owner sees only `encrypted_key`.
3. A refused import stores nothing.
