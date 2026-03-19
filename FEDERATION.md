# Goofy Media Federation Guide

This document describes the federation architecture of Goofy Media: how the system works internally, which interfaces are public, and what an alternative implementation needs to do in order to federate with a Goofy Media instance.

---

## Table of Contents

1. [Overview](#overview)
2. [Core Design Principles](#core-design-principles)
3. [Cryptographic Primitives](#cryptographic-primitives)
   - [RSA Key Pairs](#rsa-key-pairs)
   - [User ID Derivation](#user-id-derivation)
   - [Content UUID Derivation](#content-uuid-derivation)
4. [Request Authentication](#request-authentication)
   - [X-Goofy-* Headers](#x-goofy--headers)
   - [Signing a Request](#signing-a-request)
   - [Replay-Attack Prevention](#replay-attack-prevention)
5. [Data Models and Content Signatures](#data-models-and-content-signatures)
   - [Post Signature](#post-signature)
   - [Comment Signature](#comment-signature)
6. [Public API Reference](#public-api-reference)
   - [User & Profile Endpoints](#user--profile-endpoints)
   - [Post Endpoints](#post-endpoints)
   - [Comment Endpoints](#comment-endpoints)
   - [Follow Endpoints](#follow-endpoints)
   - [Registration Endpoints](#registration-endpoints)
7. [Building an Alternative Implementation](#building-an-alternative-implementation)
   - [Step 1 – Generate an RSA Key Pair](#step-1--generate-an-rsa-key-pair)
   - [Step 2 – Derive Your User ID](#step-2--derive-your-user-id)
   - [Step 3 – Register with a Goofy Media Instance](#step-3--register-with-a-goofy-media-instance)
   - [Step 4 – Authenticate Requests](#step-4--authenticate-requests)
   - [Step 5 – Create and Sign Content](#step-5--create-and-sign-content)
   - [Step 6 – Read Content from the Server](#step-6--read-content-from-the-server)
   - [Step 7 – Verify Content You Receive](#step-7--verify-content-you-receive)
8. [Planned Federation Features (Trusted Network)](#planned-federation-features-trusted-network)
9. [Reference: Error Responses](#reference-error-responses)

---

## Overview

Goofy Media is a decentralised social media platform. Rather than using ActivityPub, it defines its own cryptography-first federation model. The key ideas are:

- **No passwords.** Authentication is entirely RSA public-key based.
- **Deterministic identities.** A user's ID is derived deterministically from their RSA public key, so the same key always produces the same user ID on every server.
- **Signed content.** Every piece of content (post, comment, like, follow, profile update) carries an RSA signature that any party can verify independently.
- **Deterministic content IDs.** A post or comment UUID is derived from its own RSA signature, which means the same content always has the same ID everywhere.

These properties together allow content and identities to be verified and replicated across servers without any central authority.

---

## Core Design Principles

| Property | Mechanism |
|---|---|
| Identity | RSA-2048 public key |
| User ID | Derived from public key via PBKDF2 + word list |
| Content ID | Derived from the content's RSA signature via PBKDF2 |
| Authentication | RSA signature over each HTTP request body |
| Content integrity | RSA signature stored alongside every content object |
| Replay protection | Per-request nonce (`X-Goofy-ID`) + time window |

---

## Cryptographic Primitives

### RSA Key Pairs

Every user or federated actor generates a single RSA key pair (2048-bit recommended). The **private key never leaves the client**. The **public key** is submitted at registration time and stored by the server. All subsequent authentication and content verification uses this key pair.

The implementation uses [JSEncrypt](https://github.com/travist/jsencrypt) for RSA operations and [CryptoJS](https://github.com/brix/crypto-js) for SHA-256 hashing.

### User ID Derivation

A user ID is a human-readable string derived deterministically from the RSA public key using PBKDF2 and a word list. The algorithm is:

```
primaryHash = PBKDF2-SHA256(
    data       = publicKey,
    salt       = "GoofyUserHash123",
    keySize    = 32 bytes  (keySize parameter = 8, each word = 4 bytes),
    iterations = 1_000_000
)
```

From `primaryHash`, three additional values are derived (each using separate CryptoJS PBKDF2 calls with 1,234 iterations):

1. **Word count** (`c`): derived with salt `"GoofyUserLenHash123"`, result modulo 3, then `c = 2 + (result % 3)` → always 2, 3, or 4 words.
2. **Number suffix** (`n`): derived with salt `"GoofyUserValHash123"`, result modulo 1,000 → always 0–999.
3. **Each word** (`words[i]`): iteratively derived. For each word position, a new hash is generated with salt `"GoofyWordHash123"`, the result is used as an index into the word list (~134,611 common English words). Then the hash is re-derived with salt `"GoofyNewUserHash123"` and used as input for the next word.

The final user ID has the form:

```
word1_word2_word3<number>     e.g.  "alpha_bravo_charlie42"
word1_word2<number>           e.g.  "delta_echo7"
word1_word2_word3_word4<number>     (rare)
```

**Same public key → same user ID on every Goofy Media instance.**

### Content UUID Derivation

Post and comment UUIDs are derived from the content's RSA signature:

```
rawHash = PBKDF2-SHA256(
    data       = JSON.stringify(signature),
    salt       = "GoofyUserHash123",
    keySize    = 32 bytes,
    iterations = 789
)
```

`rawHash` is a Base64 string. To make it URL-safe:
- Replace `+` → `a`
- Replace `/` → `b`
- Replace `=` → `c`

The UUID is the **first 20 characters** of the resulting string.

**Same signature → same UUID everywhere.**

---

## Request Authentication

### X-Goofy-* Headers

Every authenticated request must include the following HTTP headers:

| Header | Type | Description |
|---|---|---|
| `X-Goofy-ID` | integer | A unique nonce for this request (must be ≥ 0). Used for replay prevention. |
| `X-Goofy-Signature` | string (URL-encoded) | RSA signature over the request hash (see below). |
| `X-Goofy-Valid-Until` | integer | Unix timestamp **in milliseconds** indicating when this request expires. |
| `X-Goofy-Public-Key` | string (URL-encoded) | The sender's RSA public key in PEM format. |
| `X-Goofy-Raw` | `"true"` (optional) | Set to `"true"` for file upload requests. The string `"FILE"` is signed instead of the body. |

### Signing a Request

To sign a request:

1. Choose a unique integer **id** (e.g. a random positive integer or incrementing counter).
2. Choose **validUntil** = current Unix time in milliseconds + a small margin (e.g. 30 000 ms).
3. Construct the signing object:
   ```json
   { "body": <request body object>, "id": <id>, "validUntil": <validUntil> }
   ```
   For requests with no body, use `{}` as the body value.
4. Compute `hash = CryptoJS.SHA256(JSON.stringify(signingObject)).toString(CryptoJS.enc.Base64)`.
5. Sign `hash` with your RSA private key using `JSEncrypt.sign(hash, CryptoJS.SHA256)`.
6. URL-encode the resulting signature and your public key.
7. Set the four (or five) headers.

**Important:** The `body` field in step 3 must be the **parsed JavaScript object** (not a re-serialised string of the body), so that `JSON.stringify` produces a canonical form consistent with what the server reconstructs from the parsed request body.

Example (pseudo-code):
```js
const id = Math.floor(Math.random() * 1e9);
const validUntil = Date.now() + 30000;

const signingObj = { body: requestBody, id, validUntil };
const hash = CryptoJS.SHA256(JSON.stringify(signingObj)).toString(CryptoJS.enc.Base64);

const encryptor = new JSEncrypt();
encryptor.setPrivateKey(privateKeyPem);
const signature = encryptor.sign(hash, CryptoJS.SHA256, "sha256");

headers["X-Goofy-ID"] = String(id);
headers["X-Goofy-Signature"] = encodeURIComponent(signature);
headers["X-Goofy-Valid-Until"] = String(validUntil);
headers["X-Goofy-Public-Key"] = encodeURIComponent(publicKeyPem);
```

### Replay-Attack Prevention

The server enforces a **time window** for each request:

```
(validUntil - 8 000 ms)  <  current server time  <  (validUntil + 60 000 ms)
```

In plain terms:
- A request may arrive **up to 8 seconds after** `validUntil` (clock-skew tolerance).
- A request cannot be sent more than **60 seconds into the future**.

In addition, the server maintains an in-memory list of `(publicKey, id)` pairs that have been seen within the valid window. Any request that reuses the same `(publicKey, id)` pair is rejected as a potential replay. Choose a different `id` for every request.

---

## Data Models and Content Signatures

### Post Signature

Before submitting a post, the client signs the **post body** (not the outer request body):

```json
{
  "title": "Post title (max 200 chars)",
  "text":  "Post body text (max 5000 chars)",
  "tags":  ["tag1", "tag2"],
  "createdAt": 1700000000000
}
```

Signing:
```js
const hash = CryptoJS.SHA256(JSON.stringify(postBody)).toString(CryptoJS.enc.Base64);
const signature = encryptor.sign(hash, CryptoJS.SHA256, "sha256");
```

The full post submission body sent in the HTTP request is:
```json
{
  "post": {
    "post": {
      "title": "...",
      "text": "...",
      "tags": ["..."],
      "createdAt": 1700000000000
    },
    "signature": "<rsa-signature>",
    "userId": "<your-user-id>"
  }
}
```

Tag rules:
- All tags must be **lowercase** strings.
- Tags must not contain `#`.
- Maximum tag length: 100 characters.
- Maximum 50 tags per post.
- `createdAt` must not be more than 10 seconds in the future.

### Comment Signature

The comment body that is signed:

```json
{
  "text":             "Comment text (max 1000 chars)",
  "postUuid":         "<uuid-of-the-post>",
  "createdAt":        1700000000000,
  "replyCommentUuid": "<uuid-of-parent-comment-or-null>"
}
```

The full comment submission body:
```json
{
  "comment": {
    "comment": {
      "text": "...",
      "postUuid": "...",
      "createdAt": 1700000000000,
      "replyCommentUuid": null
    },
    "signature": "<rsa-signature>",
    "userId": "<your-user-id>"
  }
}
```

---

## Public API Reference

All endpoints are relative to the server's base URL (e.g. `https://media.example.com`).

Endpoints marked **public** require no authentication headers.

### User & Profile Endpoints

#### `GET /user/user-data/:userId/public-key` — **public**

Returns the RSA public key for a given user ID.

```
Response 200:
{
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

This is the primary federation lookup endpoint. Use it to retrieve a remote user's public key before verifying content they authored.

---

#### `GET /user/public-info/user/:userId` — **public**

Returns the public profile of a user.

```
Response 200:
{
  "displayName":       "Alice",
  "profileBio":        "Developer and coffee enthusiast",
  "profilePronouns":   "she/her",
  "profileLinks":      "[{\"label\":\"Website\",\"url\":\"https://...\"}]",
  "profileCustomCSS":  "",
  "profilePictureUrl": "https://...",
  "profileBannerUrl":  "https://...",
  "pinnedPostUuid":    "abc123defg789hij",
  "updatedAt":         1700000000000,
  "signature":         "<rsa-signature-of-profile-data>"
}
```

---

#### `GET /user/user-data/like/:query` — **public**

Returns a list of user IDs that begin with the given prefix (autocomplete).

```
Response 200: ["alpha_bravo42", "alpha_charlie7", ...]
```

---

### Post Endpoints

#### `GET /user/post/` — **public**

Returns the most recent posts (paginated). Pagination is controlled by HTTP request headers (not query parameters):
- `query-limit` (integer, default 50, max 50)
- `query-start` (integer, default 0 — offset into the result set)

```
Response 200:
[
  {
    "post": {
      "title":    "...",
      "text":     "...",
      "tags":     ["tag1"],
      "createdAt": 1700000000000
    },
    "signature":    "<rsa-signature>",
    "uuid":         "abc123defg789hij",
    "commentCount": 3,
    "userId":       "alpha_bravo42"
  },
  ...
]
```

---

#### `GET /user/post/uuid/:uuid` — **public**

Returns a single post by its UUID.

```
Response 200: (same structure as a single entry above)
```

---

#### `GET /user/post/user/:userId` — **public**

Returns all posts authored by a specific user.

```
Response 200: (array of post objects)
```

---

#### `GET /user/post/tag/:tag` — **public**

Returns posts that include the given tag.

---

#### `POST /user/post/` — **requires authentication (registered user)**

Creates a new post. Request body format described in [Post Signature](#post-signature).

```
Response 200: "Post added"
```

---

#### `DELETE /user/post/uuid/:uuid` — **requires authentication (registered user)**

Deletes a post. Only the post author (or an admin) may delete a post.

---

#### `POST /user/post/verify` — **requires authentication (registered user)**

Verifies a post object without storing it. Useful for federated validation.

Request body:
```json
{ "post": <post-object-to-verify> }
```

```
Response 200: "OK"
Response 500: "<reason for failure>"
```

---

### Comment Endpoints

#### `GET /user/comment/post/:postUuid` — **public**

Returns all comments on a post.

```
Response 200:
[
  {
    "comment": {
      "text":             "...",
      "postUuid":         "...",
      "createdAt":        1700000000000,
      "replyCommentUuid": null
    },
    "uuid":       "...",
    "replyCount": 2,
    "userId":     "alpha_bravo42",
    "signature":  "<rsa-signature>"
  },
  ...
]
```

---

#### `GET /user/comment/comment/:uuid` — **public**

Returns a single comment by its UUID.

---

#### `GET /user/comment/comment/:commentUuid/replies` — **public**

Returns the direct replies to a comment.

---

#### `POST /user/comment/` — **requires authentication (registered user)**

Creates a new comment. Request body format described in [Comment Signature](#comment-signature).

---

### Follow Endpoints

#### `GET /user/follows/followers` — **requires authentication (registered user)**

Returns the list of users who follow the authenticated user.

---

#### `GET /user/follows/following` — **requires authentication (registered user)**

Returns the list of users the authenticated user is following.

---

#### `GET /user/follows/user/:userId` — **requires authentication (registered user)**

Returns whether the authenticated user is following `userId`.

---

#### `POST /user/follows/user` — **requires authentication (registered user)**

Follow a user. Request body:
```json
{ "follow": { "follow": { "followingUserId": "<target-user-id>", "createdAt": 1700000000000 }, "signature": "<rsa-signature>", "userId": "<your-user-id>" } }
```

---

#### `DELETE /user/follows/user/:userId` — **requires authentication (registered user)**

Unfollow a user.

---

### Registration Endpoints

#### `GET /guest/register/code/:code` — **public**

Check whether an invite code is valid and unused.

```
Response 200: "Code available"
Response 400: "Code not available"
```

---

#### `POST /guest/register/code` — **requires authentication (any key)**

Register a new user account. The request must be signed with the new user's key pair.

Request body:
```json
{ "code": "<invite-code>" }
```

```
Response 200: "Register success"
Response 400: "Register code not available" | "Failed to register user"
```

On success, the server stores the public key from the `X-Goofy-Public-Key` header and associates it with the user ID derived from that key. The invite code is consumed.

---

## Building an Alternative Implementation

This section describes every step required to build a client or server that interoperates with a Goofy Media instance.

### Step 1 – Generate an RSA Key Pair

Generate an RSA key pair (2048-bit minimum). Keep the private key secret; the public key is your identity.

```js
// Using JSEncrypt (browser / Node.js):
const crypt = new JSEncrypt({ default_key_size: 2048 });
crypt.getKey();
const publicKey  = crypt.getPublicKey();   // PEM string
const privateKey = crypt.getPrivateKey();  // PEM string – keep this secret
```

You can also use any standard RSA library (OpenSSL, Node's `crypto`, etc.) as long as the key is in PEM format.

### Step 2 – Derive Your User ID

Use the [User ID Derivation](#user-id-derivation) algorithm above to compute the user ID from your public key. This ID is **deterministic**: any conforming implementation will arrive at the same ID for the same public key.

### Step 3 – Register with a Goofy Media Instance

Registration requires an invite code issued by an administrator of the target instance.

1. Sign a request body of `{ "code": "<invite-code>" }` following [Signing a Request](#signing-a-request).
2. `POST /guest/register/code` with the authentication headers and the JSON body.
3. On success, your public key and user ID are stored on the server.

### Step 4 – Authenticate Requests

Every write operation (and some read operations) requires the authentication headers described in [X-Goofy-* Headers](#x-goofy--headers). Use a fresh, unique `X-Goofy-ID` and a suitable `X-Goofy-Valid-Until` for every request.

### Step 5 – Create and Sign Content

For posts:
1. Construct the post body: `{ title, text, tags, createdAt }`.
2. Compute `hash = SHA256(JSON.stringify(postBody))` as Base64.
3. Sign `hash` with your private key using RSA: `signature = rsa.sign(hash)`.
4. Wrap in the submission envelope (see [Post Signature](#post-signature)) and POST to `/user/post/`.

For comments:
1. Construct the comment body: `{ text, postUuid, createdAt, replyCommentUuid }`.
2. Sign the same way.
3. Wrap and POST to `/user/comment/`.

The server will:
- Verify the content signature against the public key on file for your user ID.
- Derive the UUID from the signature and store the content.

### Step 6 – Read Content from the Server

All post and comment listing endpoints are public (no authentication required). Fetch and display content using the GET endpoints listed above. Pagination is controlled by HTTP request headers (not query parameters):
- `query-limit` (integer, default 50, max 50)
- `query-start` (integer, default 0 — offset into the result set)

To read content authored by a specific user:
```
GET /user/post/user/<userId>
```

To look up a user's public key (needed for verification):
```
GET /user/user-data/<userId>/public-key
```

### Step 7 – Verify Content You Receive

Every post and comment object contains a `signature` field. To verify it:

1. Look up the author's public key: `GET /user/user-data/<userId>/public-key`.
2. Confirm that `userId` is the correct derivation of the public key (run the [User ID Derivation](#user-id-derivation) algorithm on the retrieved key and compare).
3. Reconstruct the signed object:
   - For posts: `{ title, text, tags, createdAt }` (exactly these four fields, in this order).
   - For comments: `{ text, postUuid, createdAt, replyCommentUuid }`.
4. Compute `hash = SHA256(JSON.stringify(contentObject))` as Base64.
5. Verify the signature: `rsa.verify(hash, signature, publicKey)`.
6. Optionally verify the UUID by running [Content UUID Derivation](#content-uuid-derivation) on the signature and comparing to the `uuid` field.

A complete verification chain guarantees that:
- The content was authored by the holder of the private key matching the stored public key.
- The content has not been tampered with.
- The user ID is authentically derived from the same public key.

---

## Planned Federation Features (Trusted Network)

The codebase contains stubs for a **trusted guest user** mechanism that will underpin server-to-server federation. These functions are currently empty and are intended for future implementation:

```js
// services/db/users.js

// Add a user from a federated instance to the local trusted list
addTrustedGuestUserIfNotExists(userId, publicKey)

// Remove a trusted federated user
removeTrustedGuestUser(userId)

// Look up a trusted federated user by ID
getTrustedGuestUser(userId)
```

The `getPublicKeyFromUserId` function (used during content verification) already has comments indicating the intended federation lookup order:

```js
// 1. Check locally registered users
// 2. Check trusted / guest users  ← stub, not yet implemented
// 3. Ask other servers in trusted network  ← stub, not yet implemented
```

When implemented, this will allow a Goofy Media instance to:
- Cache public keys for users registered on other instances.
- Resolve unknown user IDs by querying a network of trusted peer servers.
- Accept content signed by users from trusted instances without requiring them to re-register locally.

An alternative implementation that wants to federate with future Goofy Media trusted-network features should:
- Expose a `GET /<userId>/public-key` endpoint (or equivalent) for key resolution.
- Be prepared to receive and respond to inter-server requests for user public keys.

---

## Reference: Error Responses

| HTTP Status | Meaning |
|---|---|
| `400 Bad Request` | Missing or malformed parameters |
| `401 Unauthorized` | Authentication failed (bad/missing headers, expired timestamp, invalid signature, unregistered user) |
| `403 Forbidden` | Authenticated but not permitted (e.g. deleting another user's post) |
| `500 Internal Server Error` | Server-side processing failure or content verification failure |

Common `401` messages:
- `"Unsigned request unauthorized"` – required headers are absent.
- `"Signature verification failed: VALID UNTIL EXPIRED"` – `validUntil` is too far in the past.
- `"Signature verification failed: VALID UNTIL TOO FAR IN THE FUTURE"` – `validUntil` is more than 60 seconds ahead.
- `"Signature verification failed: ID ALREADY USED"` – nonce reuse detected.
- `"Signature verification failed: SIGNATURE INVALID"` – signature does not match body/key.
- `"Non-Registered request unauthorized"` – user has not registered on this instance.
