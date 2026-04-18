# NumKeys Protocol Sequence Diagrams

**Author**: Bernard Parah

## Table of Contents

### Issuance Flow
1. [Step 1: User Keypair Generation](#step-1-user-keypair-generation)
2. [Step 2: Phone Verification Request](#step-2-phone-verification-request)
3. [Step 3: Proxy Number Generation](#step-3-proxy-number-generation)
4. [Step 4: Attestation Creation](#step-4-attestation-creation)
5. [Step 5: Saving to Wallet](#step-5-saving-to-wallet)

### Verification Flow
7. [Step 7: Service Integration - Initial Setup](#step-7-service-integration-initial-setup)
8. [Step 8: User Registration with Proxy](#step-8-user-registration-with-proxy)
9. [Step 9: Challenge Creation](#step-9-challenge-creation)
10. [Step 10: Wallet Interaction](#step-10-wallet-interaction)
11. [Step 11: Verification Process](#step-11-verification-process)
12. [Step 12: Offline Verification](#step-12-offline-verification)

### System Overview
13. [Complete System Flow](#complete-system-flow)

---

## Issuance Flow

### Step 1: User Keypair Generation

```mermaid
sequenceDiagram
    participant User
    participant Wallet

    User->>Wallet: Open wallet app
    User->>Wallet: Request new proxy number
    
    Note over Wallet: Generate cryptographic identity
    Wallet->>Wallet: Generate Ed25519 keypair
    Wallet->>Wallet: sk_u = random 32 bytes
    Wallet->>Wallet: pk_u = derive public key
    
    Wallet->>Wallet: Store sk_u securely
    Wallet->>User: Ready to proceed ✓
```

### Step 2: Phone Verification Request

```mermaid
sequenceDiagram
    participant Wallet
    participant Issuer

    Wallet->>Wallet: User enters phone: +1234567890
    Wallet->>Wallet: User selects scope: "1" (US)
    
    Wallet->>Issuer: POST /attest
    Note over Wallet,Issuer: {<br/>  phone_number: "+1234567890",<br/>  user_pubkey: "pk_u_base64url",<br/>  scope: "1"<br/>}
    
    Issuer->>Issuer: Validate request
    Issuer->>Issuer: Run phone-verification process
    Note over Issuer: SMS OTP, voice verification,<br/>carrier API, or equivalent
```

### Step 3: Proxy Number Generation

```mermaid
sequenceDiagram
    participant Issuer

    Note over Issuer: Generate proxy deterministically
    
    Issuer->>Issuer: nonce = random 128 bits<br/>"0123456789abcdef0123456789abcdef"
    
    Issuer->>Issuer: Build input string
    Note over Issuer: phone + "|" + user_pubkey + "|" +<br/>domain + "|" + scope + "|" + nonce
    
    Issuer->>Issuer: hash = SHA256(input)
    Issuer->>Issuer: Extract decimal digits
    Note over Issuer: For each hex char: digit = hex % 10
    
    Issuer->>Issuer: proxy = "+100" + first_10_digits
    Note over Issuer: Result: "+10012345678"
```

### Step 4: Attestation Creation

```mermaid
sequenceDiagram
    participant Issuer

    Note over Issuer: Create attestation JWT
    
    Issuer->>Issuer: phone_hash = SHA256("1234567890")
    Note over Issuer: "sha256:c775e7b757ede..."
    
    Issuer->>Issuer: Create binding proof
    Note over Issuer: message = "numkeys-binding" + "|" + iss + "|" + sub + "|" +<br/>phone_hash + "|" + user_pubkey + "|" + nonce + "|" + iat + "|" + jti
    
    Issuer->>Issuer: sig = Sign(sk_i, UTF8(message))
    Issuer->>Issuer: binding_proof = "sig:" + base64url(sig)
    
    Issuer->>Issuer: Build JWT payload
    Note over Issuer: {<br/>  iss: "issuer.com",<br/>  sub: "+10012345678",<br/>  iat: 1720000000,<br/>  jti: "11111111-1111-4111-8111-111111111111",<br/>  phone_hash: "sha256:...",<br/>  user_pubkey: "pk_u",<br/>  binding_proof: "sig:...",<br/>  nonce: "0123456789abcdef..."<br/>}
    
    Issuer->>Issuer: Sign JWT with sk_i
```

### Step 5: Saving to Wallet

```mermaid
sequenceDiagram
    participant Issuer
    participant Wallet
    participant Storage

    Issuer->>Wallet: 200 OK
    Note over Issuer,Wallet: {<br/>  proxy_number: "+10012345678",<br/>  attestation: "eyJ0eXAiOiJKV1Q..."<br/>}
    
    Wallet->>Wallet: Validate response
    Wallet->>Wallet: Parse attestation JWT
    
    Wallet->>Storage: Save attestation
    Wallet->>Storage: Map to proxy number
    Wallet->>Storage: Associate with keypair
    
    Wallet->>Wallet: Display success
    Note over Wallet: "Your proxy number:<br/>+10012345678"
```

---

## Verification Flow

### Step 7: Service Integration - Initial Setup

```mermaid
sequenceDiagram
    participant Developer
    participant Service
    participant Code

    Developer->>Code: Integrate verifier logic
    Note over Code: Use the published protocol rules,<br/>test vectors, and reference implementation
    
    Developer->>Service: Deploy integration
    Service->>Service: Ready to verify proxies ✓
```

### Step 8: User Registration with Proxy

```mermaid
sequenceDiagram
    participant User
    participant Service

    User->>Service: Sign up / Log in
    User->>Service: Phone: +10012345678
    
    Service->>Service: Detect proxy pattern
    Note over Service: Pattern: +{country_code}00{digits}
    
    Service->>Service: Proxy detected!
    Service->>Service: Initiate verification flow
    Service->>User: "Please verify your phone"
```

### Step 9: Challenge Creation

```mermaid
sequenceDiagram
    participant Service
    participant Database

    Service->>Service: Generate challenge
    Note over Service: {<br/>  proxy_number: "+10012345678",<br/>  service_id: "app.example.com",<br/>  challenge_nonce: crypto.random(16),<br/>  verification_id: "verify_12345",<br/>  expires_at: Date.now() + 300000,<br/>  callback_url: "https://app.example.com/callback"<br/>}
    
    Service->>Service: Create callback URL
    Note over Service: /verify/callback/abc123
    
    Service->>Database: Store challenge
    Database->>Service: Challenge ID: abc123
    
    Service->>Service: Encode as QR code
    Service->>Service: Display to user
```

### Step 10: Wallet Interaction

```mermaid
sequenceDiagram
    participant User
    participant Wallet
    participant Service

    User->>Wallet: Scan QR code
    Wallet->>Wallet: Decode challenge
    
    Wallet->>Wallet: Find attestation
    Note over Wallet: Lookup by proxy: +10012345678
    
    Wallet->>User: Show approval dialog
    Note over Wallet: "app.example.com wants to<br/>verify your phone number"
    
    User->>Wallet: ✓ Approve
    
    Wallet->>Wallet: Build canonical response payload
    Note over Wallet: {<br/>  service_id: "app.example.com",<br/>  challenge_nonce: "a1b2c3d4e5f6",<br/>  response_nonce: "f6e5d4c3b2a1",<br/>  verification_id: "verify_12345",<br/>  timestamp: 1720000100000<br/>}
    Wallet->>Wallet: Sign canonical JSON payload
    
    Wallet->>Service: POST /verify/callback/abc123
    Note over Wallet,Service: {<br/>  proxy_number: "+10012345678",<br/>  attestation_jwt: "eyJ0eXA...",<br/>  challenge_response: {...},<br/>  user_signature: "sig_base64url"<br/>}
```

### Step 11: Verification Process

```mermaid
sequenceDiagram
    participant Service
    participant Cache
    participant Issuer Domain

    Note over Service: Extract issuer from JWT
    Service->>Service: iss = "issuer.com"
    
    Service->>Cache: Get public key for issuer.com
    
    alt Not cached
        Cache->>Issuer Domain: GET /.well-known/numkeys/pubkey.json
        Issuer Domain->>Cache: {public_key: "pk_i", ...}
        Cache->>Cache: Store with TTL
    end
    
    Cache->>Service: Return pk_i
    
    Note over Service: Verify attestation
    Service->>Service: Verify JWT signature with pk_i ✓
    Service->>Service: Check iat freshness policy ✓
    Service->>Service: Verify binding proof with pk_i ✓
    
    Note over Service: Verify user consent
    Service->>Service: Extract pk_u from attestation
    Service->>Service: Verify canonical response payload with pk_u ✓
    Service->>Service: Check verification_id and challenge_nonce ✓
    Service->>Service: Check response_nonce not reused ✓
    
    Service->>Service: All checks passed! ✅
```

### Step 12: Offline Verification

```mermaid
sequenceDiagram
    participant User
    participant Service
    participant Local Cache

    Note over Service: Subsequent verification
    Note over Service: (issuer key already cached)
    
    User->>Service: Provide attestation
    
    Service->>Local Cache: Get issuer.com key
    Local Cache->>Service: Return cached pk_i
    
    Note over Service: All verification local
    Service->>Service: Verify JWT ✓
    Service->>Service: Verify binding ✓
    Service->>Service: Verify user sig ✓
    
    Note over Service: Complete in microseconds
    Service->>User: Verified! ✅
    
    Note over Service: No network calls needed
```

---

## System Overview

### Complete System Flow

```mermaid
graph LR
    subgraph "1. Setup"
        A[User] -->|Gets| B[NumKeys Wallet]
        B -->|Generates| C[Keypair]
    end
    
    subgraph "2. Issuance"
        C -->|Requests proxy| D[Issuer]
        D -->|Verifies phone| E[SMS/OTP]
        E -->|Confirms| D
        D -->|Issues| F[Attestation]
        F -->|Stored in| B
    end
    
    subgraph "3. Usage"
        B -->|Provides proxy| G[Service A]
        G -->|Challenges| B
        B -->|Signs| H[Response]
        H -->|Verifies| G
    end
    
    subgraph "4. Reuse"
        B -->|Same proxy| I[Service B]
        I -->|Offline verify| I
    end
    
    style A fill:#f9f
    style F fill:#9f9
    style G fill:#9ff
    style I fill:#ff9
```

## Key Points

1. **One-time issuance**: Users verify their phone, then receive a proxy and attestation
2. **Per-service consent**: Each service requires explicit user approval
3. **Offline capability**: After first key fetch, no network needed
4. **Privacy preserved**: Real numbers never shared with services
5. **User control**: Wallet manages all cryptographic operations
