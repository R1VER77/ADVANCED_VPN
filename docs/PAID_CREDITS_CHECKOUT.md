# Paid credits: an account-free crypto checkout

Status: **design, not built** (22 November 2026; payment rail and onion-only
checkout settled the same evening). Decision: [D020](DECISIONS.md). Nothing here is
offered for sale until the gates in §8 are met; until then it runs on Zcash testnet only.

In short:
- payment in **shielded Zcash only**;
- the checkout is reachable **only as a Tor onion service**;
- what the customer gets is blind tokens, not an account.

## 1. What is being sold, and to whom

People who cannot or will not run a server of their own buy **credits**: the same
blind-signed tokens that members earn by contributing a relay
([mesh design](MESH_DESIGN.md) §6, `tools/mesh_tokens.py`). A credit is spent to
carry traffic through a chain.

**Paid credits buy capacity only on relays and exits the project itself operates.**
Members' contributed servers stay outside the paid pool, for three reasons:
- abuse reports and legal process for a paying customer's traffic should reach the
  operator who was paid, not a volunteer;
- the free cloud accounts most members use may forbid carrying a paying third party's
  traffic;
- paying members for capacity would make the project an intermediary passing money
  between people, the line [D020](DECISIONS.md) declines (exit micropayments).

## 2. Design goal

The seller can learn **that** some payment arrived, but cannot learn **which traffic**
it paid for. The servers that carry traffic can learn **that** a credit is valid, but
not **who** paid for it.

This separation comes from the blind signature, not from the coin. The coin decides
only how well the step "this customer paid the project" is hidden on its blockchain
(§5).

## 3. How Mullvad does it, and what changes here

What Mullvad publishes:
- One click makes a random account number; no email, name or password.
- It runs its own wallet and node for Monero, with no payment processor.
- For a Monero payment it keeps the transaction hash beyond 20 days (to refuse
  crediting it twice), plus the amount, currency and date (the date truncated after
  20 days).
- No refunds for cryptocurrency; a 10% discount for paying in it.
- It does not publish how a payment is matched to an account, or how many
  confirmations it waits for. It has published no position on the EU rule for
  privacy coins (below).

Sources: [Monero announcement](https://mullvad.net/en/blog/2022/5/3/we-now-accept-monero),
[pricing](https://mullvad.net/en/pricing),
[no-logging data policy](https://mullvad.net/en/help/no-logging-data-policy) (updated
17 June 2026), [refunds](https://mullvad.net/en/help/refunds) (updated 26 August 2026).

**The difference:** Mullvad credits time to an account. Here there is no account. What
the customer holds after paying is a set of blind tokens, which nothing on the seller's
side can link back to the order.

**The EU rule** (Regulation (EU) 2024/1624, Article 79, from 10 July 2027) forbids
credit institutions, financial institutions and crypto-asset service providers from
handling anonymity-enhancing coins. It does not bind a business that is paid directly,
into its own wallet, for its own service. This design is built that way: no payment
processor, no customer balances, no custody of anyone's coins.

## 4. The flow

```
App (customer)                    Checkout (project)              Mint (project)
-------------                    ------------------              --------------
1. order id (random 128-bit),
   tier, blinded tokens  ───────►  2. fresh payment address
                                      for this order, price,
                          ◄───────    expiry
3. customer pays from
   their own wallet      ───────►  4. view-only watcher sees
                                      the payment, waits for
                                      confirmations
                                   5. order paid  ─────────────►  6. sign the blinded
                                                                     tokens
                          ◄─────────────────────────────────────────
7. unblind; tokens are
   ready to spend
                                   8. keep tx hash, amount, date;
                                      delete the order
```

1. **Order.** The app draws a random order ID and creates the blinded tokens locally.
   The tier fixes how many tokens and of which rate class. The app reaches the
   checkout **only through Tor, at the checkout's onion service**, so the checkout never
   learns the customer's address; there is no clearnet address to fall back to.
2. **Address.** The checkout derives a **fresh receiving address for this order only**:
   - a unified address with an **Orchard receiver only**, from the project's viewing key;
   - no Sapling receiver and no transparent receiver.

   Since NU6.3, a wallet paying an Orchard receiver must send in the **Ironwood pool**
   (ZIP 326), the pool whose notes are quantum-recoverable (§5). No address is ever
   published or reused; §5 explains why that matters against a future quantum computer.
3. **Pay.** The customer pays the exact price from any wallet. Prices are fixed per
   tier, so amounts carry no per-customer pattern.
4. **Watch.** A watcher holding **view-only keys** (no spending keys on any server)
   detects the payment. It credits the order after a confirmation count, a design
   parameter to fix before launch (on the order of 10 blocks). The chain data comes
   from public lightwalletd/Zaino servers through Tor. A payment is credited only when
   a second, independent server returns the same transaction and its proofs verify
   locally, so one lying server cannot fake a payment.
   - Underpayment: the order stays open until it expires.
   - Overpayment: issues the tier paid for; there are no refunds in coin, as at Mullvad.
5. **Issue.** The mint signs the blinded tokens for the tier paid. It never sees the
   unblinded tokens, so the tokens later shown to a relay cannot be matched to this
   order (the blinding is perfectly hiding: [D018](DECISIONS.md)).
6. **Spend.** Tokens are spent as members' credits are: one per unit of traffic, daily
   epochs, double spends refused.
7. **Record.** The order is deleted. The ledger keeps what tax and double-crediting
   need and nothing more: coin, amount, transaction hash, date, tier.
   - It records no token, no order ID after issuance, and no address of the customer.
   - Its retention period is set in the service's privacy notice (§8).

**Remaining linkage, and its mitigation.** Spending tokens right after buying them links
the purchase and the first use by timing. The daily epochs blunt this, and the app
should hold fresh tokens until the next epoch by default.

## 5. Zcash shielded, and what that does and does not give

The payment step only tells the world, at worst, that someone paid the project; the
blind tokens keep it from saying for what. Payment is **shielded Zcash only**: sender,
receiver and amount are hidden in the shielded pool. No transparent payment is accepted.

**Against a future quantum computer, be precise** (ZIP 2005, Final; Ironwood pool created
at NU6.3, mainnet height 3428143):
- **Quantum recoverability protects funds, not privacy.** Notes in the Ironwood pool can
  later be recovered by a future Recovery Protocol if elliptic-curve cryptography falls.
  That protocol is outlined, not yet specified. Older Orchard and Sapling notes are not
  covered.
- **Privacy against a quantum adversary holds only if the adversary does not know the
  receiving address.** ZIP 2005 retains the current privacy "against post-quantum
  adversaries without knowledge of the notes' addresses". A fresh, never-published
  address per order (§4) keeps that condition true for the payment to the project.
- **So payments are never advertised as "quantum-private".** The accurate claim:
  shielded today; quantum-recoverable funds in Ironwood; private against a quantum
  adversary who never learns the order's address.

**Wallet requirements:**
- The watcher must scan the **Ironwood pool**: `zcash_client_backend` 0.24 or later.
  A wallet that does not scan it would miss payments.
- Orchard-pool payments from wallets that predate ZIP 326 are credited too. The offline
  treasury then migrates them to Ironwood (ZIP 318).

**Why not other coins** (checked 22 November 2026):
- **Monero:** its quantum-resistant addressing (Carrot, with FCMP++) is not on mainnet.
  The latest release is 0.18.5.4 (16 October 2026); a test network forked on 5 October;
  a developer's non-binding draft aims at about March 2027.
- **Abelian:** the only live coin claiming lattice-based hiding of sender, receiver and
  amount, but:
  - its sender hides among only 7 coins (`TxoRingSize = 7`, `pqabelian/abec`);
  - its schemes are its own variants of Kyber and Dilithium, not ML-KEM and ML-DSA;
  - no independent audit was found;
  - its markets are thin.
- **No other live coin** offered post-quantum privacy: Lattix, QRL, Nervos CKB and
  Algorand have post-quantum signatures at most.

**Why no swap chain.** An earlier idea routed a payment Zcash → Abelian → Zcash or
Monero. A round trip does not protect the first leg, which stays on its chain. A swap
also runs through an exchange that sees both sides, adding a third party that can link
them.

**The project's own coins.** Moving revenue afterwards is the project's treasury
business. It never touches a customer's privacy, because the customer's link ends at
step 3.

## 6. Keys and servers

- **Watcher:** view-only keys only. Losing the watcher exposes which payments arrived;
  it cannot spend.
- **Spending keys:** offline, never on a networked server.
- **Mint:** the signing key per epoch (as `tools/mesh_tokens.py`), held on the mint
  only.
- **Checkout, mint and watcher:** run on servers the project operates, under the same
  egress lock and no-logging rules as its relays. The checkout keeps an order only until
  issuance or expiry.

## 7. What is classical and what is post-quantum

| Part | Today | Note |
|---|---|---|
| Token unforgeability (public pool) | Classical: Chaum blind RSA-FDH | A quantum adversary could forge tokens; the mint's key rotation and spent-set limit the damage. |
| Token unlinkability | Survives a quantum adversary | Perfectly hiding blinding ([D018](DECISIONS.md)). |
| Customer → project payment | Shielded Zcash: elliptic-curve today | Funds in Ironwood are quantum-recoverable; privacy holds against a quantum adversary only without the address (§5). |
| Checkout connection | Tor onion service only | Hides the customer's address from the checkout. Tor's own handshakes are classical today. |

## 8. Gates before the first sale

1. **The data plane accepts credit spends.** Today the Rust data plane refuses every
   public-pool spend until a reviewed constant-time verifier is vendored (mesh design
   §6; [credit review](MESH_CREDIT_REVIEW_20261122.md)). Nothing can be sold before
   that.
2. **Voucher issuance and redemption are specified and proved**: the open roadmap item.
3. **A service layer** in the terms and privacy notice, separate from the software's,
   naming:
   - the seller;
   - the ledger and its retention period;
   - what refunds exist (none in coin);
   - acceptable use and abuse handling for the project's exits.
4. **An end-to-end testnet purchase** over a real onion service, with a forged-server
   test refused by the two-server check.
5. **The confirmation counts, prices and token amounts** per tier, fixed and published.
6. **The voucher tier is signed.** Today `tools/voucher.py` signs every tier with one
   key and carries the tier as an unsigned field, so a cheaper voucher could be
   presented as a dearer one. Use one key per tier, or put the tier in the signed
   input.
