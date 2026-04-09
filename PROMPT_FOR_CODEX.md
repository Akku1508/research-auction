Build a **FULL decentralized auction website** with folder structure:
- `backend/` for Flask + MongoDB + crypto modules
- `frontend/` for templates/static files

Must include:
1. Login page (username/password + signup link)
2. Signup page (full name, email, phone, username, password, role bidder/auctioneer)
3. Dashboard with profile icon/info/past activity/auctions
4. Bidder flow: view open/closed auctions, participate, generate keys, bid using Pedersen commitment + ring signature, then do OT secret retrieval after auctioneer triggers share button
5. Auctioneer flow: create auction(title, bidder limit, time), join auctions as auctioneer (multi-auctioneer), enforce auction starts only when k auctioneers join, trigger secret share distribution, run Shamir + ZKP verification + winner selection

Cryptography logic to implement strictly:
- Ring signatures for anonymity
- Pedersen commitment: `C_i = g^b_i * h^r_i`
- OT retrieval where bidder gets only `c_j`, auctioneer does not know `j`
- ZK opening proof:
  - `T = g^u * h^v`
  - `z1 = u + e*b_i`, `z2 = v + e*r_i`
  - verify `g^z1 * h^z2 == T * C_i^e`
- Shamir secret sharing:
  - `f(x) = S + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)`
- Max-bid proof:
  - `C_w = v_w*G + r_w*H`
  - `D_j = C_w - C_j`
  - prove `D_j = d_j*G + rho_j*H` with `d_j >= 0`

Database collections:
- users: username, password(hash), role, public_key
- auctions: title, status, bidders, auctioneers, commitments, shares, winner
- bids: auction_id, bidder_id, commitment, revealed_bid, randomness

Security:
- never expose private keys
- never store raw bids before reveal
- hashed passwords
- modular files exactly:
  - `backend/crypto/commitment.py`
  - `backend/crypto/ring_signature.py`
  - `backend/crypto/oblivious_transfer.py`
  - `backend/crypto/zk_proof.py`
  - `backend/crypto/shamir.py`

Routes required:
- login/signup
- create auction
- bid submission
- verification
- winner declaration

Output must be complete runnable project with clean comments on each crypto stage.
