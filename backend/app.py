import hashlib
import secrets
from datetime import datetime

from bson import ObjectId
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash

from crypto.commitment import PedersenCommitment
from crypto.common import curve, point_from_json, point_to_json
from crypto.oblivious_transfer import NaorPinkasTreeOT
from crypto.ring_signature import RingSignature
from crypto.shamir import reconstruct_secret, split_secret
from crypto.zk_proof import ZKProofs

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
)
app.secret_key = "change-me-in-production"

client = MongoClient("mongodb://localhost:27017/")
db = client["decentralized_auction"]
users_col = db["users"]
auctions_col = db["auctions"]
bids_col = db["bids"]

ring = RingSignature()
pedersen = PedersenCommitment()
ot_tree = NaorPinkasTreeOT()
zk = ZKProofs()


def serialize_auction(a):
    a["_id"] = str(a["_id"])
    return a


@app.route("/")
def root():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        data = request.form
        if users_col.find_one({"username": data["username"]}):
            flash("Username already exists")
            return redirect(url_for("signup"))

        sk, pk = ring.generate_keypair()
        users_col.insert_one(
            {
                "full_name": data["full_name"],
                "email": data["email"],
                "phone": data["phone"],
                "username": data["username"],
                "password": generate_password_hash(data["password"]),
                "role": data["role"],
                "public_key": point_to_json(pk),
                "private_key_hash": hashlib.sha256(str(sk).encode()).hexdigest(),
                "created_at": datetime.utcnow(),
                "past_activity": [],
            }
        )
        flash("Signup successful. Please login.")
        return redirect(url_for("login"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = users_col.find_one({"username": request.form["username"]})
        if user and check_password_hash(user["password"], request.form["password"]):
            session["user_id"] = str(user["_id"])
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = users_col.find_one({"_id": ObjectId(session["user_id"])})
    my_auctions = list(auctions_col.find({"$or": [{"bidders": session["user_id"]}, {"auctioneers": session["user_id"]}]}))
    return render_template("dashboard.html", user=user, auctions=[serialize_auction(a) for a in my_auctions])


@app.route("/auctions", methods=["GET", "POST"])
def auctions():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST" and session["role"] == "auctioneer":
        title = request.form["title"]
        bidder_limit = int(request.form["bidder_limit"])
        threshold_k = int(request.form["threshold_k"])
        auction = {
            "title": title,
            "status": "OPEN",
            "bidders": [],
            "auctioneers": [session["user_id"]],
            "bidder_limit": bidder_limit,
            "threshold_k": threshold_k,
            "time": request.form.get("time"),
            "commitments": [],
            "shares": [],
            "winner": None,
            "ot_ready": False,
            "ot_sender_state": None,
        }
        auctions_col.insert_one(auction)
        flash("Auction created")
        return redirect(url_for("auctions"))

    all_auctions = [serialize_auction(a) for a in auctions_col.find().sort("_id", -1)]
    return render_template("auctions.html", auctions=all_auctions, role=session["role"])


@app.route("/auction/<auction_id>/join_auctioneer", methods=["POST"])
def join_auctioneer(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))
    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$addToSet": {"auctioneers": session["user_id"]}})
    flash("Joined as auctioneer")
    return redirect(url_for("auctions"))


@app.route("/auction/<auction_id>/register_bidder", methods=["POST"])
def register_bidder_to_auction(auction_id):
    if session.get("role") != "bidder":
        return redirect(url_for("auctions"))
    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$addToSet": {"bidders": session["user_id"]}})
    flash("Registered in auction")
    return redirect(url_for("auctions"))


@app.route("/auction/<auction_id>/prepare_ot", methods=["POST"])
def prepare_ot(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))
    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    messages = []
    values = list(range(1, auction["bidder_limit"] + 1))
    for _ in values:
        r_i = secrets.randbelow(curve.n - 1) + 1
        messages.append(r_i.to_bytes(66, "big"))
    state = ot_tree.sender_prepare_tree(messages)
    auctions_col.update_one(
        {"_id": ObjectId(auction_id)},
        {"$set": {"ot_ready": True, "ot_sender_state": {"original_n": state["original_n"], "n": state["n"], "k": state["k"], "ciphertexts": [c.hex() for c in state["ciphertexts"]], "level_pairs": [[p[0].hex(), p[1].hex()] for p in state["level_pairs"]]}}},
    )
    flash("Secret keys shared via OT setup")
    return redirect(url_for("auctions"))


@app.route("/auction/<auction_id>/submit_bid", methods=["POST"])
def submit_bid(auction_id):
    if session.get("role") != "bidder":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    bid_value = int(request.form["bid_value"])
    if auction["status"] != "OPEN":
        flash("Auction closed")
        return redirect(url_for("auctions"))

    # Stage 1 ring
    all_pks = [point_from_json(u["public_key"]) for u in users_col.find({"role": "bidder"})]

    # Simulated bidder local keys (not stored raw)
    bidder_sk, bidder_pk = ring.generate_keypair()
    key_image = ring.generate_key_image(bidder_sk, bidder_pk)
    ring_set = all_pks[:]
    if bidder_pk not in ring_set:
        ring_set.append(bidder_pk)

    # Stage 3: OT retrieval of one hidden randomness index
    ot_state_db = auction.get("ot_sender_state")
    if not ot_state_db:
        flash("OT not prepared by auctioneer yet")
        return redirect(url_for("auctions"))

    sender_state = {
        "original_n": ot_state_db["original_n"],
        "n": ot_state_db["n"],
        "k": ot_state_db["k"],
        "ciphertexts": [bytes.fromhex(x) for x in ot_state_db["ciphertexts"]],
        "level_pairs": [(bytes.fromhex(pair[0]), bytes.fromhex(pair[1])) for pair in ot_state_db["level_pairs"]],
    }
    idx = min(max(bid_value - 1, 0), sender_state["original_n"] - 1)
    r_i = int.from_bytes(ot_tree.receiver_obtain_leaf(sender_state, idx), "big")

    # Stage 2 commitment C_i = g^b_i * h^r_i
    commitment, _ = pedersen.commit(bid_value, r_i)

    # Ring signature for anonymous submission
    msg = f"auction:{auction_id}|commit:{commitment[0]}:{commitment[1]}".encode()
    signature = ring.sign(msg, bidder_sk, bidder_pk, ring_set, key_image)

    bids_col.insert_one(
        {
            "auction_id": auction_id,
            "bidder_id": session["user_id"],
            "commitment": point_to_json(commitment),
            "revealed_bid": None,
            "randomness": None,
            "signature": {
                "key_image": point_to_json(signature["key_image"]),
                "c1": str(signature["c1"]),
                "s_values": [str(x) for x in signature["s_values"]],
                "ring": [point_to_json(x) for x in signature["ring"]],
                "message": signature["message"].hex(),
            },
            "created_at": datetime.utcnow(),
            "zk_opening": None,
        }
    )

    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$push": {"commitments": point_to_json(commitment)}})
    flash("Bid commitment submitted (raw bid hidden)")
    return redirect(url_for("auctions"))


@app.route("/auction/<auction_id>/reveal", methods=["POST"])
def reveal_bid(auction_id):
    bid_value = int(request.form["bid_value"])
    randomness = int(request.form["randomness"])
    bid = bids_col.find_one({"auction_id": auction_id, "bidder_id": session["user_id"]})
    if not bid:
        flash("No bid found")
        return redirect(url_for("auctions"))

    C_i = point_from_json(bid["commitment"])
    commit_ok = pedersen.verify_opening(C_i, bid_value, randomness)
    proof = zk.prove_opening(bid_value, randomness)
    zkp_ok = zk.verify_opening_proof(C_i, proof)

    if not (commit_ok and zkp_ok):
        flash("Invalid opening/ZKP. Bid rejected")
        return redirect(url_for("auctions"))

    bids_col.update_one(
        {"_id": bid["_id"]},
        {
            "$set": {
                "revealed_bid": bid_value,
                "randomness": str(randomness),
                "zk_opening": {"T": point_to_json(proof["T"]), "e": str(proof["e"]), "z1": str(proof["z1"]), "z2": str(proof["z2"])}
            }
        },
    )

    flash("Bid revealed and ZKP verified")
    return redirect(url_for("auctions"))


@app.route("/auction/<auction_id>/declare_winner", methods=["POST"])
def declare_winner(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if len(auction.get("auctioneers", [])) < auction.get("threshold_k", 1):
        flash("Not enough auctioneers joined (k threshold not met)")
        return redirect(url_for("auctions"))

    valid = list(bids_col.find({"auction_id": auction_id, "revealed_bid": {"$ne": None}}))
    if not valid:
        flash("No valid revealed bids")
        return redirect(url_for("auctions"))

    winner = max(valid, key=lambda x: x["revealed_bid"])

    # Stage 5 Shamir sharing across auctioneers
    secret = int(hashlib.sha256(f"{auction_id}:{winner['_id']}".encode()).hexdigest(), 16)
    shares = split_secret(secret, auction["threshold_k"], len(auction["auctioneers"]))
    recovered = reconstruct_secret(shares[: auction["threshold_k"]])

    # ZKP max relation checks with Dj = Cw - Cj = dj*G + rhoj*H
    Cw = point_from_json(winner["commitment"])
    all_ok = True
    for b in valid:
        Cj = point_from_json(b["commitment"])
        d_j = max(winner["revealed_bid"] - b["revealed_bid"], 0)
        rho_j = int(winner["randomness"]) - int(b["randomness"])
        pf = zk.prove_maximum_relation(Cw, Cj, d_j, rho_j)
        if not zk.verify_maximum_relation(pf):
            all_ok = False
            break

    if not all_ok or recovered != secret:
        flash("Winner verification failed")
        return redirect(url_for("auctions"))

    auctions_col.update_one(
        {"_id": ObjectId(auction_id)},
        {
            "$set": {
                "status": "CLOSED",
                "winner": {"bidder_id": winner["bidder_id"], "bid": winner["revealed_bid"]},
                "shares": [{"x": x, "y": str(y)} for x, y in shares],
            }
        },
    )
    flash("Winner declared with Shamir+ZKP verification")
    return redirect(url_for("auctions"))


@app.route("/api/ring")
def api_ring():
    public_keys = [u.get("public_key") for u in users_col.find({"role": "bidder"}) if u.get("public_key")]
    return jsonify({"R": public_keys})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
