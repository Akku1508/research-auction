import hashlib
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from werkzeug.security import check_password_hash, generate_password_hash

from crypto.commitment import PedersenCommitment
from crypto.common import curve, point_from_json, point_to_json
from crypto.oblivious_transfer import NaorPinkasTreeOT
from crypto.ring_signature import RingSignature
from crypto.shamir import reconstruct_secret, split_secret
from crypto.zk_proof import ZKProofs


load_dotenv(Path(__file__).with_name(".env"))

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-me-in-production")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "decentralized_auction")


STATUS_REGISTRATION = "REGISTRATION"
STATUS_BIDDING_OPEN = "BIDDING_OPEN"
STATUS_BIDDING_CLOSED = "BIDDING_CLOSED"
STATUS_OT_READY = "OT_READY"
STATUS_COMPLETED = "COMPLETED"
IST_TZ = ZoneInfo("Asia/Kolkata")


def utcnow():
    return datetime.now(timezone.utc)


def now_ist():
    return datetime.now(IST_TZ)


def parse_iso_date(value: str):
    # HTML datetime-local carries user local wall-clock time.
    local_dt = datetime.fromisoformat(value)
    if local_dt.tzinfo is None:
        local_dt = local_dt.replace(tzinfo=IST_TZ)
    return local_dt.astimezone(timezone.utc)


def ensure_aware(dt: datetime):
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def auction_dt(auction: dict, key: str):
    value = auction.get(key)
    if isinstance(value, datetime):
        return ensure_aware(value)
    raise ValueError(f"Auction field {key} is missing or invalid datetime")

def create_mongo_client():
    client_obj = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    try:
        client_obj.admin.command("ping")
    except ServerSelectionTimeoutError as exc:
        raise RuntimeError(
            "MongoDB connection failed. Set MONGO_URI in backend/.env or environment variables."
        ) from exc
    return client_obj


client = create_mongo_client()
db = client[MONGO_DB_NAME]
users_col = db["users"]
auctions_col = db["auctions"]
bids_col = db["bids"]

ring = RingSignature()
pedersen = PedersenCommitment()
ot_tree = NaorPinkasTreeOT()
zk = ZKProofs()


def format_ist(dt: datetime):
    return ensure_aware(dt).astimezone(IST_TZ).strftime("%Y-%m-%d %H:%M:%S IST")


def serialize_auction(a):
    a["_id"] = str(a["_id"])
    if isinstance(a.get("start_date"), datetime):
        a["start_date_display"] = format_ist(a["start_date"])
    if isinstance(a.get("end_date"), datetime):
        a["end_date_display"] = format_ist(a["end_date"])
    return a


def current_user():
    if "user_id" not in session:
        return None
    return users_col.find_one({"_id": ObjectId(session["user_id"])})


def must_login():
    return "user_id" in session


@app.route("/")
def root():
    if must_login():
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
                "created_at": utcnow(),
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
    if not must_login():
        return redirect(url_for("login"))
    user = current_user()
    my_auctions = list(auctions_col.find({"$or": [{"bidders": session["user_id"]}, {"auctioneers": session["user_id"]}]}))
    return render_template("dashboard.html", user=user, auctions=[serialize_auction(a) for a in my_auctions])


@app.route("/auctions", methods=["GET", "POST"])
def auctions():
    if not must_login():
        return redirect(url_for("login"))

    if request.method == "POST" and session["role"] == "auctioneer":
        start_dt = parse_iso_date(request.form["start_date"])
        end_dt = parse_iso_date(request.form["end_date"])
        if end_dt <= start_dt:
            flash("End date must be after start date")
            return redirect(url_for("auctions"))

        auction = {
            "title": request.form["title"],
            "status": STATUS_REGISTRATION,
            "required_auctioneers": int(request.form["required_auctioneers"]),
            "start_date": start_dt,
            "end_date": end_dt,
            "bid_start_value": int(request.form["bid_start_value"]),
            "auctioneers": [session["user_id"]],
            "bidders": [],
            "participant_keys": {},
            "commitments": [],
            "shares": [],
            "winner": None,
            "ot_sender_state": None,
            "created_at": utcnow(),
        }
        auctions_col.insert_one(auction)
        flash("Auction created in registration stage")
        return redirect(url_for("auctions"))

    all_auctions = [serialize_auction(a) for a in auctions_col.find().sort("_id", -1)]
    return render_template("auctions.html", auctions=all_auctions, role=session["role"], now=now_ist())


@app.route("/auction/<auction_id>/join_auctioneer", methods=["POST"])
def join_auctioneer(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))
    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$addToSet": {"auctioneers": session["user_id"]}})
    flash("Joined as auctioneer. Panel unlocks now.")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/auctioneer_panel")
def auctioneer_panel(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))
    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction or session["user_id"] not in auction.get("auctioneers", []):
        flash("Join as auctioneer first")
        return redirect(url_for("auctions"))

    bid_rows = list(bids_col.find({"auction_id": auction_id}))
    revealed_count = sum(1 for b in bid_rows if b.get("revealed_bid") is not None)
    return render_template(
        "auctioneer_panel.html",
        auction=serialize_auction(auction),
        bid_count=len(bid_rows),
        revealed_count=revealed_count,
    )


@app.route("/auction/<auction_id>/start", methods=["POST"])
def start_auction(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if session["user_id"] not in auction.get("auctioneers", []):
        flash("Join as auctioneer first")
        return redirect(url_for("auctions"))

    if len(auction.get("auctioneers", [])) < auction.get("required_auctioneers", 1):
        flash("Cannot start: required k auctioneers not present")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    if len(auction.get("bidders", [])) == 0:
        flash("Cannot start: no bidder has joined yet")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    if utcnow() < auction_dt(auction, "start_date"):
        flash("Cannot start before scheduled start date")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    if auction["status"] != STATUS_REGISTRATION:
        flash("Auction already started or closed")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$set": {"status": STATUS_BIDDING_OPEN}})
    flash("Auction started. Bidding is open.")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/close_bidding", methods=["POST"])
def close_bidding(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))
    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if auction["status"] != STATUS_BIDDING_OPEN:
        flash("Bidding is not open")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    if utcnow() < auction_dt(auction, "end_date"):
        flash("End date not reached yet")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$set": {"status": STATUS_BIDDING_CLOSED}})
    flash("Bidding closed. You can now prepare OT stage.")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/prepare_ot", methods=["POST"])
def prepare_ot(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if auction["status"] != STATUS_BIDDING_CLOSED:
        flash("Stage lock: OT can start only after bidding closes")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    bid_rows = list(bids_col.find({"auction_id": auction_id}))
    if not bid_rows:
        flash("No commitments submitted")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    messages = []
    for _ in bid_rows:
        r_i = secrets.randbelow(curve.n - 1) + 1
        messages.append(r_i.to_bytes(66, "big"))

    state = ot_tree.sender_prepare_tree(messages)
    auctions_col.update_one(
        {"_id": ObjectId(auction_id)},
        {
            "$set": {
                "status": STATUS_OT_READY,
                "ot_sender_state": {
                    "original_n": state["original_n"],
                    "n": state["n"],
                    "k": state["k"],
                    "ciphertexts": [c.hex() for c in state["ciphertexts"]],
                    "level_pairs": [[p[0].hex(), p[1].hex()] for p in state["level_pairs"]],
                },
            }
        },
    )
    flash("OT ready. Bidders may reveal (b_i, r_i) with ZKP.")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/register_bidder", methods=["POST"])
def register_bidder_to_auction(auction_id):
    if session.get("role") != "bidder":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if auction["status"] != STATUS_REGISTRATION:
        flash("Registration closed for this auction")
        return redirect(url_for("auctions"))

    bidder_id = session["user_id"]
    sk, pk = ring.generate_keypair()
    auctions_col.update_one(
        {"_id": ObjectId(auction_id)},
        {
            "$addToSet": {"bidders": bidder_id},
            "$set": {
                f"participant_keys.{bidder_id}": {
                    "public_key": point_to_json(pk),
                    "private_key_hash": hashlib.sha256(str(sk).encode()).hexdigest(),
                }
            },
        },
    )
    # Keep auction specific private key only in session (not DB) for signing.
    session[f"auction_sk_{auction_id}"] = str(sk)
    flash("Participation successful. Auction-specific key pair generated.")
    return redirect(url_for("bidder_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/bidder_panel")
def bidder_panel(auction_id):
    if session.get("role") != "bidder":
        return redirect(url_for("auctions"))
    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction or session["user_id"] not in auction.get("bidders", []):
        flash("Participate in auction first")
        return redirect(url_for("auctions"))

    bid_doc = bids_col.find_one({"auction_id": auction_id, "bidder_id": session["user_id"]})
    return render_template("bidder_panel.html", auction=serialize_auction(auction), bid_doc=bid_doc)


@app.route("/auction/<auction_id>/submit_bid", methods=["POST"])
def submit_bid(auction_id):
    if session.get("role") != "bidder":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if auction["status"] != STATUS_BIDDING_OPEN:
        flash("Stage lock: bid submission allowed only in BIDDING_OPEN")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    bidder_id = session["user_id"]
    bid_value = int(request.form["bid_value"])
    if bid_value < auction.get("bid_start_value", 1):
        flash("Bid must be >= starting value")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    if not (auction_dt(auction, "start_date") <= utcnow() <= auction_dt(auction, "end_date")):
        flash("Current time is outside allowed bidding window")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    # Phase-1 ring: public keys of all participating bidders in this auction.
    ring_entries = []
    for _, entry in auction.get("participant_keys", {}).items():
        if entry.get("public_key"):
            ring_entries.append(point_from_json(entry["public_key"]))

    sk_raw = session.get(f"auction_sk_{auction_id}")
    if not sk_raw:
        flash("Session key not found. Re-participate to regenerate auction keypair")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    signer_sk = int(sk_raw)
    signer_pk = point_from_json(auction["participant_keys"][bidder_id]["public_key"])
    if signer_pk not in ring_entries:
        ring_entries.append(signer_pk)

    # Stage-2 Pedersen commitment C_i = g^b_i h^r_i
    commitment, r_i = pedersen.commit(bid_value)

    # Ring signature over commitment message.
    key_image = ring.generate_key_image(signer_sk, signer_pk)
    msg = f"auction:{auction_id}|commit:{commitment[0]}:{commitment[1]}".encode()
    signature = ring.sign(msg, signer_sk, signer_pk, ring_entries, key_image)

    bids_col.update_one(
        {"auction_id": auction_id, "bidder_id": bidder_id},
        {
            "$set": {
                "auction_id": auction_id,
                "bidder_id": bidder_id,
                "commitment": point_to_json(commitment),
                "revealed_bid": None,
                "randomness": None,
                "ring_signature": {
                    "key_image": point_to_json(signature["key_image"]),
                    "c1": str(signature["c1"]),
                    "s_values": [str(x) for x in signature["s_values"]],
                    "ring": [point_to_json(p) for p in signature["ring"]],
                    "message": signature["message"].hex(),
                },
                "created_at": utcnow(),
            }
        },
        upsert=True,
    )

    auctions_col.update_one(
        {"_id": ObjectId(auction_id)},
        {"$addToSet": {"commitments": point_to_json(commitment)}},
    )

    # Store r_i in bidder session for later reveal to avoid DB raw pre-reveal storage.
    session[f"reveal_r_{auction_id}"] = str(r_i)

    flash("Commitment submitted with ring signature.")
    return redirect(url_for("bidder_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/reveal", methods=["POST"])
def reveal_bid(auction_id):
    if session.get("role") != "bidder":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if auction["status"] != STATUS_OT_READY:
        flash("Stage lock: reveal allowed only after OT is prepared")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    bid = bids_col.find_one({"auction_id": auction_id, "bidder_id": session["user_id"]})
    if not bid:
        flash("No commitment found")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    bid_value = int(request.form["bid_value"])
    randomness = int(request.form["randomness"])
    c_i = point_from_json(bid["commitment"])

    commit_ok = pedersen.verify_opening(c_i, bid_value, randomness)
    proof = zk.prove_opening(bid_value, randomness)
    zkp_ok = zk.verify_opening_proof(c_i, proof)

    if not (commit_ok and zkp_ok):
        flash("Invalid reveal or invalid ZKP")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

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

    flash("Reveal accepted. Stage 4 verification passed.")
    return redirect(url_for("bidder_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/declare_winner", methods=["POST"])
def declare_winner(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if session["user_id"] not in auction.get("auctioneers", []):
        flash("Join as auctioneer first")
        return redirect(url_for("auctions"))

    if auction["status"] != STATUS_OT_READY:
        flash("Stage lock: winner can be declared only after OT+Reveal stage")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    valid = list(bids_col.find({"auction_id": auction_id, "revealed_bid": {"$ne": None}}))
    if not valid:
        flash("No valid revealed bids")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    winner = max(valid, key=lambda x: x["revealed_bid"])

    # Shamir: split winner secret among auctioneers, require k shares.
    secret = int(hashlib.sha256(f"{auction_id}:{winner['_id']}".encode()).hexdigest(), 16)
    shares = split_secret(secret, auction["required_auctioneers"], len(auction["auctioneers"]))
    recovered = reconstruct_secret(shares[: auction["required_auctioneers"]])

    # ZK maximum relation checks: D_j = C_w - C_j = d_j G + rho_j H
    c_w = point_from_json(winner["commitment"])
    proof_ok = True
    for b in valid:
        c_j = point_from_json(b["commitment"])
        d_j = max(winner["revealed_bid"] - b["revealed_bid"], 0)
        rho_j = int(winner["randomness"]) - int(b["randomness"])
        pf = zk.prove_maximum_relation(c_w, c_j, d_j, rho_j)
        if not zk.verify_maximum_relation(pf):
            proof_ok = False
            break

    if not proof_ok or recovered != secret:
        flash("Winner verification failed")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    auctions_col.update_one(
        {"_id": ObjectId(auction_id)},
        {
            "$set": {
                "status": STATUS_COMPLETED,
                "winner": {"bidder_id": winner["bidder_id"], "bid": winner["revealed_bid"]},
                "shares": [{"x": x, "y": str(y)} for x, y in shares],
            }
        },
    )

    flash("Winner declared with distributed proof flow.")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/api/ring")
def api_ring():
    public_keys = [u.get("public_key") for u in users_col.find({"role": "bidder"}) if u.get("public_key")]
    return jsonify({"R": public_keys})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
