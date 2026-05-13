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
from werkzeug.utils import secure_filename

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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_ROOT = (PROJECT_ROOT / "frontend" / "static").resolve()
UPLOAD_ROOT = STATIC_ROOT / "uploads"
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "decentralized_auction")
MONGO_TIMEOUT_MS = int(os.getenv("MONGO_TIMEOUT_MS", "10000"))

STATUS_REGISTRATION = "REGISTRATION"
STATUS_BIDDING_OPEN = "BIDDING_OPEN"
STATUS_BIDDING_CLOSED = "BIDDING_CLOSED"
STATUS_OT_READY = "OT_READY"
STATUS_VERIFIED = "VERIFIED"
STATUS_COMPLETED = "COMPLETED"
IST_TZ = ZoneInfo("Asia/Kolkata")
MIN_AUCTIONEERS_FOR_SHAMIR = 2
ALLOWED_ATTACHMENT_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
    "txt",
    "rtf",
    "md",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "bmp",
    "mp4",
    "webm",
    "mov",
    "mkv",
    "mp3",
    "wav",
    "ogg",
}


def display_stage(value):
    if not value:
        return "UNKNOWN"
    return str(value).replace("_", " ").upper()


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


def normalize_auction_type(value):
    auction_type = (value or "reverse").strip().lower()
    return auction_type if auction_type in {"forward", "reverse"} else "reverse"


def auction_is_forward(auction: dict):
    return normalize_auction_type(auction.get("auction_type")) == "forward"


def auction_bid_ceiling(auction: dict):
    value = auction.get("maximum_allowed_bid", auction.get("bid_start_value", 1))
    if value in (None, ""):
        value = 1
    return int(value)


def auction_bid_floor(auction: dict):
    if auction_is_forward(auction):
        value = auction.get("starting_bid_value", auction.get("bid_start_value", 0))
        if value in (None, ""):
            value = 0
        return int(value)
    value = auction.get("minimum_allowed_bid", 0)
    if value in (None, ""):
        value = 0
    return int(value)


def auctioneer_ids(auction: dict):
    # Every auctioneer account is eligible for every auction.
    return auctioneer_pool_ids()


def auctioneer_threshold(auction: dict):
    value = auction.get("required_auctioneers", MIN_AUCTIONEERS_FOR_SHAMIR)
    if value in (None, ""):
        value = MIN_AUCTIONEERS_FOR_SHAMIR
    return max(int(value), MIN_AUCTIONEERS_FOR_SHAMIR)


def auctioneer_pool_ids():
    return [str(user["_id"]) for user in users_col.find({"role": "auctioneer"}, {"_id": 1})]


def has_required_auctioneer_threshold(auction: dict):
    return len(auctioneer_ids(auction)) >= auctioneer_threshold(auction)


def require_auctioneer_threshold(auction: dict, action_label: str):
    threshold = auctioneer_threshold(auction)
    joined_count = len(auctioneer_ids(auction))
    if joined_count >= threshold:
        return True
    flash(
        f"Cannot {action_label}: at least {threshold} auctioneer account(s) are required so Shamir secret sharing can be satisfied. Currently available in the pool: {joined_count}."
    )
    return False


def build_auctioneer_action_checks(auction: dict, bid_rows: list[dict]):
    threshold = auctioneer_threshold(auction)
    joined_count = len(auctioneer_ids(auction))
    bid_count = len(bid_rows)
    revealed_count = sum(1 for bid in bid_rows if bid.get("revealed_bid") is not None)
    valid_count = sum(1 for bid in bid_rows if bid.get("is_valid") is True)

    start_messages = []
    if joined_count < threshold:
        start_messages.append(f"Need at least {threshold} auctioneer account(s) available; currently {joined_count}.")
    try:
        if utcnow() < auction_dt(auction, "start_date"):
            start_messages.append("Scheduled start time has not arrived yet.")
    except ValueError:
        start_messages.append("Start time is missing or invalid.")
    if auction.get("status") != STATUS_REGISTRATION:
        start_messages.append("Auction is no longer in registration stage.")

    close_messages = []
    if joined_count < threshold:
        close_messages.append(f"Need at least {threshold} auctioneer account(s) available; currently {joined_count}.")
    if auction.get("status") != STATUS_BIDDING_OPEN:
        close_messages.append("Bidding must be open before it can be closed.")
    if bid_count == 0:
        close_messages.append("At least one bid commitment must exist before closing.")

    return {
        "threshold": threshold,
        "joined_count": joined_count,
        "bid_count": bid_count,
        "revealed_count": revealed_count,
        "valid_count": valid_count,
        "start": {"ready": not start_messages, "messages": start_messages},
        "close": {"ready": not close_messages, "messages": close_messages},
        "shamir": {
            "ready": joined_count >= threshold,
            "messages": []
            if joined_count >= threshold
            else [f"Shamir threshold is {threshold}, but only {joined_count} auctioneer account(s) are currently available."],
        },
    }


def collect_start_auction_blockers(auction: dict):
    blockers = []
    threshold = auctioneer_threshold(auction)
    joined_count = len(auctioneer_ids(auction))
    if joined_count < threshold:
        blockers.append(f"{threshold} auctioneer account(s) are required but only {joined_count} are available.")
    try:
        if utcnow() < auction_dt(auction, "start_date"):
            blockers.append("The scheduled start time has not arrived yet.")
    except ValueError:
        blockers.append("The start time is missing or invalid.")
    if auction.get("status") != STATUS_REGISTRATION:
        blockers.append(
            f"Auction status must be {display_stage(STATUS_REGISTRATION)}, but it is {display_stage(auction.get('status'))}."
        )
    return blockers


def collect_close_bidding_blockers(auction: dict):
    blockers = []
    threshold = auctioneer_threshold(auction)
    joined_count = len(auctioneer_ids(auction))
    bid_count = bids_col.count_documents({"auction_id": str(auction.get('_id'))})
    if joined_count < threshold:
        blockers.append(f"{threshold} auctioneer account(s) are required but only {joined_count} are available.")
    if auction.get("status") != STATUS_BIDDING_OPEN:
        blockers.append(
            f"Auction status must be {display_stage(STATUS_BIDDING_OPEN)}, but it is {display_stage(auction.get('status'))}."
        )
    if bid_count == 0:
        blockers.append("At least one bid commitment must exist before closing bidding.")
    return blockers


def build_bidder_stage_notice(auction: dict, bid_doc: dict | None):
    status = auction.get("status")
    threshold = auctioneer_threshold(auction)
    joined_count = len(auctioneer_ids(auction))

    if status == STATUS_REGISTRATION:
        return {
            "tone": "info",
            "title": "Bidding has not started yet",
            "message": (
                f"This auction is still in registration. At least {threshold} auctioneer account(s) must be available "
                f"(currently {joined_count}) and the auctioneer must click Start Auction before the bid form appears."
            ),
        }
    if status == STATUS_BIDDING_OPEN and not bid_doc:
        return {
            "tone": "success",
            "title": "Bidding is open",
            "message": "Enter your bid value, generate randomness r_i, and submit your commitment in the form below.",
        }
    if status == STATUS_BIDDING_OPEN and bid_doc:
        return {
            "tone": "info",
            "title": "Your commitment is already stored",
            "message": "You have already submitted your sealed commitment. Wait for bidding to close and the OT stage to open.",
        }
    if status == STATUS_BIDDING_CLOSED:
        return {
            "tone": "warning",
            "title": "Bidding is closed",
            "message": "No new bids can be submitted now. Wait for the auctioneer to prepare the OT stage.",
        }
    if status == STATUS_OT_READY and bid_doc:
        return {
            "tone": "success",
            "title": "Reveal stage is open",
            "message": "Retrieve your OT shared key first, then reveal your bid value, randomness, and OT key below.",
        }
    if status == STATUS_OT_READY and not bid_doc:
        return {
            "tone": "warning",
            "title": "No commitment found",
            "message": "This account cannot reveal because no bid commitment was stored for it during the bidding stage.",
        }
    if status == STATUS_VERIFIED:
        return {
            "tone": "info",
            "title": "Reveal verification completed",
            "message": "The auctioneer has finished checking revealed bids. Wait for winner declaration.",
        }
    if status == STATUS_COMPLETED:
        return {
            "tone": "info",
            "title": "Auction completed",
            "message": "This auction has already finished and the winner has been declared.",
        }
    return {
        "tone": "info",
        "title": "Awaiting next stage",
        "message": "The auction is waiting for its next protocol step.",
    }


def form_text_value(form, key, default=""):
    value = form.get(key, default)
    if value is None:
        return default
    return str(value).strip()


def form_int_value(form, key, default=0):
    value = form.get(key, None)
    if value in (None, ""):
        return default
    return int(value)



def create_mongo_client():
    client_obj = MongoClient(MONGO_URI, serverSelectionTimeoutMS=MONGO_TIMEOUT_MS)
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
auction_shares_col = db["auction_shares"]

ring = RingSignature()
pedersen = PedersenCommitment()
ot_tree = NaorPinkasTreeOT()
zk = ZKProofs()


def init_database_indexes():
    users_col.create_index("username", unique=True)
    bids_col.create_index([("auction_id", 1), ("bidder_id", 1)], unique=True)
    bids_col.create_index("auction_id")
    auctions_col.create_index("status")
    auctions_col.create_index("auctioneers")
    auctions_col.create_index("bidders")
    auction_shares_col.create_index([("auction_id", 1), ("auctioneer_id", 1)], unique=True)
    auction_shares_col.create_index("auction_id")


def migrate_auction_bid_ceiling_field():
    auctions_col.update_many(
        {"auction_type": {"$exists": False}},
        {"$set": {"auction_type": "reverse"}},
    )
    auctions_col.update_many(
        {"maximum_allowed_bid": {"$exists": False}, "bid_start_value": {"$exists": True}},
        [{"$set": {"maximum_allowed_bid": "$bid_start_value"}}],
    )
    auctions_col.update_many(
        {"minimum_allowed_bid": {"$exists": False}},
        {"$set": {"minimum_allowed_bid": 0}},
    )
    auctions_col.update_many(
        {"required_auctioneers": {"$exists": False}},
        {"$set": {"required_auctioneers": MIN_AUCTIONEERS_FOR_SHAMIR}},
    )
    auctions_col.update_many(
        {"required_auctioneers": {"$lt": MIN_AUCTIONEERS_FOR_SHAMIR}},
        {"$set": {"required_auctioneers": MIN_AUCTIONEERS_FOR_SHAMIR}},
    )


init_database_indexes()
migrate_auction_bid_ceiling_field()


def format_ist(dt: datetime):
    return ensure_aware(dt).astimezone(IST_TZ).strftime("%Y-%m-%d %H:%M:%S IST")


def serialize_auction(a):
    a["_id"] = str(a["_id"])
    a["required_auctioneers"] = auctioneer_threshold(a)
    a["auctioneers"] = auctioneer_ids(a)
    a["auctioneer_count"] = len(a["auctioneers"])
    a["auction_type"] = normalize_auction_type(a.get("auction_type"))
    a["auction_type_label"] = "Forward" if a["auction_type"] == "forward" else "Reverse"
    a["winner_rule_label"] = (
        "Highest valid bid wins" if a["auction_type"] == "forward" else "Lowest valid bid wins"
    )
    a["subject_heading"] = (
        "What is being sold" if a["auction_type"] == "forward" else "What deal is being requested"
    )
    a["condition_heading"] = (
        "Material conditions" if a["auction_type"] == "forward" else "Requirement notes"
    )
    a["starting_bid_value"] = int(a.get("starting_bid_value", a.get("bid_start_value", 0)) or 0)
    if "minimum_allowed_bid" not in a:
        a["minimum_allowed_bid"] = a["starting_bid_value"] if a["auction_type"] == "forward" else 0
    if "maximum_allowed_bid" not in a:
        a["maximum_allowed_bid"] = a.get("bid_start_value")
    a["bid_floor"] = auction_bid_floor(a)
    a["bid_ceiling"] = auction_bid_ceiling(a)
    a["subject_description"] = a.get("subject_description", "")
    a["condition_notes"] = a.get("condition_notes", "")
    a["desired_quality"] = a.get("desired_quality", "")
    a["source_location"] = a.get("source_location", "")
    a["written_assets"] = a.get("written_assets") or []
    a["media_assets"] = a.get("media_assets") or []
    if isinstance(a.get("start_date"), datetime):
        aware_start = ensure_aware(a["start_date"]).astimezone(IST_TZ)
        a["start_date_display"] = aware_start.strftime("%Y-%m-%d %H:%M:%S IST")
        a["start_date_input"] = aware_start.strftime("%Y-%m-%dT%H:%M")
    if isinstance(a.get("end_date"), datetime):
        aware_end = ensure_aware(a["end_date"]).astimezone(IST_TZ)
        a["end_date_display"] = aware_end.strftime("%Y-%m-%d %H:%M:%S IST")
        a["end_date_input"] = aware_end.strftime("%Y-%m-%dT%H:%M")
    return a




def save_uploaded_assets(auction_id: str, uploaded_files, category: str):
    valid_files = []
    for file_storage in uploaded_files:
        if not file_storage or not file_storage.filename:
            continue
        original_name = secure_filename(file_storage.filename)
        if not original_name:
            continue
        extension = Path(original_name).suffix.lower().lstrip(".")
        if extension not in ALLOWED_ATTACHMENT_EXTENSIONS:
            raise ValueError(f"Unsupported file type: {file_storage.filename}")
        valid_files.append((file_storage, original_name))

    if not valid_files:
        return []

    target_dir = UPLOAD_ROOT / auction_id / category
    target_dir.mkdir(parents=True, exist_ok=True)
    saved_assets = []
    for file_storage, original_name in valid_files:
        stored_name = f"{secrets.token_hex(8)}_{original_name}"
        file_path = target_dir / stored_name
        file_storage.save(file_path)
        saved_assets.append(
            {
                "original_name": file_storage.filename,
                "stored_name": stored_name,
                "path": file_path.relative_to(STATIC_ROOT).as_posix(),
                "mimetype": file_storage.mimetype,
                "category": category,
                "uploaded_at": utcnow(),
            }
        )
    return saved_assets


def public_key_to_string(point):
    return f"{point[0]:064x}{point[1]:064x}"


def public_key_from_any(value):
    if isinstance(value, dict):
        return point_from_json(value)
    if isinstance(value, str):
        data = value.strip().lower()
        if data.startswith("0x"):
            data = data[2:]
        if len(data) != 128:
            raise ValueError("Invalid public key format")
        return (int(data[:64], 16), int(data[64:], 16))
    raise ValueError("Unsupported public key format")

def normalize_shared_key(value: str):
    normalized = (value or "").strip().lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    return normalized


@app.route("/healthz")
def healthz():
    try:
        client.admin.command("ping")
        mongo_ok = True
    except Exception:
        mongo_ok = False
    return jsonify(
        {
            "status": "ok" if mongo_ok else "degraded",
            "mongo": mongo_ok,
            "database": MONGO_DB_NAME,
        }
    )


def current_user():
    if "user_id" not in session:
        return None
    return users_col.find_one({"_id": ObjectId(session["user_id"])})


def must_login():
    return "user_id" in session


@app.context_processor
def inject_layout_user():
    return {"layout_user": current_user() if must_login() else None}


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

        _, pk = ring.generate_keypair()
        users_col.insert_one(
            {
                "full_name": data["full_name"],
                "email": data["email"],
                "phone": data["phone"],
                "username": data["username"],
                "password": generate_password_hash(data["password"]),
                "role": data["role"],
                "public_key": public_key_to_string(pk),
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
    if session.get("role") == "auctioneer":
        my_auctions = list(auctions_col.find())
    else:
        my_auctions = list(auctions_col.find({"bidders": session["user_id"]}))
    return render_template("dashboard.html", user=user, auctions=[serialize_auction(a) for a in my_auctions])


@app.route("/auctions", methods=["GET", "POST"])
def auctions():
    if not must_login():
        return redirect(url_for("login"))

    if request.method == "POST" and session["role"] == "auctioneer":
        try:
            start_dt = parse_iso_date(request.form["start_date"])
            end_dt = parse_iso_date(request.form["end_date"])
            required_auctioneers = form_int_value(request.form, "required_auctioneers", MIN_AUCTIONEERS_FOR_SHAMIR)
            auction_type = normalize_auction_type(request.form.get("auction_type"))
            maximum_allowed_bid = form_int_value(request.form, "maximum_allowed_bid")
            starting_bid_value = form_int_value(request.form, "starting_bid_value", 0) if auction_type == "forward" else 0
        except (KeyError, TypeError, ValueError):
            flash("Please enter valid dates and numeric auction values.")
            return redirect(url_for("auctions"))

        if end_dt <= start_dt:
            flash("End date must be after start date")
            return redirect(url_for("auctions"))

        subject_description = form_text_value(request.form, "subject_description")
        condition_notes = form_text_value(request.form, "condition_notes")
        desired_quality = form_text_value(request.form, "desired_quality")
        source_location = form_text_value(request.form, "source_location")

        if not subject_description:
            flash("Please describe what is being sold or requested.")
            return redirect(url_for("auctions"))
        if not condition_notes:
            flash("Please add the written conditions or requirements.")
            return redirect(url_for("auctions"))
        if required_auctioneers < MIN_AUCTIONEERS_FOR_SHAMIR:
            flash(f"At least {MIN_AUCTIONEERS_FOR_SHAMIR} auctioneers are required because Shamir secret sharing must use a minimum threshold of 2.")
            return redirect(url_for("auctions"))
        if maximum_allowed_bid < 1:
            flash("Maximum bid value must be at least 1")
            return redirect(url_for("auctions"))
        if auction_type == "forward" and starting_bid_value > maximum_allowed_bid:
            flash("Forward auction starting bid must be less than or equal to the maximum bid value")
            return redirect(url_for("auctions"))
        if auction_type == "reverse" and (not desired_quality or not source_location):
            flash("Reverse auctions should include desired quality and source/location details.")
            return redirect(url_for("auctions"))

        current_auctioneer_pool = auctioneer_pool_ids()
        if len(current_auctioneer_pool) < required_auctioneers:
            flash(
                f"Cannot create auction yet: need at least {required_auctioneers} auctioneer account(s) in the system for Shamir secret sharing, but only {len(current_auctioneer_pool)} exist.",
                "error",
            )
            return redirect(url_for("auctions"))

        auction_id = ObjectId()
        try:
            written_assets = save_uploaded_assets(str(auction_id), request.files.getlist("written_files"), "written")
            media_assets = save_uploaded_assets(str(auction_id), request.files.getlist("media_files"), "media")
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("auctions"))

        auction = {
            "_id": auction_id,
            "title": form_text_value(request.form, "title"),
            "auction_type": auction_type,
            "status": STATUS_REGISTRATION,
            "required_auctioneers": required_auctioneers,
            "start_date": start_dt,
            "end_date": end_dt,
            "minimum_allowed_bid": starting_bid_value if auction_type == "forward" else 0,
            "maximum_allowed_bid": maximum_allowed_bid,
            "starting_bid_value": starting_bid_value,
            "subject_description": subject_description,
            "condition_notes": condition_notes,
            "desired_quality": desired_quality,
            "source_location": source_location,
            "written_assets": written_assets,
            "media_assets": media_assets,
            "created_by": session["user_id"],
            "auctioneers": current_auctioneer_pool,
            "bidders": [],
            "participant_keys": {},
            "commitments": [],
            "commitment_records": [],
            "shares": [],
            "winner": None,
            "ot_sender_state": None,
            "winner_secret_id": None,
            "created_at": utcnow(),
        }
        auctions_col.insert_one(auction)
        flash(
            f"Auction created in registration stage with {len(current_auctioneer_pool)} auctioneer account(s) available for every auction.",
            "success",
        )
        return redirect(url_for("auctions"))

    all_auctions = [serialize_auction(a) for a in auctions_col.find().sort("_id", -1)]
    return render_template("auctions.html", auctions=all_auctions, role=session["role"], now=now_ist())


@app.route("/auction/<auction_id>/join_auctioneer", methods=["POST"])
def join_auctioneer(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))
    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction:
        flash("Auction not found", "error")
        return redirect(url_for("auctions"))
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/auctioneer_panel")
def auctioneer_panel(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))
    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction:
        flash("Auction not found", "error")
        return redirect(url_for("auctions"))

    bid_rows = list(bids_col.find({"auction_id": auction_id}))
    revealed_count = sum(1 for b in bid_rows if b.get("revealed_bid") is not None)
    verified_count = sum(1 for b in bid_rows if b.get("is_valid") is True)
    invalid_count = sum(1 for b in bid_rows if b.get("is_valid") is False)
    verification_rows = []
    for bid in bid_rows:
        expected_shared_key = None
        if bid.get("revealed_bid") is not None:
            expected_shared_key = bid.get("ot_key_map", {}).get(str(bid.get("revealed_bid")))
        if not expected_shared_key:
            expected_shared_key = bid.get("ot_expected_shared_key")
        verification_rows.append(
            {
                "bidder_id": bid.get("bidder_id"),
                "revealed_bid": bid.get("revealed_bid"),
                "randomness": bid.get("randomness"),
                "revealed_shared_key": bid.get("revealed_shared_key"),
                "expected_shared_key": expected_shared_key,
                "expected_shared_key_from_reveal_bid": bid.get("expected_shared_key_from_reveal_bid"),
                "original_commitment": bid.get("commitment"),
                "expected_commitment": bid.get("expected_commitment"),
                "shared_key_valid": bid.get("shared_key_valid"),
                "commitment_valid": bid.get("commitment_valid"),
                "zk_valid": bid.get("zk_valid"),
                "key_proof_valid": bid.get("key_proof_valid"),
                "is_valid": bid.get("is_valid"),
            }
        )
    action_checks = build_auctioneer_action_checks(auction, bid_rows)
    return render_template(
        "auctioneer_panel.html",
        auction=serialize_auction(auction),
        bid_count=len(bid_rows),
        revealed_count=revealed_count,
        verified_count=verified_count,
        invalid_count=invalid_count,
        commitment_records=auction.get("commitment_records", []),
        verification_rows=verification_rows,
        action_checks=action_checks,
    )


@app.route("/auction/<auction_id>/start", methods=["POST"])
def start_auction(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction:
        flash("Auction not found", "error")
        return redirect(url_for("auctions"))

    blockers = collect_start_auction_blockers(auction)
    if blockers:
        flash("Cannot start auction yet: " + " ".join(blockers), "error")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$set": {"status": STATUS_BIDDING_OPEN}})
    flash("Auction started. Bidding is open.", "success")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/edit", methods=["POST"])
def edit_auction(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction:
        flash("Auction not found", "error")
        return redirect(url_for("auctions"))

    try:
        auction_type = normalize_auction_type(request.form.get("auction_type", auction.get("auction_type")))
        maximum_allowed_bid = form_int_value(request.form, "maximum_allowed_bid", auction.get("maximum_allowed_bid", 1))
        starting_bid_value = (
            form_int_value(request.form, "starting_bid_value", auction.get("starting_bid_value", 0))
            if auction_type == "forward"
            else 0
        )
        required_auctioneers = form_int_value(
            request.form,
            "required_auctioneers",
            auctioneer_threshold(auction),
        )
        start_dt = parse_iso_date(request.form["start_date"])
        end_dt = parse_iso_date(request.form["end_date"])
    except (KeyError, TypeError, ValueError):
        flash("Please enter valid dates and numeric auction values.")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    subject_description = form_text_value(request.form, "subject_description", auction.get("subject_description", ""))
    condition_notes = form_text_value(request.form, "condition_notes", auction.get("condition_notes", ""))
    desired_quality = form_text_value(request.form, "desired_quality", auction.get("desired_quality", ""))
    source_location = form_text_value(request.form, "source_location", auction.get("source_location", ""))

    if not subject_description:
        flash("Please describe what is being sold or requested.")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))
    if not condition_notes:
        flash("Please add the written conditions or requirements.")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))
    if required_auctioneers < MIN_AUCTIONEERS_FOR_SHAMIR:
        flash(f"At least {MIN_AUCTIONEERS_FOR_SHAMIR} auctioneers are required because Shamir secret sharing must use a minimum threshold of 2.")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))
    if maximum_allowed_bid < 1:
        flash("Maximum bid value must be at least 1")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))
    if auction_type == "forward" and starting_bid_value > maximum_allowed_bid:
        flash("Forward auction starting bid must be less than or equal to the maximum bid value")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))
    if auction_type == "reverse" and (not desired_quality or not source_location):
        flash("Reverse auctions should include desired quality and source/location details.")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))
    if end_dt <= start_dt:
        flash("End date must be after start date")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    current_auctioneer_pool = auctioneer_pool_ids()
    if len(current_auctioneer_pool) < required_auctioneers:
        flash(
            f"Cannot update auction yet: need at least {required_auctioneers} auctioneer account(s) in the system for Shamir secret sharing, but only {len(current_auctioneer_pool)} exist.",
            "error",
        )
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    try:
        new_written_assets = save_uploaded_assets(auction_id, request.files.getlist("written_files"), "written")
        new_media_assets = save_uploaded_assets(auction_id, request.files.getlist("media_files"), "media")
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    update_data = {
        "title": form_text_value(request.form, "title"),
        "auction_type": auction_type,
        "required_auctioneers": required_auctioneers,
        "start_date": start_dt,
        "end_date": end_dt,
        "minimum_allowed_bid": starting_bid_value if auction_type == "forward" else 0,
        "maximum_allowed_bid": maximum_allowed_bid,
        "starting_bid_value": starting_bid_value,
        "subject_description": subject_description,
        "condition_notes": condition_notes,
        "desired_quality": desired_quality,
        "source_location": source_location,
        "written_assets": list(auction.get("written_assets", [])) + new_written_assets,
        "media_assets": list(auction.get("media_assets", [])) + new_media_assets,
        "auctioneers": current_auctioneer_pool,
    }
    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$set": update_data})
    flash("Auction details updated")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/close_bidding", methods=["POST"])
def close_bidding(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))
    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction:
        flash("Auction not found", "error")
        return redirect(url_for("auctions"))

    blockers = collect_close_bidding_blockers(auction)
    if blockers:
        flash("Cannot close bidding yet: " + " ".join(blockers), "error")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$set": {"status": STATUS_BIDDING_CLOSED}})
    bid_count = bids_col.count_documents({"auction_id": auction_id})
    flash(f"Bidding closed with {bid_count} submitted commitment(s). You can now prepare OT stage.", "success")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/prepare_ot", methods=["POST"])
def prepare_ot(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction:
        flash("Auction not found", "error")
        return redirect(url_for("auctions"))
    if not require_auctioneer_threshold(auction, "prepare the OT stage"):
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))
    if auction["status"] != STATUS_BIDDING_CLOSED:
        flash("Stage lock: OT can start only after bidding closes")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    bid_rows = list(bids_col.find({"auction_id": auction_id}))
    if not bid_rows:
        flash("No commitments submitted")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    for bid in bid_rows:
        bid_floor = auction_bid_floor(auction)
        bid_ceiling = auction_bid_ceiling(auction)
        shared_keys = [secrets.token_bytes(32) for _ in range(bid_ceiling - bid_floor + 1)]
        ot_key_map = {
            str(value): shared_keys[value - bid_floor].hex()
            for value in range(bid_floor, bid_ceiling + 1)
        }

        state = ot_tree.sender_prepare_tree(shared_keys)
        bids_col.update_one(
            {"_id": bid["_id"]},
            {
                "$set": {
                    "ot_sender_state": {
                        "original_n": state["original_n"],
                        "n": state["n"],
                        "k": state["k"],
                        "ciphertexts": [c.hex() for c in state["ciphertexts"]],
                        "level_pairs": [[p[0].hex(), p[1].hex()] for p in state["level_pairs"]],
                    },
                    "ot_key_map": ot_key_map,
                    "ot_ready": True,
                }
            },
        )

    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$set": {"status": STATUS_OT_READY}})
    flash("OT ready. Bidders may reveal (b_i, r_i) and prove possession of the OT key.")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/register_bidder", methods=["POST"])
def register_bidder_to_auction(auction_id):
    if session.get("role") != "bidder":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction:
        flash("Auction not found", "error")
        return redirect(url_for("auctions"))

    if auction["status"] not in {STATUS_REGISTRATION, STATUS_BIDDING_OPEN}:
        flash("Participation is available only before bidding closes.")
        return redirect(url_for("auctions"))

    try:
        if utcnow() > auction_dt(auction, "end_date"):
            flash("Participation is closed because the auction window has already ended.")
            return redirect(url_for("auctions"))
    except ValueError:
        flash("Auction timing is invalid.")
        return redirect(url_for("auctions"))

    bidder_id = session["user_id"]
    existing = auction.get("participant_keys", {}).get(bidder_id)
    if existing:
        flash("Already participating in this auction. Your auction key pair is already linked.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    sk, pk = ring.generate_keypair()
    auctions_col.update_one(
        {"_id": ObjectId(auction_id)},
        {
            "$addToSet": {"bidders": bidder_id},
            "$set": {
                f"participant_keys.{bidder_id}": {
                    "public_key": public_key_to_string(pk),
                }
            },
        },
    )
    # Keep the auction-specific session key only in session (not DB) for signing.
    session[f"auction_sk_{auction_id}"] = str(sk)
    session[f"auction_pk_{auction_id}"] = public_key_to_string(pk)
    flash("Participation successful. Your auction-specific key pair was generated and you can now bid when the stage is open.")
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
    bidder_public_key = auction.get("participant_keys", {}).get(session["user_id"], {}).get("public_key")
    bid_floor = auction_bid_floor(auction)
    bid_ceiling = auction_bid_ceiling(auction)
    return render_template(
        "bidder_panel.html",
        auction=serialize_auction(auction),
        bid_doc=bid_doc,
        bidder_public_key=bidder_public_key,
        bid_floor=bid_floor,
        bid_ceiling=bid_ceiling,
        ot_shared_key_value=session.get(f"ot_shared_key_{auction_id}"),
        reveal_randomness_value=session.get(f"reveal_r_{auction_id}"),
        chosen_bid_value=session.get(f"chosen_bid_{auction_id}"),
        stage_notice=build_bidder_stage_notice(auction, bid_doc),
    )


@app.route("/auction/<auction_id>/submit_bid", methods=["POST"])
def submit_bid(auction_id):
    if session.get("role") != "bidder":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if auction["status"] != STATUS_BIDDING_OPEN:
        flash(f"Stage lock: bid submission allowed only in {display_stage(STATUS_BIDDING_OPEN)}")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    bidder_id = session["user_id"]
    if bids_col.find_one({"auction_id": auction_id, "bidder_id": bidder_id}):
        flash("Bid already submitted. Commitment is binding and cannot be changed.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    bid_value = int(request.form["bid_value"])
    bid_floor = auction_bid_floor(auction)
    bid_ceiling = auction_bid_ceiling(auction)
    if bid_value < bid_floor or bid_value > bid_ceiling:
        flash(f"Bid must be within the allowed range {bid_floor} to {bid_ceiling}")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    if not (auction_dt(auction, "start_date") <= utcnow() <= auction_dt(auction, "end_date")):
        flash("Current time is outside allowed bidding window")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    # Phase-1 ring: public keys of all participating bidders in this auction.
    ring_entries = []
    for _, entry in auction.get("participant_keys", {}).items():
        if entry.get("public_key"):
            ring_entries.append(public_key_from_any(entry["public_key"]))

    sk_raw = session.get(f"auction_sk_{auction_id}")
    if not sk_raw:
        flash("Auction session key missing. Rejoin the auction to restore your signing key.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    try:
        signer_sk = int(str(sk_raw).strip())
    except ValueError:
        flash("Invalid session key format")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    signer_pk = public_key_from_any(auction["participant_keys"][bidder_id]["public_key"])
    derived_pk = curve.scalar_mult(signer_sk, ring.G)
    if not curve.points_equal(derived_pk, signer_pk):
        flash("Stored session key does not match your registered public key for this auction.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    session[f"auction_sk_{auction_id}"] = str(signer_sk)
    if signer_pk not in ring_entries:
        ring_entries.append(signer_pk)

    randomness_raw = request.form.get("randomness", "").strip()
    if not randomness_raw:
        flash("Generate randomness r_i first, then submit your commitment.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    try:
        r_i = int(randomness_raw)
    except ValueError:
        flash("Invalid randomness format")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    if not (1 <= r_i < curve.n):
        flash("Randomness r_i must be in valid scalar range.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    session[f"chosen_bid_{auction_id}"] = str(bid_value)
    
    # Stage-2 Pedersen commitment C_i = g^b_i h^r_i
    commitment, r_i = pedersen.commit(bid_value, randomness=r_i)

    # Ring signature over commitment message.
    key_image = ring.generate_key_image(signer_sk, signer_pk)
    msg = f"auction:{auction_id}|commit:{commitment[0]}:{commitment[1]}".encode()
    signature = ring.sign(msg, signer_sk, signer_pk, ring_entries, key_image)
    if not ring.verify(signature):
        flash("Ring signature verification failed")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

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
        {
            "$addToSet": {"commitments": point_to_json(commitment)},
            "$push": {
                "commitment_records": {
                    "commitment": point_to_json(commitment),
                    "signing_public_key": public_key_to_string(signer_pk),
                    "key_image": point_to_json(key_image),
                    "submitted_at": utcnow(),
                }
            },
        },
    )

    # Store r_i in bidder session for later reveal to avoid DB raw pre-reveal storage.
    session[f"reveal_r_{auction_id}"] = str(r_i)

    flash("Commitment submitted with ring signature.")
    return redirect(url_for("bidder_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/retrieve_ot", methods=["POST"])
def retrieve_ot_value(auction_id):
    if session.get("role") != "bidder":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if auction["status"] != STATUS_OT_READY:
        flash(f"OT retrieval is available only in {display_stage(STATUS_OT_READY)} stage")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    bid = bids_col.find_one({"auction_id": auction_id, "bidder_id": session["user_id"]})
    if not bid or not bid.get("ot_sender_state"):
        flash("No OT state available for your bid")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    selected_index_raw = request.form.get("bid_index", "").strip()
    if selected_index_raw == "":
        flash("Choose your bid value before retrieving OT value.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    try:
        selected_index = int(selected_index_raw)
    except ValueError:
        flash("Invalid bid value selected.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    bid_floor = auction_bid_floor(auction)
    bid_ceiling = auction_bid_ceiling(auction)
    if selected_index < bid_floor or selected_index > bid_ceiling:
        flash(f"Chosen bid value must be within the range {bid_floor} to {bid_ceiling}.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    chosen_bid = session.get(f"chosen_bid_{auction_id}")
    if chosen_bid is not None and selected_index != int(chosen_bid):
        flash("Selected OT value must match your committed bid.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    
    ot_state_db = bid["ot_sender_state"]
    sender_state = {
        "original_n": ot_state_db["original_n"],
        "n": ot_state_db["n"],
        "k": ot_state_db["k"],
        "ciphertexts": [bytes.fromhex(x) for x in ot_state_db["ciphertexts"]],
        "level_pairs": [(bytes.fromhex(pair[0]), bytes.fromhex(pair[1])) for pair in ot_state_db["level_pairs"]],
    }
    # The OT tree is indexed from 0, but auction bid values may start at a
    # non-zero floor in forward auctions. Convert the chosen bid value into a
    # zero-based leaf index so the bidder retrieves the intended leaf.
    choice_index = selected_index - bid_floor
    shared_key = ot_tree.receiver_obtain_leaf(sender_state, choice_index).hex()
    session[f"ot_shared_key_{auction_id}"] = shared_key
    session[f"ot_choice_{auction_id}"] = str(selected_index)
    session[f"ot_choice_offset_{auction_id}"] = str(choice_index)
    flash("OT shared key retrieved successfully for your selected bid value.")
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
    bid_floor = auction_bid_floor(auction)
    bid_ceiling = auction_bid_ceiling(auction)
    if bid_value < bid_floor or bid_value > bid_ceiling:
        flash(f"Reveal bid must stay within the auction range {bid_floor} to {bid_ceiling}.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    committed_bid = session.get(f"chosen_bid_{auction_id}")
    if committed_bid is not None and bid_value != int(committed_bid):
        flash("Reveal bid must match the bid you already committed.")
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    randomness_raw = request.form.get("randomness", "").strip() or session.get(f"reveal_r_{auction_id}", "")
    if not randomness_raw:
        flash("Enter commitment randomness r_i used during bid submission.")        
        return redirect(url_for("bidder_panel", auction_id=auction_id))
    randomness = int(randomness_raw)
    shared_key = normalize_shared_key(request.form.get("shared_key", "") or session.get(f"ot_shared_key_{auction_id}", ""))
    if not shared_key:
        flash("Enter OT shared key (retrieved from OT stage).")
        return redirect(url_for("bidder_panel", auction_id=auction_id))

    proof = zk.prove_opening(bid_value, randomness)
    key_proof = zk.prove_key_possession(shared_key)

    bids_col.update_one(
        {"_id": bid["_id"]},
        {
            "$set": {
                "revealed_bid": bid_value,
                "randomness": str(randomness),
                "revealed_shared_key": shared_key,
                "verification_status": "PENDING",
                "zk_opening": {"T": point_to_json(proof["T"]), "e": str(proof["e"]), "z1": str(proof["z1"]), "z2": str(proof["z2"])},
                "zk_key_proof": {"T": point_to_json(key_proof["T"]), "e": str(key_proof["e"]), "z": str(key_proof["z"])},
            }
        },
    )

    flash("Reveal submitted. Auctioneer verification is pending.")
    return redirect(url_for("bidder_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/verify_reveals", methods=["POST"])
def verify_revealed_bids(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction:
        flash("Auction not found", "error")
        return redirect(url_for("auctions"))
    if not require_auctioneer_threshold(auction, "verify revealed bids"):
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    if auction["status"] != STATUS_OT_READY:
        flash("Verification allowed only after OT stage")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    revealed = list(bids_col.find({"auction_id": auction_id, "revealed_bid": {"$ne": None}}))
    if not revealed:
        flash("No revealed bids to verify")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    valid_count, invalid_count = 0, 0
    for bid in revealed:
        c_i = point_from_json(bid["commitment"])
        b_i = int(bid["revealed_bid"])
        r_i = int(bid["randomness"])
        expected_commitment, _ = pedersen.commit(b_i, r_i)
        commit_ok = pedersen.verify_opening(c_i, b_i, r_i)
        revealed_shared_key = normalize_shared_key(bid.get("revealed_shared_key", ""))
        ot_key_map = bid.get("ot_key_map", {})
        expected_shared_key = normalize_shared_key(ot_key_map.get(str(b_i), ""))
        # Backward compatibility for records created before ot_key_map existed.
        if not expected_shared_key:
            expected_shared_key = normalize_shared_key(bid.get("ot_expected_shared_key", ""))
        shared_key_ok = bool(revealed_shared_key and expected_shared_key and revealed_shared_key == expected_shared_key)
        zk_payload = bid.get("zk_opening", {})
        zk_ok = False
        if zk_payload and zk_payload.get("T"):
            zk_ok = zk.verify_opening_proof(
                c_i,
                {
                    "T": point_from_json(zk_payload["T"]),
                    "e": int(zk_payload["e"]),
                    "z1": int(zk_payload["z1"]),
                    "z2": int(zk_payload["z2"]),
                },
            )
        key_proof_payload = bid.get("zk_key_proof", {})
        key_proof_ok = False
        if key_proof_payload and key_proof_payload.get("T"):
            key_proof_ok = zk.verify_key_possession_proof(
                expected_shared_key,
                {
                    "T": point_from_json(key_proof_payload["T"]),
                    "e": int(key_proof_payload["e"]),
                    "z": int(key_proof_payload["z"]),
                },
            )
        is_valid = bool(shared_key_ok and commit_ok and zk_ok and key_proof_ok)
        bids_col.update_one(
            {"_id": bid["_id"]},
             {
                "$set": {
                    "shared_key_valid": shared_key_ok,
                    "expected_shared_key_from_reveal_bid": expected_shared_key,
                    "commitment_valid": commit_ok,
                    "expected_commitment": point_to_json(expected_commitment),
                    "zk_valid": zk_ok,
                    "key_proof_valid": key_proof_ok,
                    "is_valid": is_valid,
                    "verification_status": "VERIFIED",
                }
            },
        )
        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1

    auctions_col.update_one({"_id": ObjectId(auction_id)}, {"$set": {"status": STATUS_VERIFIED}})
    flash(f"Verification completed. Valid bids: {valid_count}, Invalid bids: {invalid_count}.")
    return redirect(url_for("auctioneer_panel", auction_id=auction_id))


@app.route("/auction/<auction_id>/declare_winner", methods=["POST"])
def declare_winner(auction_id):
    if session.get("role") != "auctioneer":
        return redirect(url_for("auctions"))

    auction = auctions_col.find_one({"_id": ObjectId(auction_id)})
    if not auction:
        flash("Auction not found", "error")
        return redirect(url_for("auctions"))
    if not require_auctioneer_threshold(auction, "declare the winner"):
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    if auction["status"] != STATUS_VERIFIED:
        flash("Stage lock: winner declaration allowed only after auctioneer verification")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    valid = list(bids_col.find({"auction_id": auction_id, "is_valid": True}))
    if not valid:
        flash("No valid revealed bids")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))

    forward_auction = auction_is_forward(auction)
    winner = max(valid, key=lambda x: x["revealed_bid"]) if forward_auction else min(valid, key=lambda x: x["revealed_bid"])

    # Shamir: persist threshold shares in MongoDB so multiple auctioneers can
    # jointly hold the winning authorization material.
    secret = int(hashlib.sha256(f"{auction_id}:{winner['_id']}".encode()).hexdigest(), 16)
    threshold = auctioneer_threshold(auction)
    auctioneer_id_list = auctioneer_ids(auction)
    total_auctioneers = len(auctioneer_id_list)
    if total_auctioneers < threshold:
        flash(
            f"Winner declaration blocked: at least {threshold} unique auctioneer account(s) must be present to distribute Shamir shares, but only {total_auctioneers} are available."
        )
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))
    shares = split_secret(secret, threshold, total_auctioneers)

    auction_shares_col.delete_many({"auction_id": auction_id})
    share_docs = []
    for idx, (x, y) in enumerate(shares):
        auctioneer_id = auctioneer_id_list[idx]
        doc = {
            "auction_id": auction_id,
            "auctioneer_id": auctioneer_id,
            "x": x,
            "y": str(y),
            "threshold": threshold,
            "total": total_auctioneers,
            "winner_secret_id": str(winner["_id"]),
            "created_at": utcnow(),
        }
        share_docs.append(doc)
    if share_docs:
        auction_shares_col.insert_many(share_docs)

    persisted_shares = list(auction_shares_col.find({"auction_id": auction_id}).sort("x", 1))
    if len(persisted_shares) < threshold:
        flash("Winner share distribution failed")
        return redirect(url_for("auctioneer_panel", auction_id=auction_id))
    recovered = reconstruct_secret(
        [(int(doc["x"]), int(doc["y"])) for doc in persisted_shares[:threshold]]
    )

    # ZK relation checks depend on the auction direction.
    c_w = point_from_json(winner["commitment"])
    proof_ok = True
    for b in valid:
        c_j = point_from_json(b["commitment"])
        if forward_auction:
            d_j = max(winner["revealed_bid"] - b["revealed_bid"], 0)
            rho_j = int(winner["randomness"]) - int(b["randomness"])
            pf = zk.prove_maximum_relation(c_w, c_j, d_j, rho_j)
            if not zk.verify_maximum_relation(pf):
                proof_ok = False
                break
        else:
            d_j = max(b["revealed_bid"] - winner["revealed_bid"], 0)
            rho_j = int(b["randomness"]) - int(winner["randomness"])
            pf = zk.prove_minimum_relation(c_w, c_j, d_j, rho_j)
            if not zk.verify_minimum_relation(pf):
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
                "shares": [{"auctioneer_id": doc["auctioneer_id"], "x": doc["x"], "y": doc["y"]} for doc in share_docs],
                "winner_secret_id": str(winner["_id"]),
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
    port = int(os.getenv("PORT", os.getenv("FLASK_PORT", "5000")))
    debug = os.getenv("FLASK_DEBUG", "1").strip().lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=port, debug=debug)
