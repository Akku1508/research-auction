# Backend Setup (Flask + MongoDB)

## 1) Install dependencies
```bash
pip install -r backend/requirements.txt
```

## 2) Configure environment variables
Preferred:
1. Copy `backend/.env.example` to `backend/.env`
2. Replace values with your MongoDB credentials.

The app auto-loads `backend/.env` on startup.

Required values:
- `MONGO_URI` - MongoDB connection string (`mongodb://...` or `mongodb+srv://...`)
- `MONGO_DB_NAME` - database name, for example `decentralized_auction`
- `FLASK_SECRET_KEY` - random secret for session signing
- `MONGO_TIMEOUT_MS` - optional ping timeout in milliseconds

### PowerShell alternative
```powershell
$env:MONGO_URI='mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority&appName=dapv-auction'
$env:MONGO_DB_NAME='decentralized_auction'
$env:FLASK_SECRET_KEY='replace-with-random-secret'
$env:MONGO_TIMEOUT_MS='10000'
```

## 3) Run
```bash
python backend/app.py
```

## 4) Verify MongoDB
- Open `http://127.0.0.1:5000/healthz`
- Confirm the response shows `mongo: true`

## Reverse auction note
- Bids are integer values in the range `0..maximum_allowed_bid`
- OT generates one secret per integer value in that range so the bidder can privately retrieve the matching key without exposing the chosen value in the auction records

## Auction type notes
- Reverse auctions use the existing procurement flow and the lowest valid bid wins.
- Forward auctions use a starting bid value plus a maximum bid cap, and the highest valid bid wins.
- Both auction types can store written files and media attachments in the create and edit forms. Uploaded files are saved under `frontend/static/uploads/`.

## Common startup error
If you see `localhost:27017 ... actively refused`, then `MONGO_URI` is not set and the app fell back to local MongoDB.
Set the URI in `backend/.env` or export it as an environment variable, then run again.

## Free deployment on Render
1. Create a free MongoDB Atlas cluster and add your connection string to `MONGO_URI`.
2. Push this repo to GitHub.
3. In Render, create a new Blueprint from the repo and use `render.yaml`.
4. When prompted, set `MONGO_URI`.
5. After the service starts, open the Render URL and verify `/healthz` returns `mongo: true`.
