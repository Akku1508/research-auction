# Backend Setup (Flask + MongoDB Atlas)

## 1) Install dependencies
```bash
pip install -r backend/requirements.txt
```

## 2) Configure environment variables
Create a `.env` (or export variables in shell) using `backend/.env.example`.

Required values:
- `MONGO_URI` → MongoDB Atlas connection string (`mongodb+srv://...`)
- `MONGO_DB_NAME` → database name (e.g. `decentralized_auction`)
- `FLASK_SECRET_KEY` → random secret for session signing

Example:
```bash
export MONGO_URI='mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority&appName=dapv-auction'
export MONGO_DB_NAME='decentralized_auction'
export FLASK_SECRET_KEY='replace-with-random-secret'
```

## 3) Run
```bash
python backend/app.py
```

If Atlas credentials/network are correct, startup performs a `ping` to verify connectivity immediately.
