# Backend Setup (Flask + MongoDB Atlas)

## 1) Install dependencies
```bash
pip install -r backend/requirements.txt
```

## 2) Configure environment variables
Preferred (easy in VS Code):
1. Copy `backend/.env.example` to `backend/.env`
2. Replace values with your Atlas credentials.

The app auto-loads `backend/.env` on startup.

Required values:
- `MONGO_URI` → MongoDB Atlas connection string (`mongodb+srv://...`)
- `MONGO_DB_NAME` → database name (e.g. `decentralized_auction`)
- `FLASK_SECRET_KEY` → random secret for session signing

### PowerShell alternative (temporary session variables)
```powershell
$env:MONGO_URI='mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority&appName=dapv-auction'
$env:MONGO_DB_NAME='decentralized_auction'
$env:FLASK_SECRET_KEY='replace-with-random-secret'
```

## 3) Run
```bash
python backend/app.py
```

## Common startup error
If you see `localhost:27017 ... actively refused`, then `MONGO_URI` is not set and the app fell back to local MongoDB.
Set Atlas URI in `backend/.env` (or env vars), then run again.
