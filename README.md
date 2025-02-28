## SocialHub – Telegram Chat Viewer

📌 SocialHub is a web application that allows you to connect a Telegram account, view chats, and read messages.

## 🚀 Technologies

-   **Frontend**: Next.js
-   **Backend**: FastAPI
-   **Authentication**: JWT
-   **Database**: SQLite

## ⚡ Main Features

✅ User registration & login via JWT
✅ Connect a Telegram account
✅ View chat list with minimalist design
✅ Read messages in selected chats with a "Back to Chats" button
✅ Disconnect from Telegram

## 🔧 Installation & Setup

## 1️⃣ Clone the repository

```bash
git clone https://github.com/batalova-kira/socialhub.git
cd socialhub
```

## 2️⃣ Setup and Run

```bash
## Install required software:
## - Git: https://git-scm.com/
## - Node.js (v16+): https://nodejs.org/
## - Python (3.9+): https://www.python.org/
## Check versions:
git --version
node --version
python --version  ## or python3 --version on Linux/Mac
```

## Setup backend (FastAPI):

```bash
cd server
python -m venv venv  ## Create virtual environment
```

## Activate it:

```bash
#### Windows (CMD): venv\Scripts\activate
#### Windows (Git Bash): source venv/Scripts/activate
#### Mac/Linux: source venv/bin/activate
pip install -r requirements.txt  #### Install dependencies (fastapi, uvicorn, sqlalchemy, aiosqlite, telethon, python-jose[cryptography], passlib[bcrypt], python-dotenv)
```

## Create and configure .env:

```bash
cp .env.example .env
```

## Edit server/.env with your text editor (e.g., Notepad or VS Code):

```bash
## API_ID=your_telegram_api_id (get from https://my.telegram.org)
## API_HASH=your_telegram_api_hash (get from https://my.telegram.org)
## JWT_SECRET=your_secret_key (e.g., "mysecretkey123")
```

## Start FastAPI server (in this terminal):

```bash
python -m uvicorn main:app --reload
```

## Backend runs at: http://127.0.0.1:8000

## Setup frontend (Next.js):

```bash
cd ../client
npm install  # Install dependencies
```

## Start Next.js (open a new terminal for this):

```bash
npm run dev
```

## Frontend runs at: http://localhost:3000

## How to use:

#### 1. Open http://localhost:3000 in your browser

#### 2. Register (e.g., username: "test123", password: "password123") or login

#### 3. Enter Telegram phone number (e.g., +380963048847) and click "Get Code"

#### 4. Wait for code in Telegram (SMS or call, up to 1-2 minutes)

#### 5. Enter code and click "Connect"

#### 6. View chats and messages

🤝 Contact
Author: https://github.com/batalova-kira

Feedback? Open an https://github.com/batalova-kira/socialhub/issues. 🚀

```

```
