# SocialHub – Telegram Chat Viewer

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

### 1️⃣ Clone the repository

```bash
git clone https://github.com/batalova-kira/socialhub.git
cd socialhub

2️⃣ Run the backend (FastAPI)
📌 Install dependencies

bash
Wrap
Copy
cd server
python -m venv venv  # Create a virtual environment
# Activate it:
# Windows (CMD): venv\Scripts\activate
# Windows (Git Bash): source venv/Scripts/activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt  # Install dependencies
📌 Start FastAPI server

bash
Wrap
Copy
python -m uvicorn main:app --reload
✅ Backend is running at: http://127.0.0.1:8000

3️⃣ Run the frontend (Next.js)
📌 Install dependencies

bash
Wrap
Copy
cd ../client
npm install  # Install dependencies
📌 Start Next.js

bash
Wrap
Copy
npm run dev
✅ Frontend is running at: http://localhost:3000

🔑 Configuration
Before running, create a .env file in the server/ directory:

Copy the example:
bash
Wrap
Copy
cp .env.example .env
Edit server/.env with these variables:
text
Wrap
Copy
API_ID=your_telegram_api_id
API_HASH=your_telegram_api_hash
JWT_SECRET=your_secret_key
Get API_ID and API_HASH from my.telegram.org.
Use any string for JWT_SECRET (e.g., "mysecretkey123").
📋 How to Use
Open http://localhost:3000 in your browser.
Register (e.g., username: "test123", password: "password123") or log in.
Enter your Telegram phone number (e.g., +380963048847) and click "Get Code".
Wait for the code in Telegram (SMS or call, up to 1-2 minutes).
Enter the code and click "Connect".
View your chats and click one to see messages.

🤝 Contact
Author: Kira Batalova

Feedback? Open an Issue. 🚀
```
