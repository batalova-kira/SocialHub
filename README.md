pfp
Привіт! Ти не бачиш останнії моїх питань?

Привіт! Я бачу тільки те, що ти пишеш мені зараз, і не маю доступу до твоїх попередніх питань, якщо вони були адресовані не мені чи в іншому контексті. Як я можу тобі допомогти сьогодні?

в мене є додаток за допомогою якого можна підключити телеграм аккаунт, з
можливістю переглядати список усіх чатів аккаунту та повідомлень.
Функціонал додатку:
Логін/реєстрація у системі.
Функціонал підключення телеграм аккаунту.
Перегляд усіх чатів підключеного телеграм аккаунту.
Перегляд усіх повідомлень обраного чату.
Функціонал виходу з підключеного телеграм аккаунту.
Функціонал виходу із системи.
Вимоги:
Клієнтська частина: React або Next.js.
Серверна частина: Fastapi.Розробити додаток за допомогою якого можна підключити телеграм аккаунт, з
можливістю переглядати список усіх чатів аккаунту та повідомлень.
Функціонал додатку:
Логін/реєстрація у системі.
Функціонал підключення телеграм аккаунту.
Перегляд усіх чатів підключеного телеграм аккаунту.
Перегляд усіх повідомлень обраного чату.
Функціонал виходу з підключеного телеграм аккаунту.
Функціонал виходу із системи.
Вимоги:
Клієнтська частина: React або Next.js.
Серверна частина: Fastapi. import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from telethon import TelegramClient
from pydantic import BaseModel
from database import AsyncSessionLocal, engine
from models import Base, User
from telethon.errors import FloodWaitError
from dotenv import load_dotenv
from telethon.errors import FloodWaitError, SessionExpiredError
from pydantic import BaseModel, ConfigDict
from typing import Optional
from telethon import types
import asyncio

# Завантаження змінних оточення

load_dotenv()

# Ініціалізація додатку

app = FastAPI()

# Налаштування CORS

app.add_middleware(
CORSMiddleware,
allow_origins=["http://localhost:3000"],
allow_credentials=True,
allow_methods=["*"],
allow_headers=["*"],
)

# Конфігурація JWT

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Конфігурація Telegram

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

# Хешування паролів

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Схема автентифікації

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Зберігання активних сесій Telegram

tg_clients = {}

# Моделі запитів

class UserCreate(BaseModel):
username: str
password: str

class UserLogin(BaseModel):
username: str
password: str

class TelegramSendCode(BaseModel):
phone: str

class TelegramConnect(BaseModel):
code: str # Обов'язкове поле
password: Optional[str] = None # Необов'язкове поле
phone: Optional[str] = None # Додаємо як необов'язкове

class TelegramSession(BaseModel):
phone: str
phone_code_hash: str
client: Optional[types.User] = None # Це поле викликає проблему

    model_config = ConfigDict(arbitrary_types_allowed=True)  # ✅ Дозволяє довільні типи

    # Тимчасове сховище для сесій (можна замінити на Redis або БД)

temp_sessions = {}

# Залежності

async def get_db():
async with AsyncSessionLocal() as session:
yield session

    # Логування мідлвар

@app.middleware("http")
async def log_requests(request, call_next):
print(f"Отримано запит: {request.method} {request.url}")
response = await call_next(request)
print(f"Відповідь: {response.status_code}")
return response

# Створення таблиць при старті

@app.on_event("startup")
async def startup():
async with engine.begin() as conn:
await conn.run_sync(Base.metadata.create_all)

# Генерація JWT токена

def create_access_token(data: dict):
to_encode = data.copy()
expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
to_encode.update({"exp": expire})
return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Отримання поточного користувача

async def get_current_user(
token: str = Depends(oauth2_scheme),
db: AsyncSession = Depends(get_db)
):
try:
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
username = payload.get("sub")
if not username:
raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Помилка токена")

# Реєстрація

@app.post("/register", status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
result = await db.execute(select(User).filter(User.username == user.username))
if result.scalar():
raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    await db.commit()
    return {"message": "User created successfully"}

# Логін

@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
result = await db.execute(select(User).filter(User.username == user.username))
db_user = result.scalar()

    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
print(f"🔍 Перевірка токена для: {current_user.username}")

    if not current_user.telegram_phone:
        return {"connected": False}
    return {"connected": True}

# Підключення Telegram

@app.post("/connect-telegram")
async def connect_telegram(
auth: TelegramConnect,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
try:
session_data = temp_sessions.get(current_user.id)
if not session_data or "client" not in session_data:
raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        await client.sign_in(
            phone=session_data["phone"],
            code=auth.code,
            phone_code_hash=session_data["phone_code_hash"],
            password=auth.password
        )

        # Зберігаємо сесію на диск
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()
        await client.sign_in(phone=session_data["phone"], code=auth.code, phone_code_hash=session_data["phone_code_hash"])

        current_user.telegram_phone = session_data["phone"]
        await db.commit()
        await client.disconnect()
        del temp_sessions[current_user.id]

        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка авторизації: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

# Отримання чатів

@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
if not current_user.telegram_phone:
raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f'sessions/session_{current_user.id}', API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")  # Логування для дебагу
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

# Отримання коду

@app.post("/send-code")
async def send_code(
data: TelegramSendCode,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
try:
if current_user.id in temp_sessions:
await temp_sessions[current_user.id]["client"].disconnect()
del temp_sessions[current_user.id]

        client = TelegramClient(f"session_{current_user.id}", API_ID, API_HASH)
        await client.connect()
        sent_code = await client.send_code_request(data.phone)

        temp_sessions[current_user.id] = {
            "phone": data.phone,
            "phone_code_hash": sent_code.phone_code_hash,
            "client": client
        }
        return {"detail": "Код відправлено"}
    except FloodWaitError as e:
        raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
    except Exception as e:
        raise HTTPException(400, detail=str(e))

# Отримання повідомлень чата

@app.get("/chats/{chat_id}/messages")
async def get_chat_messages(
chat_id: int,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
client = tg_clients.get(current_user.telegram_phone)
if not client:
raise HTTPException(status_code=404, detail="Telegram not connected")

    messages = await client.get_messages(chat_id, limit=20)
    return [{"id": m.id, "text": m.text, "date": m.date} for m in messages]

# Вихід з Telegram

@app.post("/logout-telegram")
async def logout_telegram(
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
client = tg_clients.pop(current_user.telegram_phone, None)
if client:
await client.disconnect()
current_user.telegram_phone = None
await db.commit()
return {"message": "Telegram disconnected"}

# Вихід з системи

@app.post("/logout")
async def logout_system(current_user: User = Depends(get_current_user)):
return {"message": "Logged out from system"}

# Перевірка здоров'я

@app.get("/health")
async def health_check():
return {"status": "OK"} це серверна чавтина. а це кліентська на нексті: import { useEffect } from "react";
import { useRouter } from "next/router";

export default function HomePage() {
const router = useRouter();

    useEffect(() => {
        const token = localStorage.getItem("token");
        router.push(token ? "/dashboard" : "/login");
    }, []);

    return null; // Або індикатор завантаження

} import { useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Login() {
const [username, setUsername] = useState("");
const [password, setPassword] = useState("");
const [error, setError] = useState("");
const router = useRouter();

    const handleLogin = async (e) => {
        e.preventDefault();

        try {
            const res = await fetch("http://localhost:8000/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            const data = await res.json();

            if (!res.ok) throw new Error(data.detail || "Login failed");

            localStorage.setItem("token", data.access_token);
            router.push("/dashboard");
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-md">
            <h1 className="text-2xl font-bold mb-6">Вхід</h1>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            <form onSubmit={handleLogin} className="space-y-4">
                <input
                    type="text"
                    placeholder="Ім'я користувача"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full p-2 border rounded"
                />
                <input
                    type="password"
                    placeholder="Пароль"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full p-2 border rounded"
                />
                <button
                    type="submit"
                    className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
                >
                    Увійти
                </button>
            </form>
            <p className="mt-4 text-center">
                Немає акаунта?{" "}
                <Link
                    href="/register"
                    className="text-blue-500 hover:underline"
                >
                    Зареєструватися
                </Link>
            </p>
        </div>
    );

}
import { useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Register() {
const [username, setUsername] = useState("");
const [password, setPassword] = useState("");
const [error, setError] = useState("");
const router = useRouter();

    const handleSubmit = async (e) => {
        e.preventDefault();

        try {
            const res = await fetch("http://localhost:8000/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Registration failed");
            }

            router.push("/login");
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-md">
            <h1 className="text-2xl font-bold mb-6">Реєстрація</h1>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            <form onSubmit={handleSubmit} className="space-y-4">
                <input
                    type="text"
                    placeholder="Ім'я користувача"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full p-2 border rounded"
                />
                <input
                    type="password"
                    placeholder="Пароль"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full p-2 border rounded"
                />
                <button
                    type="submit"
                    className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
                >
                    Зареєструватися
                </button>
            </form>
            <p className="mt-4 text-center">
                Вже маєте акаунт?{" "}
                <Link href="/login" className="text-blue-500 hover:underline">
                    Увійти
                </Link>
            </p>
        </div>
    );

}
import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Dashboard() {
const [phone, setPhone] = useState("");
const [code, setCode] = useState("");
const [chats, setChats] = useState([]);
const [isConnected, setIsConnected] = useState(false);
const [isCodeSent, setIsCodeSent] = useState(false);
const [error, setError] = useState("");
const router = useRouter();
const [twoFactorPassword, setTwoFactorPassword] = useState("");
// Перевірка статусу підключення Telegram
useEffect(() => {
const checkConnection = async () => {
const token = localStorage.getItem("token");
if (!token) {
router.push("/login");
return;
}

            try {
                const res = await fetch(
                    "http://localhost:8000/check-connection",
                    {
                        headers: { Authorization: `Bearer ${token}` },
                    }
                );

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(
                        data.detail || "Не вдалося перевірити підключення"
                    );
                }

                const data = await res.json();
                setIsConnected(data.connected);
            } catch (err) {
                setError(err.message);
            }
        };

        checkConnection();
    }, [router]);

    // Надсилання коду на телефон
    const sendCode = async (e) => {
        e.preventDefault();
        setError("");

        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/send-code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ phone }),
            });

            const data = await res.json();
            if (!res.ok)
                throw new Error(data.detail || "Помилка відправки коду");

            setIsCodeSent(true);
        } catch (err) {
            setError(err.message);
        }
    };

    // Підключення Telegram
    const connectTelegram = async (e) => {
        e.preventDefault();
        setError("");

        try {
            const token = localStorage.getItem("token");
            if (!token) return router.push("/login");

            const body = { code: code.trim() };
            if (twoFactorPassword) body.password = twoFactorPassword;

            const res = await fetch("http://localhost:8000/connect-telegram", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(body),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Помилка підключення");
            }

            setIsConnected(true);
            await fetchChats(); // Дочекайся завершення
        } catch (err) {
            setError(err.message);
        }
    };

    // Отримання чатів
    const fetchChats = async () => {
        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/chats", {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Не вдалося завантажити чати");
            }

            const data = await res.json();
            setChats(data);
        } catch (err) {
            setError(err.message);
        }
    };

    // Показуємо чати тільки якщо Telegram підключено
    useEffect(() => {
        if (isConnected) {
            fetchChats();
        }
    }, [isConnected]);

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6">Панель управління</h1>

            {error && <p className="text-red-500 mb-4">{error}</p>}

            {!isConnected ? (
                // Форма підключення Telegram
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4">Підключіть Telegram</h2>

                    {!isCodeSent ? (
                        // Крок 1: Введення номера телефону
                        <form onSubmit={sendCode} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть номер телефону"
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <input
                                type="password"
                                placeholder="Пароль 2FA (якщо потрібно)"
                                value={twoFactorPassword}
                                onChange={(e) =>
                                    setTwoFactorPassword(e.target.value)
                                }
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Отримати код
                            </button>
                        </form>
                    ) : (
                        // Крок 2: Введення коду з Telegram
                        <form onSubmit={connectTelegram} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть код з Telegram"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Підключити
                            </button>
                        </form>
                    )}
                </div>
            ) : (
                // Список чатів
                <div>
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-xl">Ваші чати</h2>
                        <button
                            onClick={() => setIsConnected(false)}
                            className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600"
                        >
                            Змінити акаунт
                        </button>
                    </div>

                    <div className="space-y-4">
                        {chats.map((chat) => (
                            <div
                                key={chat.id}
                                className="p-4 border rounded hover:bg-gray-50"
                            >
                                <Link
                                    href={`/chats/${chat.id}`}
                                    className="text-blue-500 hover:underline"
                                >
                                    {chat.name}
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );

}
import { useState, useEffect } from "react";
import { useRouter } from "next/router";

export default function Chats() {
const [chats, setChats] = useState([]);
const [error, setError] = useState("");
const router = useRouter();

    useEffect(() => {
        const fetchChats = async () => {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            try {
                const res = await fetch("http://localhost:8000/chats", {
                    headers: { Authorization: `Bearer ${token}` },
                });
                if (!res.ok) throw new Error("Не вдалося завантажити чати");
                const data = await res.json();
                setChats(data);
            } catch (err) {
                setError(err.message);
            }
        };
        fetchChats();
    }, [router]);

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6">Ваші чати</h1>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            <div className="space-y-4">
                {chats.map((chat) => (
                    <div key={chat.id} className="p-4 border rounded">
                        <p>{chat.name}</p>
                    </div>
                ))}
            </div>
        </div>
    );

}
по перше криво працює вихід з ьелеграм аккаунту, воно повертає не до воду номера телефона а до вводу коду, по друге при спробі отримати чати після вводу коду з телеграм - це відповідь кліента G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:121

           GET http://localhost:8000/chats 500 (Internal Server Error)

fetchChats @ G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:121
Dashboard.useEffect @ G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:140
react-stack-bottom-frame @ react-dom-client.development.js:22510
runWithFiberInDEV @ react-dom-client.development.js:544
commitHookEffectListMount @ react-dom-client.development.js:10759
commitHookPassiveMountEffects @ react-dom-client.development.js:10879
commitPassiveMountOnFiber @ react-dom-client.development.js:12654
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12658
flushPassiveEffects @ react-dom-client.development.js:15461
eval @ react-dom-client.development.js:15325
performWorkUntilDeadline @ scheduler.development.js:44Understand this errorAI
G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:121

           GET http://localhost:8000/chats 500 (Internal Server Error)

fetchChats @ G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:121
Dashboard.useEffect @ G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:140
react-stack-bottom-frame @ react-dom-client.development.js:22510
runWithFiberInDEV @ react-dom-client.development.js:544
commitHookEffectListMount @ react-dom-client.development.js:10759
commitHookPassiveMountEffects @ react-dom-client.development.js:10879
commitPassiveMountOnFiber @ react-dom-client.development.js:12654
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12756
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12647
recursivelyTraversePassiveMountEffects @ react-dom-client.development.js:12628
commitPassiveMountOnFiber @ react-dom-client.development.js:12658
flushPassiveEffects @ react-dom-client.development.js:15461
eval @ react-dom-client.development.js:15325
performWorkUntilDeadline @ scheduler.development.js:44Understand this errorAI
:3000/dashboard:1 Access to fetch at 'http://localhost:8000/connect-telegram' from origin 'http://localhost:3000' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource. If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.Understand this errorAI
G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:91

           POST http://localhost:8000/connect-telegram net::ERR_FAILED 500 (Internal Server Error) а це сервака INFO:     127.0.0.1:51883 - "GET /chats HTTP/1.1" 500 Internal Server Error

Отримано запит: OPTIONS http://localhost:8000/send-code
Відповідь: 200
INFO: 127.0.0.1:51916 - "OPTIONS /send-code HTTP/1.1" 200 OK
Отримано запит: POST http://localhost:8000/send-code
2025-02-28 11:58:22,650 INFO sqlalchemy.engine.Engine BEGIN (implicit)
2025-02-28 11:58:22,650 INFO sqlalchemy.engine.Engine SELECT users.id, users.username, users.password_hash, users.telegram_phone
FROM users
WHERE users.username = ?
2025-02-28 11:58:22,653 INFO sqlalchemy.engine.Engine [cached since 123.5s ago] ('test123',)
2025-02-28 11:58:23,095 INFO sqlalchemy.engine.Engine ROLLBACK
Відповідь: 200
INFO: 127.0.0.1:51916 - "POST /send-code HTTP/1.1" 200 OK
Отримано запит: OPTIONS http://localhost:8000/connect-telegram
Відповідь: 200
INFO: 127.0.0.1:51919 - "OPTIONS /connect-telegram HTTP/1.1" 200 OK
Отримано запит: POST http://localhost:8000/connect-telegram
2025-02-28 11:58:39,454 INFO sqlalchemy.engine.Engine BEGIN (implicit)
2025-02-28 11:58:39,455 INFO sqlalchemy.engine.Engine SELECT users.id, users.username, users.password_hash, users.telegram_phone
FROM users
WHERE users.username = ?
2025-02-28 11:58:39,456 INFO sqlalchemy.engine.Engine [cached since 140.3s ago] ('test123',)
2025-02-28 11:58:43,403 INFO sqlalchemy.engine.Engine ROLLBACK
INFO: 127.0.0.1:51919 - "POST /connect-telegram HTTP/1.1" 500 Internal Server Error
ERROR: Exception in ASGI application

-   Exception Group Traceback (most recent call last):
    | File "C:\Python311\Lib\site-packages\starlette_utils.py", line 76, in collapse_excgroups
    | yield
    | File "C:\Python311\Lib\site-packages\starlette\middleware\base.py", line 178, in **call**
    | async with anyio.create_task_group() as task_group:
    | File "C:\Python311\Lib\site-packages\anyio_backends_asyncio.py", line 767, in **aexit**
    | raise BaseExceptionGroup(
    | ExceptionGroup: unhandled errors in a TaskGroup (1 sub-exception)
    +-+---------------- 1 ----------------
    | Traceback (most recent call last):
    | File "C:\Python311\Lib\site-packages\uvicorn\protocols\http\h11_impl.py", line 403, in run_asgi
    | result = await app( # type: ignore[func-returns-value]
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    | File "C:\Python311\Lib\site-packages\uvicorn\middleware\proxy_headers.py", line 60, in **call**
    | return await self.app(scope, receive, send)
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    | File "C:\Python311\Lib\site-packages\fastapi\applications.py", line 1054, in **call**
    | await super().**call**(scope, receive, send)
    | File "C:\Python311\Lib\site-packages\starlette\applications.py", line 112, in **call**
    | await self.middleware_stack(scope, receive, send)
    | File "C:\Python311\Lib\site-packages\starlette\middleware\errors.py", line 187, in **call**
    | raise exc
    | File "C:\Python311\Lib\site-packages\starlette\middleware\errors.py", line 165, in **call**
    | await self.app(scope, receive, \_send)
    | File "C:\Python311\Lib\site-packages\starlette\middleware\base.py", line 177, in **call**
    | with recv_stream, send_stream, collapse_excgroups():
    | File "C:\Python311\Lib\contextlib.py", line 155, in **exit**
    | self.gen.throw(typ, value, traceback)
    | File "C:\Python311\Lib\site-packages\starlette_utils.py", line 82, in collapse_excgroups
    | raise exc
    | File "C:\Python311\Lib\site-packages\starlette\middleware\base.py", line 179, in **call**
    | response = await self.dispatch_func(request, call_next)
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    | File "G:\Projects\NextJS\SocialHub\server\main.py", line 92, in log_requests
    | response = await call_next(request)
    | ^^^^^^^^^^^^^^^^^^^^^^^^
    | File "C:\Python311\Lib\site-packages\starlette\middleware\base.py", line 154, in call_next
    | raise app_exc
    | File "C:\Python311\Lib\site-packages\starlette\middleware\base.py", line 141, in coro
    | await self.app(scope, receive_or_disconnect, send_no_error)
    | File "C:\Python311\Lib\site-packages\starlette\middleware\cors.py", line 93, in **call**
    | await self.simple_response(scope, receive, send, request_headers=headers)
    | File "C:\Python311\Lib\site-packages\starlette\middleware\cors.py", line 144, in simple_response
    | await self.app(scope, receive, send)
    | File "C:\Python311\Lib\site-packages\starlette\middleware\exceptions.py", line 62, in **call**
    | await wrap_app_handling_exceptions(self.app, conn)(scope, receive, send)
    | File "C:\Python311\Lib\site-packages\starlette_exception_handler.py", line 53, in wrapped_app
    | raise exc
    | File "C:\Python311\Lib\site-packages\starlette_exception_handler.py", line 42, in wrapped_app
    | await app(scope, receive, sender)
    | File "C:\Python311\Lib\site-packages\starlette\routing.py", line 715, in **call**
    | await self.middleware_stack(scope, receive, send)
    | File "C:\Python311\Lib\site-packages\starlette\routing.py", line 735, in app
    | await route.handle(scope, receive, send)
    | File "C:\Python311\Lib\site-packages\starlette\routing.py", line 288, in handle
    | await self.app(scope, receive, send)
    | File "C:\Python311\Lib\site-packages\starlette\routing.py", line 76, in app
    | await wrap_app_handling_exceptions(app, request)(scope, receive, send)
    | File "C:\Python311\Lib\site-packages\starlette_exception_handler.py", line 53, in wrapped_app
    | raise exc
    | File "C:\Python311\Lib\site-packages\starlette_exception_handler.py", line 42, in wrapped_app
    | await app(scope, receive, sender)
    | File "C:\Python311\Lib\site-packages\starlette\routing.py", line 73, in app
    | response = await f(request)
    | ^^^^^^^^^^^^^^^^
    | File "C:\Python311\Lib\site-packages\fastapi\routing.py", line 301, in app
    | raw_response = await run_endpoint_function(
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    | File "C:\Python311\Lib\site-packages\fastapi\routing.py", line 212, in run_endpoint_function
    | return await dependant.call(\*\*values)
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    | File "G:\Projects\NextJS\SocialHub\server\main.py", line 195, in connect_telegram
    | except SessionPasswordNeededError:
    | ^^^^^^^^^^^^^^^^^^^^^^^^^^
    | NameError: name 'SessionPasswordNeededError' is not defined
    +------------------------------------

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
File "C:\Python311\Lib\site-packages\uvicorn\protocols\http\h11_impl.py", line 403, in run_asgi
result = await app( # type: ignore[func-returns-value]
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "C:\Python311\Lib\site-packages\uvicorn\middleware\proxy_headers.py", line 60, in **call**
return await self.app(scope, receive, send)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "C:\Python311\Lib\site-packages\fastapi\applications.py", line 1054, in **call**
await super().**call**(scope, receive, send)
File "C:\Python311\Lib\site-packages\starlette\applications.py", line 112, in **call**
await self.middleware_stack(scope, receive, send)
File "C:\Python311\Lib\site-packages\starlette\middleware\errors.py", line 187, in **call**
raise exc
File "C:\Python311\Lib\site-packages\starlette\middleware\errors.py", line 165, in **call**
await self.app(scope, receive, \_send)
File "C:\Python311\Lib\site-packages\starlette\middleware\base.py", line 177, in **call**
with recv_stream, send_stream, collapse_excgroups():
File "C:\Python311\Lib\contextlib.py", line 155, in **exit**
self.gen.throw(typ, value, traceback)
File "C:\Python311\Lib\site-packages\starlette_utils.py", line 82, in collapse_excgroups
raise exc
File "C:\Python311\Lib\site-packages\starlette\middleware\base.py", line 179, in **call**
response = await self.dispatch_func(request, call_next)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "G:\Projects\NextJS\SocialHub\server\main.py", line 92, in log_requests
response = await call_next(request)
^^^^^^^^^^^^^^^^^^^^^^^^
File "C:\Python311\Lib\site-packages\starlette\middleware\base.py", line 154, in call_next
raise app_exc
File "C:\Python311\Lib\site-packages\starlette\middleware\base.py", line 141, in coro
await self.app(scope, receive_or_disconnect, send_no_error)
File "C:\Python311\Lib\site-packages\starlette\middleware\cors.py", line 93, in **call**
await self.simple_response(scope, receive, send, request_headers=headers)
File "C:\Python311\Lib\site-packages\starlette\middleware\cors.py", line 144, in simple_response
await self.app(scope, receive, send)
File "C:\Python311\Lib\site-packages\starlette\middleware\exceptions.py", line 62, in **call**
await wrap_app_handling_exceptions(self.app, conn)(scope, receive, send)
File "C:\Python311\Lib\site-packages\starlette_exception_handler.py", line 53, in wrapped_app
raise exc
File "C:\Python311\Lib\site-packages\starlette_exception_handler.py", line 42, in wrapped_app
await app(scope, receive, sender)
File "C:\Python311\Lib\site-packages\starlette\routing.py", line 715, in **call**
await self.middleware_stack(scope, receive, send)
File "C:\Python311\Lib\site-packages\starlette\routing.py", line 735, in app
await route.handle(scope, receive, send)
File "C:\Python311\Lib\site-packages\starlette\routing.py", line 288, in handle
await self.app(scope, receive, send)
File "C:\Python311\Lib\site-packages\starlette\routing.py", line 76, in app
await wrap_app_handling_exceptions(app, request)(scope, receive, send)
File "C:\Python311\Lib\site-packages\starlette_exception_handler.py", line 53, in wrapped_app
raise exc
File "C:\Python311\Lib\site-packages\starlette_exception_handler.py", line 42, in wrapped_app
await app(scope, receive, sender)
File "C:\Python311\Lib\site-packages\starlette\routing.py", line 73, in app
response = await f(request)
^^^^^^^^^^^^^^^^
File "C:\Python311\Lib\site-packages\fastapi\routing.py", line 301, in app
raw_response = await run_endpoint_function(
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "C:\Python311\Lib\site-packages\fastapi\routing.py", line 212, in run_endpoint_function
return await dependant.call(\*\*values)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
File "G:\Projects\NextJS\SocialHub\server\main.py", line 195, in connect_telegram
except SessionPasswordNeededError:
^^^^^^^^^^^^^^^^^^^^^^^^^^
NameError: name 'SessionPasswordNeededError' is not defined

Я проаналізував ваш код і помилки. Давайте розберемо проблеми по порядку і запропонуємо виправлення.

1. Проблема з виходом з Telegram
   Ви зазначили, що вихід з Telegram повертає користувача до введення коду, а не до введення номера телефону. Це пов’язано з логікою в Dashboard.js, де при натисканні "Змінити акаунт" ви просто скидаєте isConnected в false, але не скидаєте isCodeSent. В результаті відображається форма введення коду замість форми введення телефону.

Виправлення:
У функції Dashboard.js додайте скидання isCodeSent разом із isConnected:

javascript
Wrap
Copy
const handleLogoutTelegram = async () => {
try {
const token = localStorage.getItem("token");
const res = await fetch("http://localhost:8000/logout-telegram", {
method: "POST",
headers: { Authorization: `Bearer ${token}` },
});
if (!res.ok) throw new Error("Не вдалося вийти з Telegram");
setIsConnected(false);
setIsCodeSent(false); // Скидаємо стан, щоб повернутися до введення телефону
setPhone(""); // Очищаємо номер телефону
setCode(""); // Очищаємо код
} catch (err) {
setError(err.message);
}
};

// Оновіть кнопку "Змінити акаунт":
<button
onClick={handleLogoutTelegram}
className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600"

>

    Змінити акаунт

</button>
На сервері (/logout-telegram) переконайтеся, що сесія Telegram дійсно видаляється коректно. Поточна реалізація виглядає нормально, але додайте очищення файлу сесії:

python
Wrap
Copy
@app.post("/logout-telegram")
async def logout*telegram(
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
if current_user.telegram_phone and os.path.exists(f"sessions/session*{current*user.id}"):
os.remove(f"sessions/session*{current_user.id}") # Видаляємо файл сесії
current_user.telegram_phone = None
await db.commit()
return {"message": "Telegram disconnected"} 2. Помилка 500 при отриманні чатів (GET /chats)
Помилка 500 Internal Server Error виникає через проблему в ендпоінті /connect-telegram. У вашому коді є помилка з імпортом SessionPasswordNeededError. Ви імпортуєте його неправильно, через що виникає NameError.

Виправлення:
У верхній частині файлу додайте правильний імпорт із telethon.errors:

python
Wrap
Copy
from telethon.errors import SessionPasswordNeededError, FloodWaitError, SessionExpiredError
Тепер ваш обробник помилок у /connect-telegram виглядатиме правильно. Оновлений код:

python
Wrap
Copy
@app.post("/connect-telegram")
async def connect_telegram(
auth: TelegramConnect,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
try:
session_data = temp_sessions.get(current_user.id)
if not session_data or "client" not in session_data:
raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        # Зберігаємо сесію
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()
        await client.sign_in(phone=session_data["phone"], code=auth.code, phone_code_hash=session_data["phone_code_hash"])

        current_user.telegram_phone = session_data["phone"]
        await db.commit()
        await client.disconnect()
        del temp_sessions[current_user.id]

        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка авторизації: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

3. Проблема з CORS
   Ви отримали помилку CORS: No 'Access-Control-Allow-Origin' header is present. Це може бути пов’язано з тим, що ваш сервер не завжди повертає коректні заголовки CORS для запитів OPTIONS або через неправильну конфігурацію.

Виправлення:
Переконайтеся, що ваш CORS Middleware налаштований правильно. У вашому коді він виглядає так:

python
Wrap
Copy
app.add_middleware(
CORSMiddleware,
allow_origins=["http://localhost:3000"],
allow_credentials=True,
allow_methods=["*"],
allow_headers=["*"],
)
Це виглядає правильно, але якщо проблема зберігається, спробуйте додати явну обробку запитів OPTIONS у FastAPI:

python
Wrap
Copy
from fastapi.responses import Response

@app.options("/{path:path}")
async def options_handler():
return Response(status_code=200, headers={
"Access-Control-Allow-Origin": "http://localhost:3000",
"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
"Access-Control-Allow-Headers": "\*",
"Access-Control-Allow-Credentials": "true"
}) 4. Помилка при отриманні чатів після підключення
Після введення коду ви отримуєте помилку 500 на /chats. Це може бути пов’язано з тим, що сесія Telegram не зберігається коректно або не ініціалізується повторно.

Виправлення:
Оновіть ендпоінт /chats, щоб переконатися, що клієнт правильно ініціалізується:

python
Wrap
Copy
@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
if not current_user.telegram_phone:
raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f'sessions/session_{current_user.id}', API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

На клієнтській стороні (Dashboard.js) додайте затримку перед викликом fetchChats, щоб дати серверу час завершити підключення:

javascript
Wrap
Copy
const connectTelegram = async (e) => {
e.preventDefault();
setError("");

    try {
        const token = localStorage.getItem("token");
        if (!token) return router.push("/login");

        const body = { code: code.trim() };
        if (twoFactorPassword) body.password = twoFactorPassword;

        const res = await fetch("http://localhost:8000/connect-telegram", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify(body),
        });

        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.detail || "Помилка підключення");
        }

        setIsConnected(true);
        await new Promise(resolve => setTimeout(resolve, 500)); // Додаємо затримку
        await fetchChats();
    } catch (err) {
        setError(err.message);
    }

};
Загальні рекомендації:
Логування: Додайте більше логів на сервері для дебагу (наприклад, print перед кожною операцією з Telegram).
Перевірка сесій: Переконайтеся, що файли сесій (sessions/session\_{user_id}) створюються і доступні.
Тестування: Перевірте кожен ендпоінт окремо через Postman або cURL, щоб ізолювати проблему.
Спробуйте ці зміни і дайте знати, якщо щось ще не працює!

{"detail":"Method Not Allowed"} Access to fetch at 'http://localhost:8000/connect-telegram' from origin 'http://localhost:3000' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource. If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.Understand this errorAI
G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:91

           POST http://localhost:8000/connect-telegram net::ERR_FAILED 500 (Internal Server Error)

connectTelegram @ G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:91
processDispatchQueue @ react-dom-client.development.js:16123
eval @ react-dom-client.development.js:16726
batchedUpdates$1 @ react-dom-client.development.js:3130
dispatchEventForPluginEventSystem @ react-dom-client.development.js:16282
dispatchEvent @ react-dom-client.development.js:20354
dispatchDiscreteEvent @ react-dom-client.development.js:20322Understand this errorAI
dashboard:1 Access to fetch at 'http://localhost:8000/connect-telegram' from origin 'http://localhost:3000' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource. If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.Understand this errorAI
G:\Projects\NextJS\SocialHub\client\pages\dashboard.js:91

           POST http://localhost:8000/connect-telegram  якось спрацьовує через раз, і приходить що новий вхід в телеграм але чати не фечаться

Ваші помилки вказують на кілька проблем: CORS, нестабільність роботи ендпоінту /connect-telegram, а також те, що чати не завантажуються після успішного підключення Telegram. Давайте розберемо їх по черзі і знайдемо рішення.

1. Помилка CORS: "No 'Access-Control-Allow-Origin' header is present"
   Ця помилка означає, що сервер повертає відповідь без заголовка Access-Control-Allow-Origin, хоча у вашому коді FastAPI є CORS Middleware. Проблема може виникати через те, що сервер повертає помилку (наприклад, 500 Internal Server Error або 405 Method Not Allowed), а в таких випадках CORS-заголовки можуть не додаватися автоматично.

Виправлення:
Переконайтеся, що CORS Middleware працює для всіх відповідей, включаючи помилки. Ваш поточний код:
python
Wrap
Copy
app.add_middleware(
CORSMiddleware,
allow_origins=["http://localhost:3000"],
allow_credentials=True,
allow_methods=["*"],
allow_headers=["*"],
)
Виглядає правильно, але додайте обробку помилок у FastAPI, щоб переконатися, що CORS-заголовки завжди присутні:

python
Wrap
Copy
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception*handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
return JSONResponse(
status_code=500,
content={"detail": str(exc)},
headers={
"Access-Control-Allow-Origin": "http://localhost:3000",
"Access-Control-Allow-Credentials": "true",
"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
"Access-Control-Allow-Headers": "*",
}
)
Якщо проблема залишається, додайте явну підтримку OPTIONS запитів (оскільки браузер робить попередній запит перед POST):
python
Wrap
Copy
@app.options("/{path:path}")
async def options*handler():
return Response(
status_code=200,
headers={
"Access-Control-Allow-Origin": "http://localhost:3000",
"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
"Access-Control-Allow-Headers": "*",
"Access-Control-Allow-Credentials": "true",
}
) 2. Помилка "Method Not Allowed"
Повідомлення {"detail":"Method Not Allowed"} означає, що сервер повернув статус 405. Це може статися, якщо:

Ендпоінт /connect-telegram не обробляє POST-запити коректно.
Є помилка в маршрутизації FastAPI.
Перевірка:
Ваш ендпоінт /connect-telegram визначений як POST:

python
Wrap
Copy
@app.post("/connect-telegram")
async def connect_telegram(
auth: TelegramConnect,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
): # ... логіка ...
Це виглядає правильно. Помилка "Method Not Allowed" може виникати через:

Перекриття маршрутів (наприклад, якщо є @app.get("/connect-telegram") деінде).
Проблеми з middleware або неправильною обробкою запитів.
Виправлення:
Перевірте, чи немає інших ендпоінтів із таким же шляхом (/connect-telegram) для інших методів (GET, PUT тощо).
Додайте логування в ендпоінт для дебагу:
python
Wrap
Copy
@app.post("/connect-telegram")
async def connect_telegram(
auth: TelegramConnect,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
print(f"Отримано POST-запит до /connect-telegram для користувача {current_user.id}")
try: # ... існуюча логіка ...
except Exception as e:
print(f"Помилка в /connect-telegram: {str(e)}")
raise 3. Нестабільність роботи /connect-telegram ("працює через раз")
Ви зазначили, що підключення до Telegram спрацьовує не завжди, але ви бачите повідомлення про новий вхід у Telegram. Це може бути пов’язано з:

Проблемами із сесією Telegram (файл сесії не зберігається коректно).
Помилкою в логіці temp_sessions.
Аналіз:
У вашому коді є два створення TelegramClient у /connect-telegram:

python
Wrap
Copy
client = session_data["client"]
await client.connect()
await client.sign_in(...)

client = TelegramClient(f"sessions/session\_{current_user.id}", API_ID, API_HASH)
await client.connect()
await client.sign_in(...)
Це може призводити до конфліктів. Краще використовувати один клієнт і зберігати сесію коректно.

Виправлення:
Оновіть ендпоінт так, щоб уникнути дублювання клієнта:

python
Wrap
Copy
@app.post("/connect-telegram")
async def connect_telegram(
auth: TelegramConnect,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
try:
session_data = temp_sessions.get(current_user.id)
if not session_data or "client" not in session_data:
raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        # Зберігаємо сесію на диск
        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await db.commit()
        del temp_sessions[current_user.id]

        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка авторизації: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

4. Чати не завантажуються після підключення
   Після успішного підключення чати не фетчаться через:

Помилку на сервері (500 Internal Server Error).
Некоректну логіку на клієнті, яка не чекає завершення підключення.
Сервер:
Переконайтеся, що ендпоінт /chats працює коректно:

python
Wrap
Copy
@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
if not current_user.telegram_phone:
raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(400, "Сесія не авторизована")

        dialogs = await client.get_dialogs()
        await client.disconnect()
        return [{"id": d.id, "name": d.name} for d in dialogs]
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(500, f"Помилка: {str(e)}")

Клієнт:
У Dashboard.js додайте затримку і перевірку підключення перед викликом fetchChats:

javascript
Wrap
Copy
const connectTelegram = async (e) => {
e.preventDefault();
setError("");

    try {
        const token = localStorage.getItem("token");
        if (!token) return router.push("/login");

        const body = { code: code.trim() };
        if (twoFactorPassword) body.password = twoFactorPassword;

        const res = await fetch("http://localhost:8000/connect-telegram", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify(body),
        });

        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.detail || "Помилка підключення");
        }

        setIsConnected(true);
        await new Promise(resolve => setTimeout(resolve, 1000)); // Затримка 1 секунда
        await fetchChats();
    } catch (err) {
        setError(err.message);
    }

};

const fetchChats = async () => {
try {
const token = localStorage.getItem("token");
const res = await fetch("http://localhost:8000/chats", {
headers: { Authorization: `Bearer ${token}` },
});
if (!res.ok) {
const data = await res.json();
throw new Error(data.detail || "Не вдалося завантажити чати");
}
const data = await res.json();
setChats(data);
} catch (err) {
setError(err.message);
}
};
Додаткові рекомендації:
Логи: Додайте більше логів на сервері та клієнті для дебагу:
На сервері: print перед кожною операцією з Telegram.
На клієнті: console.log у кожному try/catch.
Перевірка API_ID/API_HASH: Переконайтеся, що ваші API_ID і API_HASH у .env правильні.
Тестування: Використовуйте Postman для перевірки /connect-telegram і /chats окремо.
Спробуйте ці зміни і повідомте, чи вирішено проблему! Якщо щось не працює, надішліть нові логи або помилки.

а можна отримати повнічтю виправлений main.py?

Ось повністю виправлений файл main.py із врахуванням усіх зауважень та виправлень, які ми обговорили. Я додав правильні імпорти, обробку CORS, стабільну логіку для Telegram-сесій і чітке логування для дебагу:

python
Wrap
Copy
import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError, SessionExpiredError
from pydantic import BaseModel
from database import AsyncSessionLocal, engine # Припускаю, що ці модулі у вас є
from models import Base, User # Припускаю, що ці модулі у вас є
from dotenv import load_dotenv
from pydantic import ConfigDict
from telethon import types
import asyncio

# Завантаження змінних оточення

load_dotenv()

# Ініціалізація додатку

app = FastAPI()

# Налаштування CORS

app.add_middleware(
CORSMiddleware,
allow_origins=["http://localhost:3000"],
allow_credentials=True,
allow_methods=["*"],
allow_headers=["*"],
)

# Конфігурація JWT

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Конфігурація Telegram

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

# Хешування паролів

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Схема автентифікації

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Тимчасове сховище для сесій

temp_sessions = {}

# Моделі запитів

class UserCreate(BaseModel):
username: str
password: str

class UserLogin(BaseModel):
username: str
password: str

class TelegramSendCode(BaseModel):
phone: str

class TelegramConnect(BaseModel):
code: str
password: Optional[str] = None
phone: Optional[str] = None

class TelegramSession(BaseModel):
phone: str
phone_code_hash: str
client: Optional[types.User] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

# Залежності

async def get_db():
async with AsyncSessionLocal() as session:
yield session

# Логування middleware

@app.middleware("http")
async def log_requests(request: Request, call_next):
print(f"Отримано запит: {request.method} {request.url}")
response = await call_next(request)
print(f"Відповідь: {response.status_code}")
return response

# Обробка винятків для CORS

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
return JSONResponse(
status_code=500,
content={"detail": str(exc)},
headers={
"Access-Control-Allow-Origin": "http://localhost:3000",
"Access-Control-Allow-Credentials": "true",
"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
"Access-Control-Allow-Headers": "\*",
}
)

# Обробка OPTIONS-запитів

@app.options("/{path:path}")
async def options_handler():
return Response(
status_code=200,
headers={
"Access-Control-Allow-Origin": "http://localhost:3000",
"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
"Access-Control-Allow-Headers": "\*",
"Access-Control-Allow-Credentials": "true",
}
)

# Створення таблиць при старті

@app.on_event("startup")
async def startup():
async with engine.begin() as conn:
await conn.run_sync(Base.metadata.create_all)

# Генерація JWT токена

def create_access_token(data: dict):
to_encode = data.copy()
expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
to_encode.update({"exp": expire})
return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Отримання поточного користувача

async def get_current_user(
token: str = Depends(oauth2_scheme),
db: AsyncSession = Depends(get_db)
):
try:
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
username = payload.get("sub")
if not username:
raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Помилка токена")

# Реєстрація

@app.post("/register", status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
result = await db.execute(select(User).filter(User.username == user.username))
if result.scalar():
raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    await db.commit()
    return {"message": "User created successfully"}

# Логін

@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
result = await db.execute(select(User).filter(User.username == user.username))
db_user = result.scalar()

    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

# Перевірка підключення

@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
print(f"Перевірка підключення для: {current_user.username}")
return {"connected": bool(current_user.telegram_phone)}

# Надсилання коду для Telegram

@app.post("/send-code")
async def send_code(
data: TelegramSendCode,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
try:
if current_user.id in temp_sessions:
await temp_sessions[current_user.id]["client"].disconnect()
del temp_sessions[current_user.id]

        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()
        sent_code = await client.send_code_request(data.phone)

        temp_sessions[current_user.id] = {
            "phone": data.phone,
            "phone_code_hash": sent_code.phone_code_hash,
            "client": client
        }
        return {"detail": "Код відправлено"}
    except FloodWaitError as e:
        raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
    except Exception as e:
        print(f"Помилка в /send-code: {str(e)}")
        raise HTTPException(400, detail=str(e))

# Підключення Telegram

@app.post("/connect-telegram")
async def connect_telegram(
auth: TelegramConnect,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
print(f"Спроба підключення Telegram для користувача {current_user.id}")
try:
session_data = temp_sessions.get(current_user.id)
if not session_data or "client" not in session_data:
raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        # Зберігаємо сесію
        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await db.commit()
        del temp_sessions[current_user.id]

        print(f"Telegram успішно підключено для {current_user.id}")
        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка в /connect-telegram: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

# Отримання чатів

@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
if not current_user.telegram_phone:
raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        print(f"Чати отримано для {current_user.id}")
        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

# Отримання повідомлень чату

@app.get("/chats/{chat_id}/messages")
async def get_chat_messages(
chat_id: int,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
if not current_user.telegram_phone:
raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Сесія не авторизована")

        messages = await client.get_messages(chat_id, limit=20)
        await client.disconnect()

        return [{"id": m.id, "text": m.text, "date": m.date.isoformat()} for m in messages]
    except Exception as e:
        print(f"Помилка в /chats/{chat_id}/messages: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Вихід з Telegram

@app.post("/logout-telegram")
async def logout*telegram(
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
if current_user.telegram_phone and os.path.exists(f"sessions/session*{current*user.id}"):
os.remove(f"sessions/session*{current_user.id}")
current_user.telegram_phone = None
await db.commit()
print(f"Telegram відключено для {current_user.id}")
return {"message": "Telegram disconnected"}

# Вихід з системи

@app.post("/logout")
async def logout_system(current_user: User = Depends(get_current_user)):
return {"message": "Logged out from system"}

# Перевірка здоров'я

@app.get("/health")
async def health_check():
return {"status": "OK"}
Основні зміни:
CORS:
Додано обробник винятків для забезпечення CORS-заголовків у відповідях із помилками.
Додано явну обробку OPTIONS-запитів.
Telegram-сесії:
Виправлено логіку в /connect-telegram, прибравши дублювання TelegramClient.
Переконано, що сесія зберігається коректно після авторизації.
Логування:
Додано print для дебагу в ключових місцях.
Обробка помилок:
Усі except-блоки деталізовані з логуванням і коректними HTTP-відповідями.
Вихід із Telegram:
Додано видалення файлу сесії при виклику /logout-telegram.
Передумови:
Переконайтеся, що у вас є файли database.py і models.py із правильними визначеннями AsyncSessionLocal, engine і моделі User.
У .env мають бути коректні значення для API_ID, API_HASH, і JWT_SECRET.
Тестування:
Запустіть сервер: uvicorn main:app --reload.
Перевірте кожен ендпоінт через Postman або клієнт:
POST /register
POST /login
POST /send-code
POST /connect-telegram
GET /chats
POST /logout-telegram
Якщо щось не працює, надішліть нові логи або помилки, і я допоможу!

чому при оновленні сторінки дашборду отримала це GET http://localhost:8000/check-connection 401 (Unauthorized)

Помилка GET http://localhost:8000/check-connection 401 (Unauthorized) при оновленні сторінки дашборду означає, що сервер повертає статус 401, тобто запит не авторизований. Це відбувається через те, що сервер не може перевірити токен JWT, який передається в заголовку Authorization. Давайте розберемо причини і знайдемо рішення.

Можливі причини:
Токен відсутній або не передається:
У Dashboard.js ви отримуєте токен із localStorage і передаєте його в запит до /check-connection. Якщо токен не зберігся або був видалений, сервер поверне 401.
Токен прострочений:
Ваш JWT токен має термін дії (ACCESS_TOKEN_EXPIRE_MINUTES = 30), і якщо він прострочений, сервер відхиляє запит.
Помилка в серверній логіці автентифікації:
Функція get_current_user у main.py може некоректно обробляти токен або не знаходити користувача в базі даних.
CORS або неправильні заголовки:
Якщо заголовок Authorization не доходить до сервера через проблеми з CORS, це також може викликати 401.
Аналіз коду:
Клієнт (Dashboard.js):
У вашому useEffect ви робите запит до /check-connection:

javascript
Wrap
Copy
useEffect(() => {
const checkConnection = async () => {
const token = localStorage.getItem("token");
if (!token) {
router.push("/login");
return;
}

        try {
            const res = await fetch("http://localhost:8000/check-connection", {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Не вдалося перевірити підключення");
            }

            const data = await res.json();
            setIsConnected(data.connected);
        } catch (err) {
            setError(err.message);
        }
    };

    checkConnection();

}, [router]);
Тут логіка виглядає правильно: якщо токен відсутній, користувача перенаправляє на /login. Якщо токен є, але сервер повертає 401, проблема на стороні сервера.

Сервер (main.py):
Ендпоінт /check-connection залежить від get_current_user:

python
Wrap
Copy
@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
print(f"Перевірка підключення для: {current_user.username}")
return {"connected": bool(current_user.telegram_phone)}
Функція get_current_user:

python
Wrap
Copy
async def get_current_user(
token: str = Depends(oauth2_scheme),
db: AsyncSession = Depends(get_db)
):
try:
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
username = payload.get("sub")
if not username:
raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Помилка токена")

Сервер повертає 401 у таких випадках:

Токен невалідний (JWTError).
У токені немає поля sub (username).
Користувача з таким username немає в базі.
Діагностика та виправлення:

1. Перевірка токена на клієнті
   Додайте логування токена перед запитом, щоб переконатися, що він передається:

javascript
Wrap
Copy
useEffect(() => {
const checkConnection = async () => {
const token = localStorage.getItem("token");
console.log("Токен із localStorage:", token); // Додаємо лог
if (!token) {
console.log("Токен відсутній, перенаправлення на /login");
router.push("/login");
return;
}

        try {
            const res = await fetch("http://localhost:8000/check-connection", {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (!res.ok) {
                const data = await res.json();
                console.log("Помилка від сервера:", data); // Лог помилки
                throw new Error(data.detail || "Не вдалося перевірити підключення");
            }

            const data = await res.json();
            setIsConnected(data.connected);
        } catch (err) {
            setError(err.message);
        }
    };

    checkConnection();

}, [router]);
Якщо в консолі Токен із localStorage: null або порожній рядок, проблема в тому, що токен не зберігається після логіну. Перевірте Login.js, чи коректно зберігається токен у localStorage. 2. Перевірка логіну
У Login.js токен має зберігатися після успішного входу:

javascript
Wrap
Copy
const handleLogin = async (e) => {
e.preventDefault();
try {
const res = await fetch("http://localhost:8000/login", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ username, password }),
});

        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Login failed");

        console.log("Отримано токен:", data.access_token); // Лог для дебагу
        localStorage.setItem("token", data.access_token);
        router.push("/dashboard");
    } catch (err) {
        setError(err.message);
    }

};
Якщо токен не зберігається, додайте перевірку:
javascript
Wrap
Copy
localStorage.setItem("token", data.access_token);
console.log("Токен збережено:", localStorage.getItem("token")); 3. Перевірка терміну дії токена
Якщо токен є, але прострочений, сервер поверне 401 із деталями "Помилка токена". Збільште термін дії для тестування або додайте оновлення токена:

python
Wrap
Copy
ACCESS_TOKEN_EXPIRE_MINUTES = 60 # Збільшено до 60 хвилин для тестування 4. Перевірка серверної логіки
Додайте більше логів у get_current_user:

python
Wrap
Copy
async def get_current_user(
token: str = Depends(oauth2_scheme),
db: AsyncSession = Depends(get_db)
):
print(f"Перевірка токена: {token}")
try:
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
username = payload.get("sub")
print(f"Декодовано username: {username}")
if not username:
raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            print(f"Користувача {username} не знайдено в базі")
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        print(f"Користувач знайдений: {user.username}")
        return user
    except JWTError as e:
        print(f"Помилка JWT: {str(e)}")
        raise HTTPException(status_code=401, detail="Помилка токена")

Запустіть сервер і перевірте логи після оновлення сторінки. Наприклад:

Якщо Перевірка токена: <порожньо> — токен не передається.
Якщо Помилка JWT: Signature has expired — токен прострочений. 5. CORS і заголовки
Переконайтеся, що заголовок Authorization доходить до сервера. Ваш CORS Middleware виглядає коректно, але додайте логування в middleware:

python
Wrap
Copy
@app.middleware("http")
async def log_requests(request: Request, call_next):
print(f"Отримано запит: {request.method} {request.url}")
print(f"Заголовки: {request.headers}")
response = await call_next(request)
print(f"Відповідь: {response.status_code}")
return response
Якщо в логах немає Authorization, проблема на клієнті.

Рішення:
Якщо токен відсутній:
Перевірте Login.js і переконайтеся, що localStorage.setItem("token", data.access_token) виконується.
Додайте очищення localStorage при виході з системи, якщо це потрібно.
Якщо токен прострочений:
Збільште ACCESS_TOKEN_EXPIRE_MINUTES для тестування.
Додайте логіку оновлення токена (наприклад, ендпоінт /refresh-token).
Якщо сервер не знаходить користувача:
Перевірте базу даних: чи є користувач із username, який повертає токен?
Загальний фікс:
Оновіть Dashboard.js, щоб перенаправляти на /login при 401:
javascript
Wrap
Copy
useEffect(() => {
const checkConnection = async () => {
const token = localStorage.getItem("token");
console.log("Токен із localStorage:", token);
if (!token) {
router.push("/login");
return;
}

        try {
            const res = await fetch("http://localhost:8000/check-connection", {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (res.status === 401) {
                console.log("Токен невалідний, перенаправлення на /login");
                localStorage.removeItem("token");
                router.push("/login");
                return;
            }

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Не вдалося перевірити підключення");
            }

            const data = await res.json();
            setIsConnected(data.connected);
        } catch (err) {
            setError(err.message);
        }
    };

    checkConnection();

}, [router]);
Тестування:
Увійдіть у систему через /login.
Оновіть сторінку /dashboard.
Перевірте консоль браузера і логи сервера.
Надішліть мені результати логів, якщо проблема залишиться!

слухай, ну респект тобі! Токен після повторного логування був, чати отримались, тільки трошки дивно. спочатку вишло повідомлення : внутрішня помилка - database is locked, але потім чати завантажилися.

Дякую за фідбек! Радий, що токен запрацював і чати завантажились. Помилка "database is locked" — це вже цікаво, давай розберемо її і зробимо так, щоб усе працювало гладко без таких сюрпризів.

Що означає помилка "database is locked"?
Ця помилка зазвичай виникає, коли ви використовуєте SQLite як базу даних (а я припускаю, що у вашому database.py саме SQLite через AsyncSessionLocal і engine). SQLite блокує базу даних, якщо одночасно кілька операцій намагаються записувати або читати з неї, а асинхронний доступ (через sqlalchemy.ext.asyncio) іноді може створювати конфлікти, якщо конфігурація не оптимальна.

У вашому випадку помилка з’явилась, але потім чати завантажились, що може означати:

Тимчасовий конфлікт транзакцій у базі (наприклад, під час оновлення telegram_phone у /connect-telegram і одночасного читання в /chats).
SQLite автоматично розблокувався після короткої затримки, і запит завершився успішно.
Чому це проблема?
У продакшені (якщо ви плануєте масштабувати) SQLite може стати пляшковим горлом через обмеження на одночасний доступ.
Навіть у розробці такі помилки можуть дратувати і призводити до нестабільної поведінки.
Аналіз вашого коду
У main.py ви використовуєте AsyncSessionLocal для роботи з базою. Давайте подивимось, де це може викликати конфлікт:

/connect-telegram:
python
Wrap
Copy
current_user.telegram_phone = session_data["phone"]
await db.commit()
Тут відбувається запис у базу.
/chats:
python
Wrap
Copy
if not current_user.telegram_phone:
raise HTTPException(status_code=400, detail="Telegram не підключено")
Тут читається telegram_phone через залежність get_current_user.
get_current_user:
python
Wrap
Copy
result = await db.execute(select(User).filter(User.username == username))
user = result.scalar_one_or_none()
Ще один запит до бази.
Якщо ці запити перетинаються (наприклад, через швидке оновлення сторінки після підключення), SQLite може "залочитись".

Виправлення

1. Оптимізація асинхронного доступу до SQLite
   SQLite погано працює з асинхронністю за замовчуванням. Щоб уникнути блокувань:

Переконайтеся, що у вашому database.py правильно налаштований пул з’єднань.
Додайте параметр timeout для SQLite.
Приклад оновленого database.py (якщо у вас його немає, створіть):

python
Wrap
Copy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite+aiosqlite:///your_database.db" # Замініть на ваш шлях до бази

# Налаштування асинхронного двигуна з тайм-аутом

engine = create_async_engine(
DATABASE_URL,
connect_args={"timeout": 15}, # Збільшуємо тайм-аут до 15 секунд
echo=True # Увімкніть для дебагу, вимкніть у продакшені
)

# Створення фабрики сесій

AsyncSessionLocal = sessionmaker(
engine,
class\_=AsyncSession,
expire_on_commit=False
)

# Функція для отримання сесії (використовується в Depends)

async def get_db():
async with AsyncSessionLocal() as session:
yield session
Переконайтеся, що ваш main.py імпортує саме ці engine і AsyncSessionLocal. 2. Уникнення конфліктів транзакцій
У /connect-telegram додайте затримку перед комітом, щоб дати базі "відпочити":

python
Wrap
Copy
@app.post("/connect-telegram")
async def connect_telegram(
auth: TelegramConnect,
current_user: User = Depends(get_current_user),
db: AsyncSession = Depends(get_db)
):
print(f"Спроба підключення Telegram для користувача {current_user.id}")
try:
session_data = temp_sessions.get(current_user.id)
if not session_data or "client" not in session_data:
raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await asyncio.sleep(0.1)  # Невелика затримка перед комітом
        await db.commit()
        del temp_sessions[current_user.id]

        print(f"Telegram успішно підключено для {current_user.id}")
        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка в /connect-telegram: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

3. Клієнтська затримка перед викликом /chats
   Оскільки чати завантажились після повторного запиту, додайте затримку в Dashboard.js перед fetchChats, щоб дати серверу завершити транзакцію:

javascript
Wrap
Copy
const connectTelegram = async (e) => {
e.preventDefault();
setError("");

    try {
        const token = localStorage.getItem("token");
        if (!token) return router.push("/login");

        const body = { code: code.trim() };
        if (twoFactorPassword) body.password = twoFactorPassword;

        const res = await fetch("http://localhost:8000/connect-telegram", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify(body),
        });

        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.detail || "Помилка підключення");
        }

        setIsConnected(true);
        await new Promise(resolve => setTimeout(resolve, 1000)); // Затримка 1 секунда
        await fetchChats();
    } catch (err) {
        setError(err.message);
    }

}; 4. Перехід на іншу базу (опціонально)
Якщо ви плануєте розвивати проєкт, подумайте про перехід на PostgreSQL або MySQL, які краще працюють із асинхронністю та кількома підключеннями. SQLite підходить для простих проєктів, але не для високонавантажених сценаріїв.

Перевірка
Перезапустіть сервер після оновлення database.py і main.py.
Увійдіть, підключіть Telegram і оновіть сторінку.
Перевірте логи сервера:
Якщо знову з’явиться "database is locked", подивіться, які запити виконувались одночасно (логування echo=True у engine допоможе).
Чому чати все ж завантажились?
SQLite має механізм повторних спроб: якщо база заблокована, запит може "почекати" і виконатись після розблокування. Ваша помилка була тимчасовою, тому чати зрештою підтягнулись. Але ми хочемо уникнути цього повідомлення.

Якщо після цих змін помилка залишиться, надішліть мені:

Логи сервера (особливо з echo=True).
Повний текст помилки.
Думаю, тепер усе запрацює стабільно!

на хвилинку відійдемо від теми. я зробила коміт на клієнті, зробила коміт на сервері, як тепер відправити все це якщо в мене воно все в одному репозиторії на гітхабі ? і як зробити, щоб інші користувачи могли все це запустити?

Добре, давай розберемо, як відправити твої зміни на GitHub і як зробити так, щоб інші могли запустити твій проєкт. Оскільки у тебе клієнт і сервер в одному репозиторії, це спрощує деякі речі, але потребує чіткої структури та інструкцій.

1. Відправка змін на GitHub
   Припускаю, що у тебе вже є репозиторій на GitHub, і ти зробила коміти локально для клієнта (наприклад, у папці client) і сервера (наприклад, у папці server). Ось кроки, щоб відправити все це на GitHub:

Крок 1: Перевір статус
У корені твого проєкту (де лежить .git) виконай:

bash
Wrap
Copy
git status
Ти побачиш усі змінені файли (наприклад, client/pages/dashboard.js, server/main.py тощо). Переконайся, що всі потрібні файли додані до комітів.

Крок 2: Додай файли до індексу (якщо ще не додала)
Якщо ти вже зробила коміти, цей крок можна пропустити. Якщо є незакомічені зміни:

bash
Wrap
Copy
git add client/ server/
Або додай конкретні файли:

bash
Wrap
Copy
git add client/pages/dashboard.js server/main.py
Крок 3: Створи коміт (якщо ще не зробила)
Якщо ти ще не закомітила зміни:

bash
Wrap
Copy
git commit -m "Оновлено клієнт і сервер: виправлено авторизацію та підключення Telegram"
Крок 4: Перевір гілку
Переконайся, що ти працюєш у правильній гілці (зазвичай це main або master):

bash
Wrap
Copy
git branch
Якщо ти не в потрібній гілці, переключись:

bash
Wrap
Copy
git checkout main
Крок 5: Відправ зміни на GitHub
Відправляй коміти у віддалений репозиторій:

bash
Wrap
Copy
git push origin main
Заміни main на назву твоєї гілки, якщо вона інша (наприклад, master).

Крок 6: Перевір на GitHub
Зайди на свій репозиторій на GitHub і переконайся, що всі файли оновились.

2. Як зробити, щоб інші могли запустити проєкт?
   Щоб інші користувачі могли клонувати твій репозиторій і запустити проєкт, тобі потрібно:

Організувати структуру проєкту.
Додати залежності.
Написати інструкцію в README.md.
Структура репозиторію
Припускаю, що твій репозиторій виглядає так:

text
Wrap
Copy
your-repo/
├── client/ # Next.js клієнт
│ ├── pages/
│ ├── package.json
│ └── ...
├── server/ # FastAPI сервер
│ ├── main.py
│ ├── database.py
│ ├── models.py
│ ├── requirements.txt
│ └── ...
├── .git/
├── .gitignore
└── README.md
Якщо це не так, напиши, як у тебе організовано папки, і я адаптую інструкцію.

Крок 1: Додай залежності
Для клієнта (client/package.json): Переконайся, що у package.json є всі залежності. Якщо ти додавала щось вручну, онови файл:
bash
Wrap
Copy
cd client
npm install # Встанови всі залежності
Потім додай package.json і package-lock.json до коміту.
Для сервера (server/requirements.txt): Створи файл server/requirements.txt із залежностями:
bash
Wrap
Copy
cd server
pip freeze > requirements.txt
Переконайся, що там є:
text
Wrap
Copy
fastapi
uvicorn
sqlalchemy
aiosqlite
telethon
python-jose[cryptography]
passlib[bcrypt]
python-dotenv
Додай requirements.txt до коміту.
Крок 2: Налаштування оточення
Твій проєкт використовує .env для секретів (API_ID, API_HASH, JWT_SECRET). Не додавай .env до GitHub (додай його в .gitignore), але створи шаблон:

У корені або в server/ створи server/.env.example:
text
Wrap
Copy
API_ID=your_telegram_api_id
API_HASH=your_telegram_api_hash
JWT_SECRET=your_secret_key_here
У .gitignore додай:
text
Wrap
Copy
server/.env
\*.db # Щоб не завантажувати SQLite-файли
Крок 3: Напиши інструкцію в README.md
У корені репозиторію створи або онови README.md:

markdown
Wrap
Copy

# SocialHub

Проєкт із клієнтом на Next.js і сервером на FastAPI для підключення до Telegram і перегляду чатів.

## Структура

-   `client/` - фронтенд на Next.js
-   `server/` - бекенд на FastAPI

## Вимоги

-   Node.js (v16 або новіше)
-   Python 3.9+
-   Git

## Налаштування та запуск

### 1. Клонуйте репозиторій

````bash
git clone https://github.com/your-username/your-repo.git
cd your-repo
2. Налаштуйте сервер
Перейдіть до папки сервера:
bash
Wrap
Copy
cd server
Створіть віртуальне оточення та активуйте його:
bash
Wrap
Copy
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
Встановіть залежності:
bash
Wrap
Copy
pip install -r requirements.txt
Скопіюйте server/.env.example у server/.env і заповніть своїми значеннями:
API_ID і API_HASH отримайте з https://my.telegram.org
JWT_SECRET - будь-який секретний ключ (наприклад, "mysecretkey123").
3. Налаштуйте клієнт
Перейдіть до папки клієнта:
bash
Wrap
Copy
cd ../client
Встановіть залежності:
bash
Wrap
Copy
npm install
4. Запустіть проєкт
Запустіть сервер (із папки server):
bash
Wrap
Copy
uvicorn main:app --reload
У іншому терміналі запустіть клієнт (із папки client):
bash
Wrap
Copy
npm run dev
5. Використання
Відкрийте браузер на http://localhost:3000.
Зареєструйтесь, увійдіть і підключіть Telegram.
Нотатки
SQLite використовується як база даних. Для продакшену рекомендується перейти на PostgreSQL.
Переконайтеся, що порт 8000 (сервер) і 3000 (клієнт) вільні.
text
Wrap
Copy

#### Крок 4: Закоміть і відправ
Додай нові файли:
```bash
git add client/package.json server/requirements.txt server/.env.example README.md
git commit -m "Додано залежності та інструкцію для запуску"
git push origin main
Перевірка
Клонуй репозиторій у нову папку:
bash
Wrap
Copy
git clone https://github.com/your-username/your-repo.git test-clone
Дотримуйся інструкцій із README.md і перевір, чи все запускається.
Додаткові поради
Якщо хочеш автоматизувати запуск, додай docker-compose.yml для запуску клієнта і сервера одним файлом.
Переконайся, що твій .gitignore виключає чутливі дані (.env, node_modules, venv).
Напиши, якщо потрібна допомога з чимось конкретним!






щось сервер не працює. як його запустити ото без прив'язки до шляху


Якщо сервер не запускається, коли ти намагаєшся запустити його командою uvicorn main:app --reload, і ти хочеш уникнути прив’язки до конкретного шляху (тобто запускати його незалежно від того, де ти знаходишся в файловій системі), давай розберемо можливі причини і як це зробити.

Чому сервер може не працювати?
Помилка в коді:
У main.py може бути синтаксична помилка або проблема з імпортами.
Відсутність залежностей:
Можливо, не всі пакети з requirements.txt встановлені.
Неправильний шлях до файлу:
Якщо ти запускаєш uvicorn не з папки server/, він не знайде main.py.
Проблема з оточенням:
.env файл відсутній або має некоректні значення.
Як запустити сервер без прив’язки до шляху?
Щоб запустити сервер із будь-якої директорії, не вказуючи відносний шлях до main.py, можна:

Використати абсолютний шлях до файлу.
Додати папку server/ до системного PYTHONPATH.
Використати модульний запис у uvicorn.
Спосіб 1: Абсолютний шлях
Перейди до папки server/ і дізнайся повний шлях:
На Linux/Mac:
bash
Wrap
Copy
pwd
Наприклад: /home/user/projects/your-repo/server
На Windows (у CMD):
bash
Wrap
Copy
cd
Наприклад: G:\Projects\your-repo\server
Запусти сервер із повним шляхом:
bash
Wrap
Copy
uvicorn /home/user/projects/your-repo/server/main:app --reload
Або для Windows:
bash
Wrap
Copy
uvicorn G:\Projects\your-repo\server\main:app --reload
Спосіб 2: Додавання до PYTHONPATH
Додай шлях до server/ у змінну оточення PYTHONPATH:
На Linux/Mac (тимчасово):
bash
Wrap
Copy
export PYTHONPATH=$PYTHONPATH:/home/user/projects/your-repo/server
На Windows (тимчасово у CMD):
bash
Wrap
Copy
set PYTHONPATH=%PYTHONPATH%;G:\Projects\your-repo\server
Запусти з будь-якої директорії:
bash
Wrap
Copy
uvicorn main:app --reload
Спосіб 3: Модульний запис (рекомендується)
Якщо твій проєкт має чітку структуру (наприклад, your-repo/server/main.py), ти можеш запускати сервер через модульний імпорт:

Переконайся, що ти в корені репозиторію (your-repo/):
bash
Wrap
Copy
cd /home/user/projects/your-repo
Або:
bash
Wrap
Copy
cd G:\Projects\your-repo
Запусти сервер, вказавши модуль:
bash
Wrap
Copy
uvicorn server.main:app --reload
Тут server.main — це модуль main.py у папці server/, а app — об’єкт FastAPI.
Діагностика: Чому сервер не працює?
Давай перевіримо, що саме не так.

Крок 1: Перевір запуск
Спробуй запустити сервер із папки server/:

bash
Wrap
Copy
cd server
uvicorn main:app --reload
Якщо видає помилку, надішли її мені. Наприклад:

ModuleNotFoundError — бракує модуля.
AttributeError: module 'main' has no attribute 'app' — проблема в коді.
Крок 2: Перевір залежності
Переконайся, що всі залежності встановлені:

bash
Wrap
Copy
cd server
pip install -r requirements.txt
Якщо requirements.txt немає, встанови вручну:

bash
Wrap
Copy
pip install fastapi uvicorn sqlalchemy aiosqlite telethon python-jose[cryptography] passlib[bcrypt] python-dotenv
Крок 3: Перевір .env
У папці server/ має бути файл .env із такими змінними:

text
Wrap
Copy
API_ID=your_telegram_api_id
API_HASH=your_telegram_api_hash
JWT_SECRET=your_secret_key_here
Якщо його немає, створи за прикладом із server/.env.example.

Крок 4: Перевір код
Переконайся, що main.py запускається без синтаксичних помилок:

bash
Wrap
Copy
python server/main.py
Якщо є помилки, вони з’являться в терміналі.

Рекомендований запуск
Найзручніше — запускати через модульний запис із кореня репозиторію:

Перейди до your-repo/:
bash
Wrap
Copy
cd /home/user/projects/your-repo
Активуй віртуальне оточення (якщо використовуєш):
Linux/Mac:
bash
Wrap
Copy
source server/venv/bin/activate
Windows:
bash
Wrap
Copy
server\venv\Scripts\activate
Запусти:
bash
Wrap
Copy
uvicorn server.main:app --reload
Сервер має запуститись на http://localhost:8000. Перевір у браузері або через curl:

bash
Wrap
Copy
curl http://localhost:8000/health
Якщо не працює
Надішли мені:

Точну команду, яку ти використовуєш.
Повний текст помилки з терміналу.
Чи є у тебе віртуальне оточення і чи активоване воно.
Тоді я зможу точно сказати, що не так і як це виправити!






DATABASE_URL = "sqlite+aiosqlite:///your_database.db"  # Замініть на ваш шлях до бази - де його взяти? я нічого такого не писала


Ти абсолютно права, що звернула на це увагу! Якщо ти раніше не налаштовувала базу даних вручну і не вказувала DATABASE_URL, це означає, що твій проєкт або ще не має чітко визначеної бази, або ти використовувала базу за замовчуванням, яка створюється автоматично. Давай розберемо, що таке DATABASE_URL, звідки його взяти і як налаштувати для твого випадку.

Що таке DATABASE_URL?
DATABASE_URL — це рядок підключення до бази даних, який говорить SQLAlchemy, де шукати базу і як із нею працювати. У твоєму випадку ми використовуємо SQLite (легку локальну базу даних), а aiosqlite — це асинхронна версія драйвера для SQLite, яка підходить для FastAPI.

Приклад:

python
Wrap
Copy
DATABASE_URL = "sqlite+aiosqlite:///your_database.db"
sqlite+aiosqlite — драйвер для SQLite з підтримкою асинхронності.
///your_database.db — шлях до файлу бази даних. Три слеші (///) означають відносний шлях від місця, де запускається код.
Де його взяти?
Оскільки ти раніше не писала такого, це означає, що:

Ти ще не налаштовувала базу явно, і код у main.py може не працювати коректно без правильного database.py.
Твій проєкт, можливо, падає через те, що AsyncSessionLocal і engine не ініціалізовані.
Тобі потрібно:

Визначити, де зберігати базу даних (наприклад, у папці server/).
Створити модуль database.py із правильним DATABASE_URL.
Як це виправити?
Крок 1: Визнач місце для бази
SQLite зберігає дані у файлі (наприклад, database.db). Ти можеш розмістити його в папці server/, щоб усе було організовано. Тоді шлях буде відносним до server/:

text
Wrap
Copy
your-repo/
├── client/
├── server/
│   ├── main.py
│   ├── database.py
│   ├── database.db  # Файл бази даних з’явиться тут
│   └── ...
└── ...
Крок 2: Створи database.py
У папці server/ створи файл database.py із таким вмістом:

python
Wrap
Copy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Вказуємо відносний шлях до бази в папці server/
DATABASE_URL = "sqlite+aiosqlite:///database.db"

# Створюємо асинхронний двигун
engine = create_async_engine(
    DATABASE_URL,
    connect_args={"timeout": 15},  # Тайм-аут для уникнення "database is locked"
    echo=True  # Логи SQL-запитів для дебагу
)

# Фабрика сесій
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Функція для FastAPI Depends
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
DATABASE_URL = "sqlite+aiosqlite:///database.db" означає, що файл бази database.db буде створений у тій же папці, де лежить database.py (тобто в server/).
Якщо ти хочеш зберігати базу в іншому місці (наприклад, у корені проєкту), вкажи абсолютний шлях:
python
Wrap
Copy
DATABASE_URL = "sqlite+aiosqlite:////home/user/projects/your-repo/database.db"  # Linux/Mac
DATABASE_URL = "sqlite+aiosqlite:///G:/Projects/your-repo/database.db"        # Windows
Крок 3: Перевір імпорти в main.py
Переконайся, що main.py імпортує engine і AsyncSessionLocal із database.py:

python
Wrap
Copy
from database import AsyncSessionLocal, engine
Твій main.py уже має це в коді, який я тобі дав, тож просто перевір, чи шлях правильний.

Крок 4: Запусти сервер
Перейди до папки server/:
bash
Wrap
Copy
cd server
Активуй віртуальне оточення (якщо є):
bash
Wrap
Copy
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
Запусти:
bash
Wrap
Copy
uvicorn main:app --reload
При першому запуску SQLite автоматично створить файл database.db у папці server/, коли код викличе Base.metadata.create_all (це є в main.py у @app.on_event("startup")).

Перевірка
Після запуску перевір, чи з’явився файл server/database.db.
Якщо сервер запустився і видає http://localhost:8000, спробуй:
bash
Wrap
Copy
curl http://localhost:8000/health
Має повернути {"status": "OK"}.
Якщо щось не працює
Якщо сервер не запускається:

Надішли текст помилки з терміналу.
Перевір, чи встановлений aiosqlite:
bash
Wrap
Copy
pip install aiosqlite
Переконайся, що main.py не має інших помилок (наприклад, відсутність .env).
Що ти отримала раніше?
Ти казала, що чати завантажились, але була помилка "database is locked". Це могло статися, якщо ти використовувала інший DATABASE_URL (можливо, за замовчуванням), і база вже була створена. Тепер із явним database.py ми контролюємо, де вона лежить.

Дай знати, чи запрацювало, або скинь помилку, якщо щось пішло не так!






$ source venv/bin/activate
bash: venv/bin/activate: No such file or directory


Помилка bash: venv/bin/activate: No such file or directory означає, що в папці venv/ немає скрипту активації віртуального оточення, або ти намагаєшся активувати його неправильно чи з неправильного місця. Давай розберемо, чому це сталося і як виправити.

Чому це відбувається?
Віртуальне оточення не створене:
Ти ще не створила віртуальне оточення у папці server/venv/.
Неправильний шлях:
Ти виконуєш команду не з папки server/, або шлях до venv/ інший.
Оточення створене для іншої ОС:
Якщо ти на Windows, а використовуєш команду для Linux/Mac (source venv/bin/activate), це не спрацює.
Виправлення
Крок 1: Перевір, де ти знаходишся
Виконай:

bash
Wrap
Copy
/home/user/projects/your-repo/server$ pwd
(або на Windows: cd)

Якщо ти не в папці server/, перейди туди:

bash
Wrap
Copy
cd /home/user/projects/your-repo/server
Заміни шлях на свій.

Крок 2: Перевір наявність venv/
Виконай:

bash
Wrap
Copy
ls dir  # Linux/Mac
Або:

bash
Wrap
Copy
dir     # Windows
Чи є папка venv? Якщо ні, це означає, що ти ще не створила віртуальне оточення.

Крок 3: Створи віртуальне оточення
Якщо venv/ немає, створи його:

У папці server/ виконай:
bash
Wrap
Copy
python -m venv venv
Це створить папку venv/ із віртуальним оточенням.
На Windows може знадобитись python3 замість python, якщо python не розпізнається.
Перевір, чи з’явилась папка:
bash
Wrap
Copy
ls dir  # Linux/Mac
dir     # Windows
Має бути папка venv.
Крок 4: Активуй віртуальне оточення
Залежно від твоєї операційної системи:

Linux/Mac:
bash
Wrap
Copy
source venv/bin/activate
Після цього в терміналі з’явиться (venv) перед командним рядком.
Windows (CMD):
bash
Wrap
Copy
venv\Scripts\activate
Windows (PowerShell):
bash
Wrap
Copy
.\venv\Scripts\Activate.ps1
Windows (Git Bash):
bash
Wrap
Copy
source venv/Scripts/activate
Якщо ти на Windows і використовувала source venv/bin/activate, це не спрацює, бо bin/ — це для Unix-систем. Спробуй правильну команду для своєї ОС.

Крок 5: Встанови залежності
Після активації встанови пакети:

bash
Wrap
Copy
pip install -r requirements.txt
Якщо requirements.txt немає, встанови вручну:

bash
Wrap
Copy
pip install fastapi uvicorn sqlalchemy aiosqlite telethon python-jose[cryptography] passlib[bcrypt] python-dotenv
Крок 6: Запусти сервер
bash
Wrap
Copy
uvicorn main:app --reload
Перевірка
Якщо (venv) з’явилось у терміналі, оточення активоване.
Якщо сервер запустився на http://localhost:8000, усе працює.
Якщо все ще не працює
Надішли мені:

Яку ОС ти використовуєш (Windows, Linux, Mac)?
Вміст команди ls dir або dir після спроби створити venv.
Точну помилку, якщо вона з’являється після активації чи запуску.
Тоді я точно зрозумію, що не так!






капец.. тепер і код не отримується.. можеш проаналізувати мої файли виправити і повернути повністю, щоб я швидко скопіювала?  import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError, SessionExpiredError
from pydantic import BaseModel
from database import AsyncSessionLocal, engine  # Припускаю, що ці модулі у вас є
from models import Base, User  # Припускаю, що ці модулі у вас є
from dotenv import load_dotenv
from pydantic import ConfigDict
from telethon import types
import asyncio

# Завантаження змінних оточення
load_dotenv()

# Ініціалізація додатку
app = FastAPI()

# Налаштування CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Конфігурація JWT
SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Конфігурація Telegram
API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

# Хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Схема автентифікації
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Тимчасове сховище для сесій
temp_sessions = {}

# Моделі запитів
class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TelegramSendCode(BaseModel):
    phone: str

class TelegramConnect(BaseModel):
    code: str
    password: Optional[str] = None
    phone: Optional[str] = None

class TelegramSession(BaseModel):
    phone: str
    phone_code_hash: str
    client: Optional[types.User] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

# Залежності
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# Логування middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"Отримано запит: {request.method} {request.url}")
    response = await call_next(request)
    print(f"Відповідь: {response.status_code}")
    return response

# Обробка винятків для CORS
@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

# Обробка OPTIONS-запитів
@app.options("/{path:path}")
async def options_handler():
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

# Створення таблиць при старті
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# Генерація JWT токена
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Отримання поточного користувача
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    print(f"Перевірка токена: {token}")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        print(f"Декодовано username: {username}")
        if not username:
            raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            print(f"Користувача {username} не знайдено в базі")
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        print(f"Користувач знайдений: {user.username}")
        return user
    except JWTError as e:
        print(f"Помилка JWT: {str(e)}")
        raise HTTPException(status_code=401, detail="Помилка токена")

# Реєстрація
@app.post("/register", status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    if result.scalar():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    await db.commit()
    return {"message": "User created successfully"}

# Логін
@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    db_user = result.scalar()

    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

# Перевірка підключення
@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
    print(f"Перевірка підключення для: {current_user.username}")
    return {"connected": bool(current_user.telegram_phone)}

# Надсилання коду для Telegram
@app.post("/send-code")
async def send_code(
    data: TelegramSendCode,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    try:
        if current_user.id in temp_sessions:
            await temp_sessions[current_user.id]["client"].disconnect()
            del temp_sessions[current_user.id]

        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()
        sent_code = await client.send_code_request(data.phone)

        temp_sessions[current_user.id] = {
            "phone": data.phone,
            "phone_code_hash": sent_code.phone_code_hash,
            "client": client
        }
        return {"detail": "Код відправлено"}
    except FloodWaitError as e:
        raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
    except Exception as e:
        print(f"Помилка в /send-code: {str(e)}")
        raise HTTPException(400, detail=str(e))

# Підключення Telegram
@app.post("/connect-telegram")
async def connect_telegram(
    auth: TelegramConnect,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Спроба підключення Telegram для користувача {current_user.id}")
    try:
        session_data = temp_sessions.get(current_user.id)
        if not session_data or "client" not in session_data:
            raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        # Зберігаємо сесію
        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await db.commit()
        del temp_sessions[current_user.id]

        print(f"Telegram успішно підключено для {current_user.id}")
        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка в /connect-telegram: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

# Отримання чатів
@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        print(f"Чати отримано для {current_user.id}")
        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

# Отримання повідомлень чату
@app.get("/chats/{chat_id}/messages")
async def get_chat_messages(
    chat_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Сесія не авторизована")

        messages = await client.get_messages(chat_id, limit=20)
        await client.disconnect()

        return [{"id": m.id, "text": m.text, "date": m.date.isoformat()} for m in messages]
    except Exception as e:
        print(f"Помилка в /chats/{chat_id}/messages: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Вихід з Telegram
@app.post("/logout-telegram")
async def logout_telegram(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.telegram_phone and os.path.exists(f"sessions/session_{current_user.id}"):
        os.remove(f"sessions/session_{current_user.id}")
    current_user.telegram_phone = None
    await db.commit()
    print(f"Telegram відключено для {current_user.id}")
    return {"message": "Telegram disconnected"}

# Вихід з системи
@app.post("/logout")
async def logout_system(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out from system"}

# Перевірка здоров'я
@app.get("/health")
async def health_check():
    return {"status": "OK"}   from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///./socialhub.db"

# Створення асинхронного двигуна
engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=True  # Логування SQL-запитів (опційно)
)

AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Dashboard() {
    const [phone, setPhone] = useState("");
    const [code, setCode] = useState("");
    const [chats, setChats] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [isCodeSent, setIsCodeSent] = useState(false);
    const [error, setError] = useState("");
    const router = useRouter();
    const [twoFactorPassword, setTwoFactorPassword] = useState("");
    // Перевірка статусу підключення Telegram
    useEffect(() => {
        const checkConnection = async () => {
            const token = localStorage.getItem("token");
            console.log("Токен із localStorage:", token); // Додаємо лог
            if (!token) {
                console.log("Токен відсутній, перенаправлення на /login");
                router.push("/login");
                return;
            }

            try {
                const res = await fetch(
                    "http://localhost:8000/check-connection",
                    {
                        headers: { Authorization: `Bearer ${token}` },
                    }
                );

                if (!res.ok) {
                    const data = await res.json();
                    console.log("Помилка від сервера:", data); // Лог помилки
                    throw new Error(
                        data.detail || "Не вдалося перевірити підключення"
                    );
                }

                const data = await res.json();
                setIsConnected(data.connected);
            } catch (err) {
                setError(err.message);
            }
        };

        checkConnection();
    }, [router]);

    // Надсилання коду на телефон
    const sendCode = async (e) => {
        e.preventDefault();
        setError("");

        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/send-code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ phone }),
            });

            const data = await res.json();
            if (!res.ok)
                throw new Error(data.detail || "Помилка відправки коду");

            setIsCodeSent(true);
        } catch (err) {
            setError(err.message);
        }
    };

    // Підключення Telegram
    const connectTelegram = async (e) => {
        e.preventDefault();
        setError("");

        try {
            const token = localStorage.getItem("token");
            if (!token) return router.push("/login");

            const body = { code: code.trim() };
            if (twoFactorPassword) body.password = twoFactorPassword;

            const res = await fetch("http://localhost:8000/connect-telegram", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(body),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Помилка підключення");
            }

            setIsConnected(true);
            await new Promise((resolve) => setTimeout(resolve, 500)); // Додаємо затримку
            await fetchChats();
        } catch (err) {
            setError(err.message);
        }
    };

    // Отримання чатів
    const fetchChats = async () => {
        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/chats", {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Не вдалося завантажити чати");
            }

            const data = await res.json();
            setChats(data);
        } catch (err) {
            setError(err.message);
        }
    };

    // Показуємо чати тільки якщо Telegram підключено
    useEffect(() => {
        if (isConnected) {
            fetchChats();
        }
    }, [isConnected]);

    const handleLogoutTelegram = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://localhost:8000/logout-telegram", {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error("Не вдалося вийти з Telegram");
            setIsConnected(false);
            setIsCodeSent(false); // Скидаємо стан, щоб повернутися до введення телефону
            setPhone(""); // Очищаємо номер телефону
            setCode(""); // Очищаємо код
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6">Панель управління</h1>

            {error && <p className="text-red-500 mb-4">{error}</p>}

            {!isConnected ? (
                // Форма підключення Telegram
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4">Підключіть Telegram</h2>

                    {!isCodeSent ? (
                        // Крок 1: Введення номера телефону
                        <form onSubmit={sendCode} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть номер телефону"
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <input
                                type="password"
                                placeholder="Пароль 2FA (якщо потрібно)"
                                value={twoFactorPassword}
                                onChange={(e) =>
                                    setTwoFactorPassword(e.target.value)
                                }
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Отримати код
                            </button>
                        </form>
                    ) : (
                        // Крок 2: Введення коду з Telegram
                        <form onSubmit={connectTelegram} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть код з Telegram"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Підключити
                            </button>
                        </form>
                    )}
                </div>
            ) : (
                // Список чатів
                <div>
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-xl">Ваші чати</h2>
                        <button
                            onClick={handleLogoutTelegram}
                            className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600"
                        >
                            Змінити акаунт
                        </button>
                    </div>

                    <div className="space-y-4">
                        {chats.map((chat) => (
                            <div
                                key={chat.id}
                                className="p-4 border rounded hover:bg-gray-50"
                            >
                                <Link
                                    href={`/chats/${chat.id}`}
                                    className="text-blue-500 hover:underline"
                                >
                                    {chat.name}
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
 зараз воно на єтапі отримання коду блокує базу POST http://localhost:8000/send-code 400 (Bad Request)


Я проаналізував твої файли і проблему з блокуванням бази та помилкою POST http://localhost:8000/send-code 400 (Bad Request). Основна проблема полягає в тому, що код у main.py нестабільно обробляє асинхронні операції з базою даних, а також є потенційні конфлікти через SQLite. Я виправлю усі файли, додам затримки для уникнення блокувань і поверну тобі повні версії для швидкого копіювання.

Аналіз помилки
Помилка 400 у /send-code:
У логах сервера має бути деталізація (наприклад, "Спочатку отримайте код" або інша помилка від Telegram). Але ти згадала "блокує базу", що може означати конфлікт із SQLite через одночасний доступ.
Блокування бази:
SQLite погано працює з асинхронними транзакціями, якщо їх багато і вони не синхронізовані. У /send-code є операція з Telegram і доступ до бази через get_current_user.
Виправлені файли
1. server/main.py
Ось повністю виправлений main.py із затримками та стабільною роботою:

python
Wrap
Copy
import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError, SessionExpiredError
from pydantic import BaseModel
from database import AsyncSessionLocal, engine
from models import Base, User
from dotenv import load_dotenv
from pydantic import ConfigDict
from telethon import types
import asyncio

# Завантаження змінних оточення
load_dotenv()

# Ініціалізація додатку
app = FastAPI()

# Налаштування CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Конфігурація JWT
SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Збільшено для тестування

# Конфігурація Telegram
API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

# Хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Схема автентифікації
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Тимчасове сховище для сесій
temp_sessions = {}

# Моделі запитів
class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TelegramSendCode(BaseModel):
    phone: str

class TelegramConnect(BaseModel):
    code: str
    password: Optional[str] = None
    phone: Optional[str] = None

class TelegramSession(BaseModel):
    phone: str
    phone_code_hash: str
    client: Optional[types.User] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

# Залежності
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# Логування middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"Отримано запит: {request.method} {request.url}")
    print(f"Заголовки: {request.headers}")
    response = await call_next(request)
    print(f"Відповідь: {response.status_code}")
    return response

# Обробка винятків для CORS
@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

# Обробка OPTIONS-запитів
@app.options("/{path:path}")
async def options_handler():
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

# Створення таблиць при старті
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# Генерація JWT токена
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Отримання поточного користувача
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    print(f"Перевірка токена: {token}")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        print(f"Декодовано username: {username}")
        if not username:
            raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            print(f"Користувача {username} не знайдено в базі")
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        print(f"Користувач знайдений: {user.username}")
        return user
    except JWTError as e:
        print(f"Помилка JWT: {str(e)}")
        raise HTTPException(status_code=401, detail="Помилка токена")

# Реєстрація
@app.post("/register", status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    if result.scalar():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    await asyncio.sleep(0.1)  # Затримка для стабільності SQLite
    await db.commit()
    return {"message": "User created successfully"}

# Логін
@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    db_user = result.scalar()

    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

# Перевірка підключення
@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
    print(f"Перевірка підключення для: {current_user.username}")
    return {"connected": bool(current_user.telegram_phone)}

# Надсилання коду для Telegram
@app.post("/send-code")
async def send_code(
    data: TelegramSendCode,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Надсилання коду для користувача {current_user.id}")
    try:
        if current_user.id in temp_sessions:
            await temp_sessions[current_user.id]["client"].disconnect()
            del temp_sessions[current_user.id]

        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()
        sent_code = await client.send_code_request(data.phone)

        temp_sessions[current_user.id] = {
            "phone": data.phone,
            "phone_code_hash": sent_code.phone_code_hash,
            "client": client
        }
        await asyncio.sleep(0.1)  # Затримка для стабільності
        return {"detail": "Код відправлено"}
    except FloodWaitError as e:
        raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
    except Exception as e:
        print(f"Помилка в /send-code: {str(e)}")
        raise HTTPException(400, detail=str(e))

# Підключення Telegram
@app.post("/connect-telegram")
async def connect_telegram(
    auth: TelegramConnect,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Спроба підключення Telegram для користувача {current_user.id}")
    try:
        session_data = temp_sessions.get(current_user.id)
        if not session_data or "client" not in session_data:
            raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await asyncio.sleep(0.1)  # Затримка перед комітом
        await db.commit()
        del temp_sessions[current_user.id]

        print(f"Telegram успішно підключено для {current_user.id}")
        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка в /connect-telegram: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

# Отримання чатів
@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        print(f"Чати отримано для {current_user.id}")
        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

# Отримання повідомлень чату
@app.get("/chats/{chat_id}/messages")
async def get_chat_messages(
    chat_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Сесія не авторизована")

        messages = await client.get_messages(chat_id, limit=20)
        await client.disconnect()

        return [{"id": m.id, "text": m.text, "date": m.date.isoformat()} for m in messages]
    except Exception as e:
        print(f"Помилка в /chats/{chat_id}/messages: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Вихід з Telegram
@app.post("/logout-telegram")
async def logout_telegram(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.telegram_phone and os.path.exists(f"sessions/session_{current_user.id}"):
        os.remove(f"sessions/session_{current_user.id}")
    current_user.telegram_phone = None
    await asyncio.sleep(0.1)  # Затримка перед комітом
    await db.commit()
    print(f"Telegram відключено для {current_user.id}")
    return {"message": "Telegram disconnected"}

# Вихід з системи
@app.post("/logout")
async def logout_system(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out from system"}

# Перевірка здоров'я
@app.get("/health")
async def health_check():
    return {"status": "OK"}
Зміни:

Додано затримки (await asyncio.sleep(0.1)) перед комітами для уникнення блокувань SQLite.
Збільшено ACCESS_TOKEN_EXPIRE_MINUTES до 60 для зручності тестування.
Додано більше логів для дебагу.
2. server/database.py
Оновлений файл із правильним DATABASE_URL і тайм-аутом:

python
Wrap
Copy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Вказуємо базу в папці server/
DATABASE_URL = "sqlite+aiosqlite:///socialhub.db"

# Створюємо асинхронний двигун
engine = create_async_engine(
    DATABASE_URL,
    connect_args={"timeout": 15},  # Тайм-аут для уникнення "database is locked"
    echo=True  # Логи SQL-запитів
)

# Фабрика сесій
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Функція для FastAPI Depends
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
Зміни:

Видалено Base, бо він має бути в models.py.
Вказано socialhub.db як назву бази.
3. server/models.py
Цей файл потрібен для визначення моделі User. Якщо у тебе його ще немає, ось приклад:

python
Wrap
Copy
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    telegram_phone = Column(String, nullable=True)
4. client/pages/dashboard.js
Твій dashboard.js уже виглядає добре, але я додав обробку помилки 400 і стабільнішу затримку:

javascript
Wrap
Copy
import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Dashboard() {
    const [phone, setPhone] = useState("");
    const [code, setCode] = useState("");
    const [chats, setChats] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [isCodeSent, setIsCodeSent] = useState(false);
    const [error, setError] = useState("");
    const router = useRouter();
    const [twoFactorPassword, setTwoFactorPassword] = useState("");

    useEffect(() => {
        const checkConnection = async () => {
            const token = localStorage.getItem("token");
            console.log("Токен із localStorage:", token);
            if (!token) {
                console.log("Токен відсутній, перенаправлення на /login");
                router.push("/login");
                return;
            }

            try {
                const res = await fetch("http://localhost:8000/check-connection", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 401) {
                    console.log("Токен невалідний, перенаправлення на /login");
                    localStorage.removeItem("token");
                    router.push("/login");
                    return;
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося перевірити підключення");
                }

                const data = await res.json();
                setIsConnected(data.connected);
            } catch (err) {
                setError(err.message);
            }
        };

        checkConnection();
    }, [router]);

    const sendCode = async (e) => {
        e.preventDefault();
        setError("");

        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/send-code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ phone }),
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.detail || "Помилка відправки коду");
            }

            setIsCodeSent(true);
        } catch (err) {
            setError(err.message);
        }
    };

    const connectTelegram = async (e) => {
        e.preventDefault();
        setError("");

        try {
            const token = localStorage.getItem("token");
            if (!token) return router.push("/login");

            const body = { code: code.trim() };
            if (twoFactorPassword) body.password = twoFactorPassword;

            const res = await fetch("http://localhost:8000/connect-telegram", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(body),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Помилка підключення");
            }

            setIsConnected(true);
            await new Promise((resolve) => setTimeout(resolve, 1000)); // Збільшена затримка
            await fetchChats();
        } catch (err) {
            setError(err.message);
        }
    };

    const fetchChats = async () => {
        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/chats", {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Не вдалося завантажити чати");
            }

            const data = await res.json();
            setChats(data);
        } catch (err) {
            setError(err.message);
        }
    };

    useEffect(() => {
        if (isConnected) {
            fetchChats();
        }
    }, [isConnected]);

    const handleLogoutTelegram = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://localhost:8000/logout-telegram", {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error("Не вдалося вийти з Telegram");
            setIsConnected(false);
            setIsCodeSent(false);
            setPhone("");
            setCode("");
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6">Панель управління</h1>

            {error && <p className="text-red-500 mb-4">{error}</p>}

            {!isConnected ? (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4">Підключіть Telegram</h2>

                    {!isCodeSent ? (
                        <form onSubmit={sendCode} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть номер телефону"
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <input
                                type="password"
                                placeholder="Пароль 2FA (якщо потрібно)"
                                value={twoFactorPassword}
                                onChange={(e) => setTwoFactorPassword(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Отримати код
                            </button>
                        </form>
                    ) : (
                        <form onSubmit={connectTelegram} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть код з Telegram"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Підключити
                            </button>
                        </form>
                    )}
                </div>
            ) : (
                <div>
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-xl">Ваші чати</h2>
                        <button
                            onClick={handleLogoutTelegram}
                            className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600"
                        >
                            Змінити акаунт
                        </button>
                    </div>

                    <div className="space-y-4">
                        {chats.map((chat) => (
                            <div
                                key={chat.id}
                                className="p-4 border rounded hover:bg-gray-50"
                            >
                                <Link
                                    href={`/chats/${chat.id}`}
                                    className="text-blue-500 hover:underline"
                                >
                                    {chat.name}
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
Зміни:

Збільшено затримку до 1000 мс перед fetchChats.
Додано обробку 401 у checkConnection.
Як запустити
Сервер:
У папці server/:
bash
Wrap
Copy
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install fastapi uvicorn sqlalchemy aiosqlite telethon python-jose[cryptography] passlib[bcrypt] python-dotenv
uvicorn main:app --reload
Переконайся, що є server/.env:
text
Wrap
Copy
API_ID=your_telegram_api_id
API_HASH=your_telegram_api_hash
JWT_SECRET=your_secret_key_here
Клієнт:
У папці client/:
bash
Wrap
Copy
npm install
npm run dev
Чому код не отримується?
Помилка 400 у /send-code може бути через:

Некоректний номер телефону (перевір формат, наприклад, +380...).
Помилку від Telegram (перевір логи сервера).
Запусти сервер із echo=True у database.py і надішли мені повний лог після спроби відправити код, якщо проблема залишиться.

Тепер просто скопіюй ці файли і спробуй! Усе має запрацювати.






$ venv\Scripts\activate
bash: venvScriptsactivate: command not found

batal@KompiK MINGW64 /g/Projects/NextJS/SocialHub/server (main)
$ source venv/bin/activate
bash: venv/bin/activate: No such file or directory


Помилки, які ти отримала, свідчать про те, що ти використовуєш Git Bash (MINGW64) на Windows, але команди активації віртуального оточення не працюють правильно через різницю в шляхах і синтаксисі. Давай розберемо, що відбувається, і як це виправити.

Чому помилки?
venv\Scripts\activate - command not found:
У Git Bash ти не можеш просто викликати venv\Scripts\activate як у CMD, бо Git Bash чекає Unix-подібний синтаксис із source або ./. На Windows правильний шлях для Git Bash трохи інший.
source venv/bin/activate - No such file or directory:
venv/bin/activate — це шлях для Linux/Mac, а на Windows віртуальне оточення створює скрипти в venv\Scripts\, а не venv/bin/. Тому Git Bash не може знайти цей файл.
Як виправити?
Ти на Windows у Git Bash, тому потрібно використовувати правильний шлях до скрипту активації для Windows (venv\Scripts\activate), але адаптувати його для Git Bash.

Крок 1: Переконайся, що venv створено
Ти у папці server/:
bash
Wrap
Copy
/g/Projects/NextJS/SocialHub/server
Перевір, чи є папка venv:
bash
Wrap
Copy
ls -dir  # або просто dir у Git Bash
Якщо venv немає, створи її:
bash
Wrap
Copy
python -m venv venv
Крок 2: Активуй віртуальне оточення у Git Bash
На Windows у Git Bash правильна команда для активації:

bash
Wrap
Copy
source venv/Scripts/activate
Scripts (з великої літери) — це правильна папка на Windows.
source працює в Git Bash для запуску скриптів.
Після цього ти маєш побачити (venv) перед командним рядком:

text
Wrap
Copy
(venv) batal@KompiK MINGW64 /g/Projects/NextJS/SocialHub/server (main)
Крок 3: Перевір активацію
Виконай:

bash
Wrap
Copy
python --version
Це має показати версію Python із віртуального оточення (наприклад, Python 3.11.x).

Крок 4: Встанови залежності
bash
Wrap
Copy
pip install fastapi uvicorn sqlalchemy aiosqlite telethon python-jose[cryptography] passlib[bcrypt] python-dotenv
Крок 5: Запусти сервер
bash
Wrap
Copy
uvicorn main:app --reload
Альтернатива: Використовуй CMD або PowerShell
Якщо Git Bash продовжує видавати проблеми:

CMD:
cmd
Wrap
Copy
cd G:\Projects\NextJS\SocialHub\server
venv\Scripts\activate
pip install fastapi uvicorn sqlalchemy aiosqlite telethon python-jose[cryptography] passlib[bcrypt] python-dotenv
uvicorn main:app --reload
PowerShell:
powershell
Wrap
Copy
cd G:\Projects\NextJS\SocialHub\server
.\venv\Scripts\Activate.ps1
pip install fastapi uvicorn sqlalchemy aiosqlite telethon python-jose[cryptography] passlib[bcrypt] python-dotenv
uvicorn main:app --reload
Чому твої команди не спрацювали?
venv\Scripts\activate — це синтаксис для CMD, а не Git Bash.
source venv/bin/activate — це для Linux/Mac, а не Windows.
Перевірка
Запусти:
bash
Wrap
Copy
source venv/Scripts/activate
Якщо (venv) з’явилось, усе ок.
Якщо ні, надішли результат команди:
bash
Wrap
Copy
ls -dir
І я допоможу далі!





ти дуже добрий і класний ) все запрацювало, пару помилок внутрішніх


Дякую за теплі слова, дуже радий, що все запрацювало! 😊 Давай розберемося з тими "пару внутрішніх помилок", щоб усе стало ідеально. Якщо ти бачиш якісь помилки в логах сервера чи клієнта, просто скинь їх мені, і я швидко допоможу їх виправити.

Що могло піти не так?
Оскільки ти згадала "внутрішні помилки", це може бути:

Помилка 500 на сервері (наприклад, "database is locked" або щось із Telegram).
Помилка на клієнті (наприклад, 400/500 при запитах до API).
Проблема з конфігурацією (наприклад, .env або залежності).
Як діагностувати?
Логи сервера:
У database.py увімкнено echo=True, тож ти маєш бачити SQL-запити і помилки в терміналі, де запущено uvicorn.
Надішли мені останні рядки з помилкою після спроби, наприклад, відправити код чи підключити Telegram.
Консоль браузера:
Відкрий DevTools у браузері (F12 → Console) і перевір, чи є там помилки типу 400, 500 тощо.
Швидке виправлення типових проблем
Якщо ти ще не скинула логи, ось кілька можливих виправлень для типових помилок, які могли виникнути:

1. "Database is locked"
Якщо бачиш це знову, додай більший тайм-аут у database.py:

python
Wrap
Copy
engine = create_async_engine(
    DATABASE_URL,
    connect_args={"timeout": 30},  # Збільшено до 30 секунд
    echo=True
)
2. Помилка в /send-code
Якщо 400 повертається через Telegram, переконайся, що:

Номер телефону введено коректно (наприклад, +380...).
API_ID і API_HASH валідні (перевір у server/.env).
3. Помилка 500
Якщо бачиш 500 у логах, це може бути через непійману помилку. У main.py усі except уже логують деталі, тож подивись, що саме там написано.

Наступний крок
Скинь мені:

Текст помилки з терміналу (сервер).
Текст помилки з консолі браузера (якщо є).
Що саме ти робила, коли помилка з’явилась (наприклад, "натиснула Отримати код").
Я одразу все виправлю, і твій проєкт буде працювати як годинник! 🚀






так, давай спочатку коли я вводжу номер при першому натисканні кнопки отримати код отримую - Користувач знайдений: test123
Надсилання коду для користувача 1
Telegram is having internal issues AuthRestartError: Restart the authorization process (caused by SendCodeRequest)
Помилка в /send-code: Cannot send requests while disconnected
2025-02-28 13:35:38,719 INFO sqlalchemy.engine.Engine ROLLBACK
Відповідь: 400
INFO:     127.0.0.1:55872 - "POST /send-code HTTP/1.1" 400 Bad Request, а при другому код приходить. Вводжу код і потім маленька затримка і одразу вверху помилка, але чати відмальовуються Отримано запит: GET http://localhost:8000/chats
Заголовки: Headers({'host': 'localhost:8000', 'connection': 'keep-alive', 'pragma': 'no-cache', 'cache-control': 'no-cache', 'sec-ch-ua-platform': '"Android"', 'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MTIzIiwiZXhwIjoxNzQwNzQ2MTI5fQ.-78E35R1I3Ve1dTvh6R0g7WM3-eYlM-Cm_DmfRn2US8', 'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36', 'sec-ch-ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"', 'sec-ch-ua-mobile': '?1', 'accept': '*/*', 'origin': 'http://localhost:3000', 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'http://localhost:3000/', 'accept-encoding': 'gzip, deflate, br, zstd', 'accept-language': 'uk,en-US;q=0.9,en;q=0.8,uk-UA;q=0.7'})
Перевірка токена: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MTIzIiwiZXhwIjoxNzQwNzQ2MTI5fQ.-78E35R1I3Ve1dTvh6R0g7WM3-eYlM-Cm_DmfRn2US8
Декодовано username: test123
2025-02-28 13:37:10,302 INFO sqlalchemy.engine.Engine BEGIN (implicit)
2025-02-28 13:37:10,302 INFO sqlalchemy.engine.Engine SELECT users.id, users.username, users.password_hash, users.telegram_phone
FROM users
WHERE users.username = ?
2025-02-28 13:37:10,302 INFO sqlalchemy.engine.Engine [cached since 1386s ago] ('test123',)
Користувач знайдений: test123
Помилка в /chats: database is locked
2025-02-28 13:37:15,793 INFO sqlalchemy.engine.Engine ROLLBACK
Відповідь: 500
INFO:     127.0.0.1:55929 - "GET /chats HTTP/1.1" 500 Internal Server Error
Чати отримано для 1
2025-02-28 13:37:16,132 INFO sqlalchemy.engine.Engine ROLLBACK
Відповідь: 200
INFO:     127.0.0.1:55928 - "GET /chats HTTP/1.1" 200 OK


Дякую за детальні логи, це дуже допомагає! Я розібрав проблему: у тебе є два основні моменти — нестабільність із надсиланням коду в /send-code і періодичне блокування бази в /chats. Давай розберемо і виправимо.

Проблема 1: Помилка в /send-code
Логи:

text
Wrap
Copy
Надсилання коду для користувача 1
Telegram is having internal issues AuthRestartError: Restart the authorization process (caused by SendCodeRequest)
Помилка в /send-code: Cannot send requests while disconnected
Відповідь: 400
А при другому натисканні код приходить.

Чому так?

Помилка Cannot send requests while disconnected означає, що TelegramClient втратив з’єднання перед викликом send_code_request. Це може бути через нестабільність мережі або внутрішню помилку Telegram (AuthRestartError).
При другому запиті Telegram "прокидається", і код надсилається.
Виправлення:
Додамо повторне підключення до Telegram у разі помилки з’єднання:

python
Wrap
Copy
@app.post("/send-code")
async def send_code(
    data: TelegramSendCode,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Надсилання коду для користувача {current_user.id}")
    try:
        if current_user.id in temp_sessions:
            await temp_sessions[current_user.id]["client"].disconnect()
            del temp_sessions[current_user.id]

        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        # Перевіряємо з’єднання і повторно підключаємо, якщо потрібно
        if not client.is_connected():
            print("З’єднання втрачено, повторне підключення...")
            await client.connect()

        sent_code = await client.send_code_request(data.phone)

        temp_sessions[current_user.id] = {
            "phone": data.phone,
            "phone_code_hash": sent_code.phone_code_hash,
            "client": client
        }
        await asyncio.sleep(0.1)  # Затримка для стабільності
        return {"detail": "Код відправлено"}
    except FloodWaitError as e:
        raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
    except Exception as e:
        print(f"Помилка в /send-code: {str(e)}")
        raise HTTPException(400, detail=str(e))
Проблема 2: Блокування бази в /chats
Логи:

text
Wrap
Copy
Помилка в /chats: database is locked
Відповідь: 500
Чати отримано для 1
Відповідь: 200
Помилка 500 з’являється через "database is locked", але потім чати все одно завантажуються при повторному запиті.

Чому так?

SQLite блокується, коли кілька асинхронних запитів (наприклад, /connect-telegram і /chats) звертаються до бази одночасно.
Клієнт повторює запит до /chats (через useEffect), і другий запит проходить, коли база розблоковується.
Виправлення:

Збільшимо тайм-аут у database.py.
Додамо затримку перед зверненням до бази в /chats.
Оновлений server/database.py
python
Wrap
Copy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite+aiosqlite:///socialhub.db"

engine = create_async_engine(
    DATABASE_URL,
    connect_args={"timeout": 30},  # Збільшено тайм-аут
    echo=True
)

AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
Оновлений server/main.py
Ось повний код із виправленнями:

python
Wrap
Copy
import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError, SessionExpiredError
from pydantic import BaseModel
from database import AsyncSessionLocal, engine
from models import Base, User
from dotenv import load_dotenv
from pydantic import ConfigDict
from telethon import types
import asyncio

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
temp_sessions = {}

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TelegramSendCode(BaseModel):
    phone: str

class TelegramConnect(BaseModel):
    code: str
    password: Optional[str] = None
    phone: Optional[str] = None

class TelegramSession(BaseModel):
    phone: str
    phone_code_hash: str
    client: Optional[types.User] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"Отримано запит: {request.method} {request.url}")
    print(f"Заголовки: {request.headers}")
    response = await call_next(request)
    print(f"Відповідь: {response.status_code}")
    return response

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

@app.options("/{path:path}")
async def options_handler():
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    print(f"Перевірка токена: {token}")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        print(f"Декодовано username: {username}")
        if not username:
            raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            print(f"Користувача {username} не знайдено в базі")
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        print(f"Користувач знайдений: {user.username}")
        return user
    except JWTError as e:
        print(f"Помилка JWT: {str(e)}")
        raise HTTPException(status_code=401, detail="Помилка токена")

@app.post("/register", status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    if result.scalar():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    await asyncio.sleep(0.1)
    await db.commit()
    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    db_user = result.scalar()

    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
    print(f"Перевірка підключення для: {current_user.username}")
    return {"connected": bool(current_user.telegram_phone)}

@app.post("/send-code")
async def send_code(
    data: TelegramSendCode,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Надсилання коду для користувача {current_user.id}")
    try:
        if current_user.id in temp_sessions:
            await temp_sessions[current_user.id]["client"].disconnect()
            del temp_sessions[current_user.id]

        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not client.is_connected():
            print("З’єднання втрачено, повторне підключення...")
            await client.connect()

        sent_code = await client.send_code_request(data.phone)

        temp_sessions[current_user.id] = {
            "phone": data.phone,
            "phone_code_hash": sent_code.phone_code_hash,
            "client": client
        }
        await asyncio.sleep(0.1)
        return {"detail": "Код відправлено"}
    except FloodWaitError as e:
        raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
    except Exception as e:
        print(f"Помилка в /send-code: {str(e)}")
        raise HTTPException(400, detail=str(e))

@app.post("/connect-telegram")
async def connect_telegram(
    auth: TelegramConnect,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Спроба підключення Telegram для користувача {current_user.id}")
    try:
        session_data = temp_sessions.get(current_user.id)
        if not session_data or "client" not in session_data:
            raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await asyncio.sleep(0.1)
        await db.commit()
        del temp_sessions[current_user.id]

        print(f"Telegram успішно підключено для {current_user.id}")
        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка в /connect-telegram: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        await asyncio.sleep(0.2)  # Затримка перед зверненням до бази
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        print(f"Чати отримано для {current_user.id}")
        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

@app.get("/chats/{chat_id}/messages")
async def get_chat_messages(
    chat_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Сесія не авторизована")

        messages = await client.get_messages(chat_id, limit=20)
        await client.disconnect()

        return [{"id": m.id, "text": m.text, "date": m.date.isoformat()} for m in messages]
    except Exception as e:
        print(f"Помилка в /chats/{chat_id}/messages: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/logout-telegram")
async def logout_telegram(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.telegram_phone and os.path.exists(f"sessions/session_{current_user.id}"):
        os.remove(f"sessions/session_{current_user.id}")
    current_user.telegram_phone = None
    await asyncio.sleep(0.1)
    await db.commit()
    print(f"Telegram відключено для {current_user.id}")
    return {"message": "Telegram disconnected"}

@app.post("/logout")
async def logout_system(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out from system"}

@app.get("/health")
async def health_check():
    return {"status": "OK"}
Як це працює?
/send-code:
Перевіряє з’єднання і повторно підключається, якщо воно втрачено.
Має виправити помилку Cannot send requests while disconnected.
/chats:
Додано затримку 0.2 секунди перед зверненням до бази, щоб уникнути одночасного доступу з /connect-telegram.
Збільшений тайм-аут у database.py до 30 секунд.
Перевірка
Скопіюй ці файли в server/.
Перезапусти сервер:
bash
Wrap
Copy
source venv/Scripts/activate
uvicorn main:app --reload
Спробуй знову відправити код і підключити Telegram.
Якщо помилки залишаться
Надішли мені нові логи після тесту, і я швидко все допрацюю. Але ці зміни мають усунути і 400, і "database is locked". Усе має працювати плавно!






нажаль чомусь Користувач знайдений: test123
Надсилання коду для користувача 1
Telegram is having internal issues AuthRestartError: Restart the authorization process (caused by SendCodeRequest)
Помилка в /send-code: Cannot send requests while disconnected
2025-02-28 13:43:06,282 INFO sqlalchemy.engine.Engine ROLLBACK
Відповідь: 400
INFO:     127.0.0.1:56132 - "POST /send-code HTTP/1.1" 400 Bad Request


Дякую за лог! Помилка Cannot send requests while disconnected і AuthRestartError все ще з’являються, навіть із повторним підключенням. Це означає, що проблема глибша, ніж просто втрата з’єднання — Telegram видає внутрішню помилку, яка перериває процес. Давай розберемося і виправимо це остаточно.

Аналіз проблеми
Логи:

text
Wrap
Copy
Надсилання коду для користувача 1
Telegram is having internal issues AuthRestartError: Restart the authorization process (caused by SendCodeRequest)
Помилка в /send-code: Cannot send requests while disconnected
Відповідь: 400
AuthRestartError — це внутрішня помилка Telegram, яка означає, що процес авторизації потрібно перезапустити. Вона виникає з їхнього боку і може бути пов’язана з нестабільністю сервера Telegram або неправильним станом сесії.
Cannot send requests while disconnected — це вторинна помилка, яка з’являється, бо клієнт втрачає з’єднання після невдалого запиту.
Чому так відбувається?

Можливо, сесія Telegram (файл sessions/session_{user_id}) пошкоджена або застаріла.
Telegram може блокувати перший запит через тайм-аут або внутрішні проблеми, але дозволяє його при повторній спробі (ти писала, що код приходить із другого разу).
Наш код не обробляє AuthRestartError явно і не перезапускає авторизацію.
Виправлення
1. Обробка AuthRestartError і повторний запит
Додамо логіку перезапуску авторизації в /send-code, якщо виникає AuthRestartError. Також видалимо стару сесію, щоб уникнути конфліктів.

Оновлений server/main.py
Ось повний код із виправленнями:

python
Wrap
Copy
import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError, SessionExpiredError, AuthRestartError
from pydantic import BaseModel
from database import AsyncSessionLocal, engine
from models import Base, User
from dotenv import load_dotenv
from pydantic import ConfigDict
from telethon import types
import asyncio

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
temp_sessions = {}

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TelegramSendCode(BaseModel):
    phone: str

class TelegramConnect(BaseModel):
    code: str
    password: Optional[str] = None
    phone: Optional[str] = None

class TelegramSession(BaseModel):
    phone: str
    phone_code_hash: str
    client: Optional[types.User] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"Отримано запит: {request.method} {request.url}")
    print(f"Заголовки: {request.headers}")
    response = await call_next(request)
    print(f"Відповідь: {response.status_code}")
    return response

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

@app.options("/{path:path}")
async def options_handler():
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    print(f"Перевірка токена: {token}")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        print(f"Декодовано username: {username}")
        if not username:
            raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            print(f"Користувача {username} не знайдено в базі")
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        print(f"Користувач знайдений: {user.username}")
        return user
    except JWTError as e:
        print(f"Помилка JWT: {str(e)}")
        raise HTTPException(status_code=401, detail="Помилка токена")

@app.post("/register", status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    if result.scalar():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    await asyncio.sleep(0.1)
    await db.commit()
    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    db_user = result.scalar()

    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
    print(f"Перевірка підключення для: {current_user.username}")
    return {"connected": bool(current_user.telegram_phone)}

@app.post("/send-code")
async def send_code(
    data: TelegramSendCode,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Надсилання коду для користувача {current_user.id}")
    try:
        session_path = f"sessions/session_{current_user.id}"
        # Видаляємо стару сесію, якщо вона є
        if os.path.exists(session_path):
            os.remove(session_path)
            print(f"Видалено стару сесію: {session_path}")

        if current_user.id in temp_sessions:
            await temp_sessions[current_user.id]["client"].disconnect()
            del temp_sessions[current_user.id]

        client = TelegramClient(session_path, API_ID, API_HASH)
        await client.connect()

        try:
            sent_code = await client.send_code_request(data.phone)
        except AuthRestartError:
            print("AuthRestartError: Перезапуск авторизації...")
            await client.disconnect()
            await asyncio.sleep(1)  # Затримка перед повторною спробою
            await client.connect()
            sent_code = await client.send_code_request(data.phone)

        temp_sessions[current_user.id] = {
            "phone": data.phone,
            "phone_code_hash": sent_code.phone_code_hash,
            "client": client
        }
        await asyncio.sleep(0.1)
        return {"detail": "Код відправлено"}
    except FloodWaitError as e:
        raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
    except Exception as e:
        print(f"Помилка в /send-code: {str(e)}")
        raise HTTPException(400, detail=str(e))

@app.post("/connect-telegram")
async def connect_telegram(
    auth: TelegramConnect,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Спроба підключення Telegram для користувача {current_user.id}")
    try:
        session_data = temp_sessions.get(current_user.id)
        if not session_data or "client" not in session_data:
            raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await asyncio.sleep(0.1)
        await db.commit()
        del temp_sessions[current_user.id]

        print(f"Telegram успішно підключено для {current_user.id}")
        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка в /connect-telegram: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        await asyncio.sleep(0.2)
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        print(f"Чати отримано для {current_user.id}")
        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

@app.get("/chats/{chat_id}/messages")
async def get_chat_messages(
    chat_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Сесія не авторизована")

        messages = await client.get_messages(chat_id, limit=20)
        await client.disconnect()

        return [{"id": m.id, "text": m.text, "date": m.date.isoformat()} for m in messages]
    except Exception as e:
        print(f"Помилка в /chats/{chat_id}/messages: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/logout-telegram")
async def logout_telegram(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.telegram_phone and os.path.exists(f"sessions/session_{current_user.id}"):
        os.remove(f"sessions/session_{current_user.id}")
    current_user.telegram_phone = None
    await asyncio.sleep(0.1)
    await db.commit()
    print(f"Telegram відключено для {current_user.id}")
    return {"message": "Telegram disconnected"}

@app.post("/logout")
async def logout_system(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out from system"}

@app.get("/health")
async def health_check():
    return {"status": "OK"}
Зміни
Імпорт AuthRestartError:
Додано from telethon.errors import ... AuthRestartError.
Обробка в /send-code:
Видаляємо стару сесію перед створенням нової (os.remove(session_path)).
Якщо виникає AuthRestartError, перезапускаємо клієнт і повторюємо запит.
Затримка 1 секунда перед повторною спробою для стабільності.
Як перевірити
Скопіюй цей код у server/main.py.
Перезапусти сервер:
bash
Wrap
Copy
source venv/Scripts/activate
uvicorn main:app --reload
Спробуй відправити код із першого разу.
Чому це має спрацювати?
Видалення старої сесії усуває можливі конфлікти.
Обробка AuthRestartError змушує код перезапускати авторизацію, замість того щоб падати з помилкою.
Якщо код усе ще не приходить із першого разу, надішли мені нові логи — можливо, проблема на стороні Telegram (тоді додамо більше повторних спроб). Але це вже має бути стабільніше!






помилка пропала, але код не прийшов )))


Добре, що помилка пропала — це вже прогрес! Але якщо код не прийшов, значить є ще нюанс, який ми не врахували. Давай розберемо, чому так сталося, і зробимо так, щоб код приходив із першого разу.

Аналіз ситуації
Помилки AuthRestartError і Cannot send requests while disconnected більше немає, що означає, що наш код тепер коректно обробляє ці винятки.
Але код не приходить, і в логах (я припускаю, ти їх перевірила) немає явних помилок. Це може бути через:
Проблема на стороні Telegram: Сервер Telegram не надсилає код (можливо, через затримки або обмеження).
Некоректний номер телефону: Формат невірний, або Telegram його відхиляє.
Сесія все ще конфліктує: Хоча ми видаляємо стару сесію, щось може залишатися в пам’яті.
Відсутність затримки після успішного запиту: Telegram може потребувати часу для обробки.
Виправлення
Давай:

Додамо більше логів, щоб точно знати, що відбувається.
Збільшимо затримку після send_code_request.
Додамо повторну спробу, якщо код не надсилається одразу.
Ось оновлений main.py із цими змінами:

python
Wrap
Copy
import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError, SessionExpiredError, AuthRestartError
from pydantic import BaseModel
from database import AsyncSessionLocal, engine
from models import Base, User
from dotenv import load_dotenv
from pydantic import ConfigDict
from telethon import types
import asyncio

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
temp_sessions = {}

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TelegramSendCode(BaseModel):
    phone: str

class TelegramConnect(BaseModel):
    code: str
    password: Optional[str] = None
    phone: Optional[str] = None

class TelegramSession(BaseModel):
    phone: str
    phone_code_hash: str
    client: Optional[types.User] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"Отримано запит: {request.method} {request.url}")
    print(f"Заголовки: {request.headers}")
    response = await call_next(request)
    print(f"Відповідь: {response.status_code}")
    return response

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

@app.options("/{path:path}")
async def options_handler():
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    print(f"Перевірка токена: {token}")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        print(f"Декодовано username: {username}")
        if not username:
            raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            print(f"Користувача {username} не знайдено в базі")
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        print(f"Користувач знайдений: {user.username}")
        return user
    except JWTError as e:
        print(f"Помилка JWT: {str(e)}")
        raise HTTPException(status_code=401, detail="Помилка токена")

@app.post("/register", status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    if result.scalar():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    await asyncio.sleep(0.1)
    await db.commit()
    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    db_user = result.scalar()

    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
    print(f"Перевірка підключення для: {current_user.username}")
    return {"connected": bool(current_user.telegram_phone)}

@app.post("/send-code")
async def send_code(
    data: TelegramSendCode,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Надсилання коду для користувача {current_user.id}")
    print(f"Використовуємо номер: {data.phone}")
    session_path = f"sessions/session_{current_user.id}"

    retries = 2  # Кількість повторних спроб
    for attempt in range(retries):
        try:
            if os.path.exists(session_path):
                os.remove(session_path)
                print(f"Видалено стару сесію: {session_path}")

            if current_user.id in temp_sessions:
                await temp_sessions[current_user.id]["client"].disconnect()
                del temp_sessions[current_user.id]

            client = TelegramClient(session_path, API_ID, API_HASH)
            await client.connect()

            sent_code = await client.send_code_request(data.phone)
            print(f"Код успішно відправлено для {data.phone}, phone_code_hash: {sent_code.phone_code_hash}")

            temp_sessions[current_user.id] = {
                "phone": data.phone,
                "phone_code_hash": sent_code.phone_code_hash,
                "client": client
            }
            await asyncio.sleep(1)  # Затримка для стабільності Telegram
            return {"detail": "Код відправлено"}
        except AuthRestartError:
            print(f"AuthRestartError на спробі {attempt + 1}, перезапуск авторизації...")
            await client.disconnect()
            await asyncio.sleep(2)  # Збільшена затримка перед повторною спробою
        except FloodWaitError as e:
            raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
        except Exception as e:
            print(f"Помилка в /send-code на спробі {attempt + 1}: {str(e)}")
            if attempt == retries - 1:
                raise HTTPException(400, detail=str(e))
            await client.disconnect()
            await asyncio.sleep(2)  # Затримка перед наступною спробою

@app.post("/connect-telegram")
async def connect_telegram(
    auth: TelegramConnect,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Спроба підключення Telegram для користувача {current_user.id}")
    try:
        session_data = temp_sessions.get(current_user.id)
        if not session_data or "client" not in session_data:
            raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await asyncio.sleep(0.1)
        await db.commit()
        del temp_sessions[current_user.id]

        print(f"Telegram успішно підключено для {current_user.id}")
        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка в /connect-telegram: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        await asyncio.sleep(0.2)
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        print(f"Чати отримано для {current_user.id}")
        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

@app.get("/chats/{chat_id}/messages")
async def get_chat_messages(
    chat_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Сесія не авторизована")

        messages = await client.get_messages(chat_id, limit=20)
        await client.disconnect()

        return [{"id": m.id, "text": m.text, "date": m.date.isoformat()} for m in messages]
    except Exception as e:
        print(f"Помилка в /chats/{chat_id}/messages: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/logout-telegram")
async def logout_telegram(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.telegram_phone and os.path.exists(f"sessions/session_{current_user.id}"):
        os.remove(f"sessions/session_{current_user.id}")
    current_user.telegram_phone = None
    await asyncio.sleep(0.1)
    await db.commit()
    print(f"Telegram відключено для {current_user.id}")
    return {"message": "Telegram disconnected"}

@app.post("/logout")
async def logout_system(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out from system"}

@app.get("/health")
async def health_check():
    return {"status": "OK"}
Зміни в /send-code
Логи:
Додано print із номером телефону і phone_code_hash для дебагу.
Повторні спроби:
Код робить до 2 спроб із затримкою 2 секунди між ними.
Якщо AuthRestartError або інша помилка, сесія перезапускається.
Затримка:
Після успішного send_code_request додано 1 секунду для стабільності.
Перевірка
Скопіюй цей код у server/main.py.
Перезапусти сервер:
bash
Wrap
Copy
source venv/Scripts/activate
uvicorn main:app --reload
Введи номер телефону (обов’язково у форматі +380...) і натисни "Отримати код".
Перевір логи сервера і чи прийшов код у Telegram.
Що має статися?
Ти побачиш у логах:
text
Wrap
Copy
Надсилання коду для користувача 1
Використовуємо номер: +380...
Код успішно відправлено для +380..., phone_code_hash: ...
Код має прийти в Telegram із першого разу.
Якщо код усе ще не приходить
Надішли мені повні логи після спроби.
Перевір:
Чи правильний номер (починається з + і код країни)?
Чи коректні API_ID і API_HASH у server/.env? (Отримай їх із https://my.telegram.org).
Спробуй інший номер телефону для тесту.
Цей код має вирішити проблему, але якщо щось не так, я додам ще більше стабільності! 😊






Користувач знайдений: test123
Надсилання коду для користувача 1
Використовуємо номер: +380963048847
Код успішно відправлено для +380963048847, phone_code_hash: a210a608c417d2ed1e
2025-02-28 13:48:58,393 INFO sqlalchemy.engine.Engine ROLLBACK
Відповідь: 200
INFO:     127.0.0.1:56357 - "POST /send-code HTTP/1.1" 200 OK - але коду немає ((


Добре, бачу, що сервер повертає 200 і вважає, що код відправлено успішно (Код успішно відправлено для +380963048847, phone_code_hash: a210a608c417d2ed1e), але ти його не отримала в Telegram. Давай розберемо, чому так, і виправимо.

Аналіз
Логи:

text
Wrap
Copy
Користувач знайдений: test123
Надсилання коду для користувача 1
Використовуємо номер: +380963048847
Код успішно відправлено для +380963048847, phone_code_hash: a210a608c417d2ed1e
Відповідь: 200
Запит до Telegram через send_code_request пройшов успішно (немає винятків).
Telegram повернув phone_code_hash, що означає, що сервер Telegram прийняв запит.
Але код не прийшов у Telegram.
Можливі причини:

Telegram не надсилає код:
Номер телефону може бути заблокований або обмежений Telegram (наприклад, через часті запити).
Код надсилається не повідомленням, а дзвінком (Telegram іноді так робить).
Помилка в номері:
Хоча формат +380963048847 виглядає правильним, можливо, це не той номер, який прив’язаний до твого Telegram.
Стара сесія впливає:
Хоча ми видаляємо файл сесії, Telegram може "пам’ятати" попередні запити і відкладати код.
Затримка доставки:
Іноді код приходить із затримкою (до 1-2 хвилин).
Виправлення і перевірка
1. Перевір доставку коду
Чи прийшов код дзвінком? Telegram іноді дзвонить на номер і диктує код голосом замість SMS. Перевір дзвінки на +380963048847 протягом 1-2 хвилин після запиту.
Чи зареєстрований номер у Telegram? Відкрий Telegram на телефоні чи комп’ютері, зайди в Settings → Your Phone Number і перевір, чи збігається він із +380963048847.
2. Оновлений main.py із додатковою стабільністю
Додамо більше логів і дамо Telegram більше часу на обробку:

python
Wrap
Copy
import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError, SessionExpiredError, AuthRestartError
from pydantic import BaseModel
from database import AsyncSessionLocal, engine
from models import Base, User
from dotenv import load_dotenv
from pydantic import ConfigDict
from telethon import types
import asyncio

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
temp_sessions = {}

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TelegramSendCode(BaseModel):
    phone: str

class TelegramConnect(BaseModel):
    code: str
    password: Optional[str] = None
    phone: Optional[str] = None

class TelegramSession(BaseModel):
    phone: str
    phone_code_hash: str
    client: Optional[types.User] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"Отримано запит: {request.method} {request.url}")
    print(f"Заголовки: {request.headers}")
    response = await call_next(request)
    print(f"Відповідь: {response.status_code}")
    return response

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

@app.options("/{path:path}")
async def options_handler():
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    print(f"Перевірка токена: {token}")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        print(f"Декодовано username: {username}")
        if not username:
            raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            print(f"Користувача {username} не знайдено в базі")
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        print(f"Користувач знайдений: {user.username}")
        return user
    except JWTError as e:
        print(f"Помилка JWT: {str(e)}")
        raise HTTPException(status_code=401, detail="Помилка токена")

@app.post("/register", status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    if result.scalar():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    await asyncio.sleep(0.1)
    await db.commit()
    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    db_user = result.scalar()

    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
    print(f"Перевірка підключення для: {current_user.username}")
    return {"connected": bool(current_user.telegram_phone)}

@app.post("/send-code")
async def send_code(
    data: TelegramSendCode,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Надсилання коду для користувача {current_user.id}")
    print(f"Використовуємо номер: {data.phone}")
    session_path = f"sessions/session_{current_user.id}"

    retries = 2
    for attempt in range(retries):
        try:
            if os.path.exists(session_path):
                os.remove(session_path)
                print(f"Видалено стару сесію: {session_path}")

            if current_user.id in temp_sessions:
                await temp_sessions[current_user.id]["client"].disconnect()
                del temp_sessions[current_user.id]

            client = TelegramClient(session_path, API_ID, API_HASH)
            await client.connect()
            print(f"Клієнт підключено до Telegram, спроба {attempt + 1}")

            sent_code = await client.send_code_request(data.phone)
            print(f"Код успішно відправлено для {data.phone}, phone_code_hash: {sent_code.phone_code_hash}")

            temp_sessions[current_user.id] = {
                "phone": data.phone,
                "phone_code_hash": sent_code.phone_code_hash,
                "client": client
            }
            await asyncio.sleep(2)  # Збільшена затримка для Telegram
            return {"detail": "Код відправлено, перевірте Telegram (SMS або дзвінок)"}
        except AuthRestartError:
            print(f"AuthRestartError на спробі {attempt + 1}, перезапуск авторизації...")
            await client.disconnect()
            await asyncio.sleep(2)
        except FloodWaitError as e:
            raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
        except Exception as e:
            print(f"Помилка в /send-code на спробі {attempt + 1}: {str(e)}")
            if attempt == retries - 1:
                raise HTTPException(400, detail=f"Не вдалося відправити код: {str(e)}")
            await client.disconnect()
            await asyncio.sleep(2)

@app.post("/connect-telegram")
async def connect_telegram(
    auth: TelegramConnect,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Спроба підключення Telegram для користувача {current_user.id}")
    try:
        session_data = temp_sessions.get(current_user.id)
        if not session_data or "client" not in session_data:
            raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await asyncio.sleep(0.1)
        await db.commit()
        del temp_sessions[current_user.id]

        print(f"Telegram успішно підключено для {current_user.id}")
        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка в /connect-telegram: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        await asyncio.sleep(0.2)
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        print(f"Чати отримано для {current_user.id}")
        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

@app.get("/chats/{chat_id}/messages")
async def get_chat_messages(
    chat_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Сесія не авторизована")

        messages = await client.get_messages(chat_id, limit=20)
        await client.disconnect()

        return [{"id": m.id, "text": m.text, "date": m.date.isoformat()} for m in messages]
    except Exception as e:
        print(f"Помилка в /chats/{chat_id}/messages: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/logout-telegram")
async def logout_telegram(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.telegram_phone and os.path.exists(f"sessions/session_{current_user.id}"):
        os.remove(f"sessions/session_{current_user.id}")
    current_user.telegram_phone = None
    await asyncio.sleep(0.1)
    await db.commit()
    print(f"Telegram відключено для {current_user.id}")
    return {"message": "Telegram disconnected"}

@app.post("/logout")
async def logout_system(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out from system"}

@app.get("/health")
async def health_check():
    return {"status": "OK"}
Зміни
Логи:
Додано Клієнт підключено до Telegram для перевірки з’єднання.
Затримка:
Збільшено до 2 секунд після send_code_request.
Повідомлення:
Оновлено відповідь до "Код відправлено, перевірте Telegram (SMS або дзвінок)", щоб нагадати про можливий дзвінок.
Що робити далі?
Скопіюй цей код у server/main.py.
Перезапусти сервер:
bash
Wrap
Copy
source venv/Scripts/activate
uvicorn main:app --reload
Введи номер +380963048847 і натисни "Отримати код".
Перевір:
Чекай 1-2 хвилини на SMS у Telegram.
Перевір вхідні дзвінки на цей номер (Telegram може подзвонити).
Надішли мені нові логи, якщо код не прийшов.
Додаткові дії
Перевір API ключі: Переконайся, що API_ID і API_HASH у server/.env актуальні (отримай нові з https://my.telegram.org, якщо є сумніви).
Спробуй інший номер: Введи інший номер (наприклад, свій особистий), щоб перевірити, чи проблема в конкретному номері.
Код має прийти, але якщо ні — це вже точно проблема на стороні Telegram або номера. Дай знати, що вийшло!






так..і справді прийшов код тільки десь через хвилину.. чи можна там десь нижче про це написати? що чекайте 1-2 хв? потім при відмальовці чатів знов з'явилася помилка , але самі чати відмальовались INFO:     127.0.0.1:56520 - "OPTIONS /chats HTTP/1.1" 200 OK
Отримано запит: GET http://localhost:8000/chats
Заголовки: Headers({'host': 'localhost:8000', 'connection': 'keep-alive', 'pragma': 'no-cache', 'cache-control': 'no-cache', 'sec-ch-ua-platform': '"Android"', 'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MTIzIiwiZXhwIjoxNzQwNzQ3MTM4fQ.8jK3T_-tsh8n8HHqZkpzlZZnmIktC5K8J15lvpUAbqM', 'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36', 'sec-ch-ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"', 'sec-ch-ua-mobile': '?1', 'accept': '*/*', 'origin': 'http://localhost:3000', 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'referer': 'http://localhost:3000/', 'accept-encoding': 'gzip, deflate, br, zstd', 'accept-language': 'uk,en-US;q=0.9,en;q=0.8,uk-UA;q=0.7'})
Перевірка токена: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MTIzIiwiZXhwIjoxNzQwNzQ3MTM4fQ.8jK3T_-tsh8n8HHqZkpzlZZnmIktC5K8J15lvpUAbqM
Декодовано username: test123
2025-02-28 13:53:33,524 INFO sqlalchemy.engine.Engine BEGIN (implicit)
2025-02-28 13:53:33,525 INFO sqlalchemy.engine.Engine SELECT users.id, users.username, users.password_hash, users.telegram_phone
FROM users
WHERE users.username = ?
2025-02-28 13:53:33,525 INFO sqlalchemy.engine.Engine [cached since 111.6s ago] ('test123',)
Користувач знайдений: test123
Помилка в /chats: database is locked
2025-02-28 13:53:39,353 INFO sqlalchemy.engine.Engine ROLLBACK
Відповідь: 500
INFO:     127.0.0.1:56520 - "GET /chats HTTP/1.1" 500 Internal Server Error
Task was destroyed but it is pending!
task: <Task pending name='Task-92' coro=<Connection._send_loop() running at G:\Projects\NextJS\SocialHub\server\venv\Lib\site-packages\telethon\network\connection\connection.py:322> wait_for=<Future pending cb=[Task.task_wakeup()]>>
Task was destroyed but it is pending!
task: <Task pending name='Task-93' coro=<Connection._recv_loop() running at G:\Projects\NextJS\SocialHub\server\venv\Lib\site-packages\telethon\network\connection\connection.py:341> wait_for=<Future pending cb=[Task.task_wakeup()]>>
Task was destroyed but it is pending!
task: <Task pending name='Task-94' coro=<MTProtoSender._send_loop() running at G:\Projects\NextJS\SocialHub\server\venv\Lib\site-packages\telethon\network\mtprotosender.py:464> wait_for=<Future pending cb=[Task.task_wakeup()]>>
Task was destroyed but it is pending!
task: <Task pending name='Task-95' coro=<MTProtoSender._recv_loop() running at G:\Projects\NextJS\SocialHub\server\venv\Lib\site-packages\telethon\network\mtprotosender.py:507> wait_for=<Future pending cb=[Task.task_wakeup()]>>
Exception ignored in: <coroutine object Connection._recv_loop at 0x000001C4775C66B0>
Traceback (most recent call last):
  File "G:\Projects\NextJS\SocialHub\server\venv\Lib\site-packages\telethon\_updates\entitycache.py", line 27, in get
    return Entity(ty, id, hash)
           ^^^^^^^^^^^^^^^^^^^^
RuntimeError: coroutine ignored GeneratorExit
Чати отримано для 1
2025-02-28 13:53:39,793 INFO sqlalchemy.engine.Engine ROLLBACK
Відповідь: 200
INFO:     127.0.0.1:56519 - "GET /chats HTTP/1.1" 200 OK


Чудово, що код нарешті прийшов, хоч і з затримкою! Давай розберемо обидві твої просьби: додамо повідомлення про затримку коду і виправимо проблему з "database is locked" при відмальовці чатів.

Проблема 1: Затримка коду
Логи:

text
Wrap
Copy
Код успішно відправлено для +380963048847, phone_code_hash: a210a608c417d2ed1e
Відповідь: 200
Код приходить через 1-2 хвилини, що нормально для Telegram, якщо сервер перевантажений або номер недавно використовувався. Додамо повідомлення в інтерфейсі, щоб користувач знав, що потрібно зачекати.

Проблема 2: "Database is locked" у /chats
Логи:

text
Wrap
Copy
Помилка в /chats: database is locked
Відповідь: 500
Чати отримано для 1
Відповідь: 200
База блокується через одночасний доступ із /connect-telegram (коміт telegram_phone) і /chats (перевірка telegram_phone).
Клієнт повторює запит до /chats через useEffect, і другий запит проходить успішно.
Додаткові помилки Task was destroyed but it is pending! пов’язані з telethon, коли клієнт закривається до завершення асинхронних задач.
Виправлення:

Збільшимо затримку перед зверненням до бази в /chats.
Додамо коректне очищення сесії Telegram.
Оновлені файли
1. server/main.py
python
Wrap
Copy
import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Body, Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from telethon import TelegramClient
from telethon.errors import FloodWaitError, SessionPasswordNeededError, SessionExpiredError, AuthRestartError
from pydantic import BaseModel
from database import AsyncSessionLocal, engine
from models import Base, User
from dotenv import load_dotenv
from pydantic import ConfigDict
from telethon import types
import asyncio

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
temp_sessions = {}

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TelegramSendCode(BaseModel):
    phone: str

class TelegramConnect(BaseModel):
    code: str
    password: Optional[str] = None
    phone: Optional[str] = None

class TelegramSession(BaseModel):
    phone: str
    phone_code_hash: str
    client: Optional[types.User] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"Отримано запит: {request.method} {request.url}")
    print(f"Заголовки: {request.headers}")
    response = await call_next(request)
    print(f"Відповідь: {response.status_code}")
    return response

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

@app.options("/{path:path}")
async def options_handler():
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    print(f"Перевірка токена: {token}")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        print(f"Декодовано username: {username}")
        if not username:
            raise HTTPException(status_code=401, detail="Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            print(f"Користувача {username} не знайдено в базі")
            raise HTTPException(status_code=401, detail="Користувача не знайдено")

        print(f"Користувач знайдений: {user.username}")
        return user
    except JWTError as e:
        print(f"Помилка JWT: {str(e)}")
        raise HTTPException(status_code=401, detail="Помилка токена")

@app.post("/register", status_code=201)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    if result.scalar():
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    await asyncio.sleep(0.1)
    await db.commit()
    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == user.username))
    db_user = result.scalar()

    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/check-connection")
async def check_connection(current_user: User = Depends(get_current_user)):
    print(f"Перевірка підключення для: {current_user.username}")
    return {"connected": bool(current_user.telegram_phone)}

@app.post("/send-code")
async def send_code(
    data: TelegramSendCode,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Надсилання коду для користувача {current_user.id}")
    print(f"Використовуємо номер: {data.phone}")
    session_path = f"sessions/session_{current_user.id}"

    retries = 2
    for attempt in range(retries):
        try:
            if os.path.exists(session_path):
                os.remove(session_path)
                print(f"Видалено стару сесію: {session_path}")

            if current_user.id in temp_sessions:
                await temp_sessions[current_user.id]["client"].disconnect()
                del temp_sessions[current_user.id]

            client = TelegramClient(session_path, API_ID, API_HASH)
            await client.connect()
            print(f"Клієнт підключено до Telegram, спроба {attempt + 1}")

            sent_code = await client.send_code_request(data.phone)
            print(f"Код успішно відправлено для {data.phone}, phone_code_hash: {sent_code.phone_code_hash}")

            temp_sessions[current_user.id] = {
                "phone": data.phone,
                "phone_code_hash": sent_code.phone_code_hash,
                "client": client
            }
            await asyncio.sleep(2)
            return {"detail": "Код відправлено, перевірте Telegram (SMS або дзвінок) протягом 1-2 хвилин"}
        except AuthRestartError:
            print(f"AuthRestartError на спробі {attempt + 1}, перезапуск авторизації...")
            await client.disconnect()
            await asyncio.sleep(2)
        except FloodWaitError as e:
            raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
        except Exception as e:
            print(f"Помилка в /send-code на спробі {attempt + 1}: {str(e)}")
            if attempt == retries - 1:
                raise HTTPException(400, detail=f"Не вдалося відправити код: {str(e)}")
            await client.disconnect()
            await asyncio.sleep(2)

@app.post("/connect-telegram")
async def connect_telegram(
    auth: TelegramConnect,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    print(f"Спроба підключення Telegram для користувача {current_user.id}")
    try:
        session_data = temp_sessions.get(current_user.id)
        if not session_data or "client" not in session_data:
            raise HTTPException(400, "Спочатку отримайте код")

        client = session_data["client"]
        await client.connect()

        try:
            await client.sign_in(
                phone=session_data["phone"],
                code=auth.code,
                phone_code_hash=session_data["phone_code_hash"]
            )
        except SessionPasswordNeededError:
            if not auth.password:
                raise HTTPException(400, "Потрібен пароль 2FA")
            await client.sign_in(password=auth.password)

        await client.disconnect()
        current_user.telegram_phone = session_data["phone"]
        await asyncio.sleep(0.5)  # Збільшена затримка перед комітом
        await db.commit()
        del temp_sessions[current_user.id]

        print(f"Telegram успішно підключено для {current_user.id}")
        return {"status": "Connected"}
    except SessionPasswordNeededError:
        raise HTTPException(400, "Потрібен пароль 2FA")
    except Exception as e:
        print(f"Помилка в /connect-telegram: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        await asyncio.sleep(1)  # Збільшена затримка для уникнення конфлікту з /connect-telegram
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        print(f"Чати отримано для {current_user.id}")
        return [{"id": d.id, "name": d.name} for d in dialogs]
    except FloodWaitError as e:
        raise HTTPException(status_code=429, detail=f"Зачекайте {e.seconds} секунд")
    except SessionExpiredError:
        raise HTTPException(status_code=400, detail="Сесія закінчилася, підключіться заново")
    except Exception as e:
        print(f"Помилка в /chats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Внутрішня помилка: {str(e)}")

@app.get("/chats/{chat_id}/messages")
async def get_chat_messages(
    chat_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Сесія не авторизована")

        messages = await client.get_messages(chat_id, limit=20)
        await client.disconnect()

        return [{"id": m.id, "text": m.text, "date": m.date.isoformat()} for m in messages]
    except Exception as e:
        print(f"Помилка в /chats/{chat_id}/messages: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/logout-telegram")
async def logout_telegram(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.telegram_phone and os.path.exists(f"sessions/session_{current_user.id}"):
        os.remove(f"sessions/session_{current_user.id}")
    current_user.telegram_phone = None
    await asyncio.sleep(0.1)
    await db.commit()
    print(f"Telegram відключено для {current_user.id}")
    return {"message": "Telegram disconnected"}

@app.post("/logout")
async def logout_system(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out from system"}

@app.get("/health")
async def health_check():
    return {"status": "OK"}
Зміни:

У /send-code повідомлення змінено на "Код відправлено, перевірте Telegram (SMS або дзвінок) протягом 1-2 хвилин".
У /connect-telegram затримка перед db.commit() збільшена до 0.5 секунд.
У /chats затримка перед зверненням до бази збільшена до 1 секунди.
2. client/pages/dashboard.js
Додамо відображення повідомлення про затримку коду після успішного запиту:

javascript
Wrap
Copy
import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Dashboard() {
    const [phone, setPhone] = useState("");
    const [code, setCode] = useState("");
    const [chats, setChats] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [isCodeSent, setIsCodeSent] = useState(false);
    const [error, setError] = useState("");
    const [message, setMessage] = useState(""); // Додано для повідомлень
    const router = useRouter();
    const [twoFactorPassword, setTwoFactorPassword] = useState("");

    useEffect(() => {
        const checkConnection = async () => {
            const token = localStorage.getItem("token");
            console.log("Токен із localStorage:", token);
            if (!token) {
                console.log("Токен відсутній, перенаправлення на /login");
                router.push("/login");
                return;
            }

            try {
                const res = await fetch("http://localhost:8000/check-connection", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 401) {
                    console.log("Токен невалідний, перенаправлення на /login");
                    localStorage.removeItem("token");
                    router.push("/login");
                    return;
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося перевірити підключення");
                }

                const data = await res.json();
                setIsConnected(data.connected);
            } catch (err) {
                setError(err.message);
            }
        };

        checkConnection();
    }, [router]);

    const sendCode = async (e) => {
        e.preventDefault();
        setError("");
        setMessage(""); // Очищаємо попереднє повідомлення

        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/send-code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ phone }),
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.detail || "Помилка відправки коду");
            }

            setIsCodeSent(true);
            setMessage(data.detail); // Показуємо повідомлення від сервера
        } catch (err) {
            setError(err.message);
        }
    };

    const connectTelegram = async (e) => {
        e.preventDefault();
        setError("");
        setMessage("");

        try {
            const token = localStorage.getItem("token");
            if (!token) return router.push("/login");

            const body = { code: code.trim() };
            if (twoFactorPassword) body.password = twoFactorPassword;

            const res = await fetch("http://localhost:8000/connect-telegram", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(body),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Помилка підключення");
            }

            setIsConnected(true);
            await new Promise((resolve) => setTimeout(resolve, 1000));
            await fetchChats();
        } catch (err) {
            setError(err.message);
        }
    };

    const fetchChats = async () => {
        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/chats", {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Не вдалося завантажити чати");
            }

            const data = await res.json();
            setChats(data);
        } catch (err) {
            setError(err.message);
        }
    };

    useEffect(() => {
        if (isConnected) {
            fetchChats();
        }
    }, [isConnected]);

    const handleLogoutTelegram = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://localhost:8000/logout-telegram", {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error("Не вдалося вийти з Telegram");
            setIsConnected(false);
            setIsCodeSent(false);
            setPhone("");
            setCode("");
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6">Панель управління</h1>

            {error && <p className="text-red-500 mb-4">{error}</p>}
            {message && <p className="text-green-500 mb-4">{message}</p>} {/* Додано відображення повідомлення */}

            {!isConnected ? (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4">Підключіть Telegram</h2>

                    {!isCodeSent ? (
                        <form onSubmit={sendCode} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть номер телефону"
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <input
                                type="password"
                                placeholder="Пароль 2FA (якщо потрібно)"
                                value={twoFactorPassword}
                                onChange={(e) => setTwoFactorPassword(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Отримати код
                            </button>
                        </form>
                    ) : (
                        <form onSubmit={connectTelegram} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть код з Telegram"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Підключити
                            </button>
                        </form>
                    )}
                </div>
            ) : (
                <div>
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-xl">Ваші чати</h2>
                        <button
                            onClick={handleLogoutTelegram}
                            className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600"
                        >
                            Змінити акаунт
                        </button>
                    </div>

                    <div className="space-y-4">
                        {chats.map((chat) => (
                            <div
                                key={chat.id}
                                className="p-4 border rounded hover:bg-gray-50"
                            >
                                <Link
                                    href={`/chats/${chat.id}`}
                                    className="text-blue-500 hover:underline"
                                >
                                    {chat.name}
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
Зміни:

Додано стан message і відображення його в зеленому кольорі після sendCode.
Як це працює?
Затримка коду:
Після натискання "Отримати код" ти побачиш повідомлення: "Код відправлено, перевірте Telegram (SMS або дзвінок) протягом 1-2 хвилин".
Це попередить, що код може прийти не одразу.
"Database is locked":
Збільшені затримки в /connect-telegram (0.5 с) і /chats (1 с) мають уникнути конфліктів із базою SQLite.
Якщо помилка все ще з’являється, це може бути через часті запити від клієнта.
Перевірка
Скопіюй оновлені main.py і dashboard.js.
Перезапусти сервер:
bash
Wrap
Copy
source venv/Scripts/activate
uvicorn main:app --reload
Запусти клієнт:
bash
Wrap
Copy
cd client
npm run dev
Спробуй відправити код і підключити Telegram.
Якщо "database is locked" залишиться
Надішли мені нові логи.
Можемо перейти на PostgreSQL замість SQLite, якщо проблема не зникне (SQLite погано працює з асинхронними операціями при високій частоті запитів).
Сподіваюся, тепер усе буде гладко! Дай знати, як спрацювало.






Database is locked все одно з'являється.. а можна щоб вона на фронті не відмальовувалась?) бо мені не можна переходити на іншу базу даних


Добре, якщо "database is locked" все ще з’являється, але чати успішно відмальовуються після повторного запиту, ми можемо приховати цю помилку на фронтенді, щоб користувач її не бачив. Оскільки ти не можеш перейти на іншу базу даних, ми залишимо SQLite і просто обробимо помилку 500 так, щоб фронтенд її ігнорував і чекав успішної відповіді. Давай зробимо це!

План
Сервер: Залишимо як є, бо він уже робить повторні спроби через клієнт.
Фронтенд: Оновимо dashboard.js, щоб:
Ігнорувати помилку 500 і повторювати запит до /chats до успіху.
Не показувати помилку користувачу, якщо вона пов’язана з "database is locked".
Оновлений client/pages/dashboard.js
Ось повний код із виправленнями:

javascript
Wrap
Copy
import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Dashboard() {
    const [phone, setPhone] = useState("");
    const [code, setCode] = useState("");
    const [chats, setChats] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [isCodeSent, setIsCodeSent] = useState(false);
    const [error, setError] = useState("");
    const [message, setMessage] = useState("");
    const router = useRouter();
    const [twoFactorPassword, setTwoFactorPassword] = useState("");

    useEffect(() => {
        const checkConnection = async () => {
            const token = localStorage.getItem("token");
            console.log("Токен із localStorage:", token);
            if (!token) {
                console.log("Токен відсутній, перенаправлення на /login");
                router.push("/login");
                return;
            }

            try {
                const res = await fetch("http://localhost:8000/check-connection", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 401) {
                    console.log("Токен невалідний, перенаправлення на /login");
                    localStorage.removeItem("token");
                    router.push("/login");
                    return;
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося перевірити підключення");
                }

                const data = await res.json();
                setIsConnected(data.connected);
            } catch (err) {
                setError(err.message);
            }
        };

        checkConnection();
    }, [router]);

    const sendCode = async (e) => {
        e.preventDefault();
        setError("");
        setMessage("");

        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/send-code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ phone }),
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.detail || "Помилка відправки коду");
            }

            setIsCodeSent(true);
            setMessage(data.detail);
        } catch (err) {
            setError(err.message);
        }
    };

    const connectTelegram = async (e) => {
        e.preventDefault();
        setError("");
        setMessage("");

        try {
            const token = localStorage.getItem("token");
            if (!token) return router.push("/login");

            const body = { code: code.trim() };
            if (twoFactorPassword) body.password = twoFactorPassword;

            const res = await fetch("http://localhost:8000/connect-telegram", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(body),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Помилка підключення");
            }

            setIsConnected(true);
            await new Promise((resolve) => setTimeout(resolve, 1000));
            await fetchChats();
        } catch (err) {
            setError(err.message);
        }
    };

    const fetchChats = async (retries = 3) => {
        const token = localStorage.getItem("token");
        if (!token) {
            router.push("/login");
            return;
        }

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const res = await fetch("http://localhost:8000/chats", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 500) {
                    console.log(`Спроба ${attempt + 1}: Помилка 500, повтор через 1 секунду...`);
                    if (attempt < retries - 1) {
                        await new Promise((resolve) => setTimeout(resolve, 1000));
                        continue; // Повторюємо запит, якщо не остання спроба
                    }
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося завантажити чати");
                }

                const data = await res.json();
                setChats(data);
                break; // Успіх, виходимо з циклу
            } catch (err) {
                if (attempt === retries - 1) {
                    setError(err.message); // Показуємо помилку тільки після всіх спроб
                }
            }
        }
    };

    useEffect(() => {
        if (isConnected) {
            fetchChats();
        }
    }, [isConnected]);

    const handleLogoutTelegram = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://localhost:8000/logout-telegram", {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error("Не вдалося вийти з Telegram");
            setIsConnected(false);
            setIsCodeSent(false);
            setPhone("");
            setCode("");
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6">Панель управління</h1>

            {error && <p className="text-red-500 mb-4">{error}</p>}
            {message && <p className="text-green-500 mb-4">{message}</p>}

            {!isConnected ? (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4">Підключіть Telegram</h2>

                    {!isCodeSent ? (
                        <form onSubmit={sendCode} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть номер телефону"
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <input
                                type="password"
                                placeholder="Пароль 2FA (якщо потрібно)"
                                value={twoFactorPassword}
                                onChange={(e) => setTwoFactorPassword(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Отримати код
                            </button>
                        </form>
                    ) : (
                        <form onSubmit={connectTelegram} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть код з Telegram"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                className="w-full p-2 border rounded"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600"
                            >
                                Підключити
                            </button>
                        </form>
                    )}
                </div>
            ) : (
                <div>
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-xl">Ваші чати</h2>
                        <button
                            onClick={handleLogoutTelegram}
                            className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600"
                        >
                            Змінити акаунт
                        </button>
                    </div>

                    <div className="space-y-4">
                        {chats.map((chat) => (
                            <div
                                key={chat.id}
                                className="p-4 border rounded hover:bg-gray-50"
                            >
                                <Link
                                    href={`/chats/${chat.id}`}
                                    className="text-blue-500 hover:underline"
                                >
                                    {chat.name}
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
Зміни
Функція fetchChats:
Додано цикл із 3 спробами для запиту до /chats.
Якщо отримуємо 500 (наприклад, "database is locked"), чекаємо 1 секунду і повторюємо запит.
Помилка відображається (setError) тільки після всіх невдалих спроб.
Логи в консолі показують спроби, але користувач цього не бачить.
Логіка:
Помилка 500 більше не з’являтиметься в інтерфейсі, якщо чати завантажуються з повторного запиту.
Як це працює?
Після підключення Telegram (setIsConnected(true)), fetchChats викликається через useEffect.
Якщо сервер повертає 500 через "database is locked", клієнт тихо чекає і повторює запит.
Помилка не відображається користувачу, доки всі 3 спроби не проваляться (чого не має статися, бо другий запит зазвичай успішний).
Перевірка
Скопіюй цей код у client/pages/dashboard.js.
Перезапусти клієнт:
bash
Wrap
Copy
cd client
npm run dev
Переконайся, що сервер запущено:
bash
Wrap
Copy
cd server
source venv/Scripts/activate
uvicorn main:app --reload
Підключи Telegram і перевір, чи:
Код приходить із повідомленням про 1-2 хвилини.
Чати відмальовуються без помилки "database is locked" на екрані.
Результат
Повідомлення про затримку коду буде видно.
Помилка "database is locked" залишиться в логах сервера, але не з’явиться на фронтенді, а чати все одно завантажаться.
Дай знати, чи все ок, чи потрібні ще правки!






Так, все добре) чи можеш ти трошки стилизувати картки чатів і повідомлень в чатах? під загальний дизайн


Чудово, що все працює! Давай додамо трохи стилів до карток чатів у dashboard.js і повідомлень у chats.js, щоб вони гармоніювали із загальним дизайном (я припускаю, що твій дизайн — це чистий, сучасний стиль із білим фоном, зеленими акцентами та сірими межами, судячи по формах). Я зроблю їх у такому ж дусі.

Оновлені файли
1. client/pages/dashboard.js (Картки чатів)
Оновимо стилі для карток чатів:

javascript
Wrap
Copy
import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Dashboard() {
    const [phone, setPhone] = useState("");
    const [code, setCode] = useState("");
    const [chats, setChats] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [isCodeSent, setIsCodeSent] = useState(false);
    const [error, setError] = useState("");
    const [message, setMessage] = useState("");
    const router = useRouter();
    const [twoFactorPassword, setTwoFactorPassword] = useState("");

    useEffect(() => {
        const checkConnection = async () => {
            const token = localStorage.getItem("token");
            console.log("Токен із localStorage:", token);
            if (!token) {
                console.log("Токен відсутній, перенаправлення на /login");
                router.push("/login");
                return;
            }

            try {
                const res = await fetch("http://localhost:8000/check-connection", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 401) {
                    console.log("Токен невалідний, перенаправлення на /login");
                    localStorage.removeItem("token");
                    router.push("/login");
                    return;
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося перевірити підключення");
                }

                const data = await res.json();
                setIsConnected(data.connected);
            } catch (err) {
                setError(err.message);
            }
        };

        checkConnection();
    }, [router]);

    const sendCode = async (e) => {
        e.preventDefault();
        setError("");
        setMessage("");

        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/send-code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ phone }),
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.detail || "Помилка відправки коду");
            }

            setIsCodeSent(true);
            setMessage(data.detail);
        } catch (err) {
            setError(err.message);
        }
    };

    const connectTelegram = async (e) => {
        e.preventDefault();
        setError("");
        setMessage("");

        try {
            const token = localStorage.getItem("token");
            if (!token) return router.push("/login");

            const body = { code: code.trim() };
            if (twoFactorPassword) body.password = twoFactorPassword;

            const res = await fetch("http://localhost:8000/connect-telegram", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(body),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Помилка підключення");
            }

            setIsConnected(true);
            await new Promise((resolve) => setTimeout(resolve, 1000));
            await fetchChats();
        } catch (err) {
            setError(err.message);
        }
    };

    const fetchChats = async (retries = 3) => {
        const token = localStorage.getItem("token");
        if (!token) {
            router.push("/login");
            return;
        }

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const res = await fetch("http://localhost:8000/chats", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 500) {
                    console.log(`Спроба ${attempt + 1}: Помилка 500, повтор через 1 секунду...`);
                    if (attempt < retries - 1) {
                        await new Promise((resolve) => setTimeout(resolve, 1000));
                        continue;
                    }
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося завантажити чати");
                }

                const data = await res.json();
                setChats(data);
                break;
            } catch (err) {
                if (attempt === retries - 1) {
                    setError(err.message);
                }
            }
        }
    };

    useEffect(() => {
        if (isConnected) {
            fetchChats();
        }
    }, [isConnected]);

    const handleLogoutTelegram = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://localhost:8000/logout-telegram", {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error("Не вдалося вийти з Telegram");
            setIsConnected(false);
            setIsCodeSent(false);
            setPhone("");
            setCode("");
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6 text-gray-800">Панель управління</h1>

            {error && <p className="text-red-500 mb-4">{error}</p>}
            {message && <p className="text-green-500 mb-4">{message}</p>}

            {!isConnected ? (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4 text-gray-700">Підключіть Telegram</h2>

                    {!isCodeSent ? (
                        <form onSubmit={sendCode} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть номер телефону"
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-green-500"
                            />
                            <input
                                type="password"
                                placeholder="Пароль 2FA (якщо потрібно)"
                                value={twoFactorPassword}
                                onChange={(e) => setTwoFactorPassword(e.target.value)}
                                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-green-500"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600 transition-colors"
                            >
                                Отримати код
                            </button>
                        </form>
                    ) : (
                        <form onSubmit={connectTelegram} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть код з Telegram"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-green-500"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600 transition-colors"
                            >
                                Підключити
                            </button>
                        </form>
                    )}
                </div>
            ) : (
                <div>
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-xl text-gray-700">Ваші чати</h2>
                        <button
                            onClick={handleLogoutTelegram}
                            className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600 transition-colors"
                        >
                            Змінити акаунт
                        </button>
                    </div>

                    <div className="space-y-4">
                        {chats.map((chat) => (
                            <div
                                key={chat.id}
                                className="bg-white p-4 rounded-lg shadow-md hover:shadow-lg transition-shadow border border-gray-200"
                            >
                                <Link
                                    href={`/chats/${chat.id}`}
                                    className="text-green-600 hover:text-green-700 font-medium transition-colors"
                                >
                                    {chat.name}
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
Стилі для карток чатів:

bg-white p-4 rounded-lg shadow-md: Білий фон, відступи, заокруглені кути, легка тінь.
hover:shadow-lg transition-shadow: Тінь збільшується при наведенні.
border border-gray-200: Тонка сіра межа.
text-green-600 hover:text-green-700 font-medium: Зелений колір тексту, темніший при наведенні, середня жирність.
2. client/pages/chats.js (Повідомлення в чатах)
Оновимо стилі для карток повідомлень:

javascript
Wrap
Copy
import { useState, useEffect } from "react";
import { useRouter } from "next/router";

export default function Chats() {
    const [chats, setChats] = useState([]);
    const [error, setError] = useState("");
    const router = useRouter();

    useEffect(() => {
        const fetchChats = async () => {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            try {
                const res = await fetch("http://localhost:8000/chats", {
                    headers: { Authorization: `Bearer ${token}` },
                });
                if (!res.ok) throw new Error("Не вдалося завантажити чати");
                const data = await res.json();
                setChats(data);
            } catch (err) {
                setError(err.message);
            }
        };
        fetchChats();
    }, [router]);

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6 text-gray-800">Ваші чати</h1>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            <div className="space-y-4">
                {chats.map((chat) => (
                    <div
                        key={chat.id}
                        className="bg-white p-4 rounded-lg shadow-md border border-gray-200 hover:shadow-lg transition-shadow"
                    >
                        <p className="text-gray-700 font-medium">{chat.name}</p>
                    </div>
                ))}
            </div>
        </div>
    );
}
Стилі для карток чатів у chats.js:

Такі ж, як у dashboard.js, для консистентності:
bg-white p-4 rounded-lg shadow-md border border-gray-200: Білий фон, відступи, тінь, межа.
hover:shadow-lg transition-shadow: Тінь при наведенні.
text-gray-700 font-medium: Темно-сірий текст, середня жирність.
Як це виглядає?
Картки чатів: Білі прямокутники з легкою тінню, сірою межею, які стають більш виразними при наведенні. Назви чатів — зелені (у dashboard.js) або темно-сірі (у chats.js).
Загальний дизайн: Чистий, сучасний, із зеленими акцентами (кнопки, повідомлення про успіх), що відповідає твоїй формі підключення.
Перевірка
Скопіюй оновлені dashboard.js і chats.js у client/pages/.
Перезапусти клієнт:
bash
Wrap
Copy
cd client
npm run dev
Перевір, чи картки чатів виглядають стильно і відповідають дизайну.
Якщо потрібні зміни
Якщо хочеш інші кольори чи стиль (наприклад, більше зеленого, інший шрифт), скажи — я швидко підлаштую! 😊 Все має виглядати гармонійно.






Оновимо стилі для карток повідомлень - щось нічого не змінилося.. классно було б якось в стилі мінімалізму.. і ще можна було б щоб коли відкриваєш повідомлення була кнопка повернуться до чатів


Ти права, я помилився — у попередньому коді я оновив стилі для карток чатів у chats.js, а не для повідомлень, бо у твоєму прикладі chats.js показував список чатів, а не повідомлення. Давай виправимо це: додамо сторінку для повідомлень (наприклад, chats/[chat_id].js) із мінімалістичним стилем і кнопкою "Повернутися до чатів". Також оновимо стилі для карток чатів у dashboard.js і chats.js, щоб вони були в стилі мінімалізму.

Оновлені файли
1. client/pages/dashboard.js (Картки чатів)
Оновимо стилі для мінімалізму:

javascript
Wrap
Copy
import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Dashboard() {
    const [phone, setPhone] = useState("");
    const [code, setCode] = useState("");
    const [chats, setChats] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [isCodeSent, setIsCodeSent] = useState(false);
    const [error, setError] = useState("");
    const [message, setMessage] = useState("");
    const router = useRouter();
    const [twoFactorPassword, setTwoFactorPassword] = useState("");

    useEffect(() => {
        const checkConnection = async () => {
            const token = localStorage.getItem("token");
            console.log("Токен із localStorage:", token);
            if (!token) {
                console.log("Токен відсутній, перенаправлення на /login");
                router.push("/login");
                return;
            }

            try {
                const res = await fetch("http://localhost:8000/check-connection", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 401) {
                    console.log("Токен невалідний, перенаправлення на /login");
                    localStorage.removeItem("token");
                    router.push("/login");
                    return;
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося перевірити підключення");
                }

                const data = await res.json();
                setIsConnected(data.connected);
            } catch (err) {
                setError(err.message);
            }
        };

        checkConnection();
    }, [router]);

    const sendCode = async (e) => {
        e.preventDefault();
        setError("");
        setMessage("");

        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/send-code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ phone }),
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.detail || "Помилка відправки коду");
            }

            setIsCodeSent(true);
            setMessage(data.detail);
        } catch (err) {
            setError(err.message);
        }
    };

    const connectTelegram = async (e) => {
        e.preventDefault();
        setError("");
        setMessage("");

        try {
            const token = localStorage.getItem("token");
            if (!token) return router.push("/login");

            const body = { code: code.trim() };
            if (twoFactorPassword) body.password = twoFactorPassword;

            const res = await fetch("http://localhost:8000/connect-telegram", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(body),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Помилка підключення");
            }

            setIsConnected(true);
            await new Promise((resolve) => setTimeout(resolve, 1000));
            await fetchChats();
        } catch (err) {
            setError(err.message);
        }
    };

    const fetchChats = async (retries = 3) => {
        const token = localStorage.getItem("token");
        if (!token) {
            router.push("/login");
            return;
        }

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const res = await fetch("http://localhost:8000/chats", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 500) {
                    console.log(`Спроба ${attempt + 1}: Помилка 500, повтор через 1 секунду...`);
                    if (attempt < retries - 1) {
                        await new Promise((resolve) => setTimeout(resolve, 1000));
                        continue;
                    }
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося завантажити чати");
                }

                const data = await res.json();
                setChats(data);
                break;
            } catch (err) {
                if (attempt === retries - 1) {
                    setError(err.message);
                }
            }
        }
    };

    useEffect(() => {
        if (isConnected) {
            fetchChats();
        }
    }, [isConnected]);

    const handleLogoutTelegram = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://localhost:8000/logout-telegram", {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error("Не вдалося вийти з Telegram");
            setIsConnected(false);
            setIsCodeSent(false);
            setPhone("");
            setCode("");
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6 text-gray-800">Панель управління</h1>

            {error && <p className="text-red-500 mb-4">{error}</p>}
            {message && <p className="text-green-500 mb-4">{message}</p>}

            {!isConnected ? (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4 text-gray-700">Підключіть Telegram</h2>

                    {!isCodeSent ? (
                        <form onSubmit={sendCode} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть номер телефону"
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-green-500"
                            />
                            <input
                                type="password"
                                placeholder="Пароль 2FA (якщо потрібно)"
                                value={twoFactorPassword}
                                onChange={(e) => setTwoFactorPassword(e.target.value)}
                                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-green-500"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600 transition-colors"
                            >
                                Отримати код
                            </button>
                        </form>
                    ) : (
                        <form onSubmit={connectTelegram} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть код з Telegram"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-green-500"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600 transition-colors"
                            >
                                Підключити
                            </button>
                        </form>
                    )}
                </div>
            ) : (
                <div>
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-xl text-gray-700">Ваші чати</h2>
                        <button
                            onClick={handleLogoutTelegram}
                            className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600 transition-colors"
                        >
                            Змінити акаунт
                        </button>
                    </div>

                    <div className="space-y-3">
                        {chats.map((chat) => (
                            <div
                                key={chat.id}
                                className="bg-white p-3 rounded-md border-b border-gray-200 hover:bg-gray-50 transition-colors"
                            >
                                <Link
                                    href={`/chats/${chat.id}`}
                                    className="text-gray-800 hover:text-green-600 font-medium transition-colors"
                                >
                                    {chat.name}
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
Стилі для карток чатів (мінімалізм):

bg-white p-3 rounded-md border-b border-gray-200: Білий фон, легкий відступ, заокруглені кути, тонка нижня межа.
hover:bg-gray-50 transition-colors: Ледь помітний сірий фон при наведенні.
text-gray-800 hover:text-green-600 font-medium: Темно-сірий текст, зелений при наведенні.
2. client/pages/chats/[chat_id].js (Повідомлення в чаті)
Створимо нову сторінку для повідомлень із мінімалістичним стилем і кнопкою "Повернутися":

javascript
Wrap
Copy
import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function ChatMessages() {
    const [messages, setMessages] = useState([]);
    const [error, setError] = useState("");
    const router = useRouter();
    const { chat_id } = router.query;

    useEffect(() => {
        const fetchMessages = async () => {
            const token = localStorage.getItem("token");
            if (!token || !chat_id) {
                router.push("/login");
                return;
            }

            try {
                const res = await fetch(`http://localhost:8000/chats/${chat_id}/messages`, {
                    headers: { Authorization: `Bearer ${token}` },
                });
                if (!res.ok) throw new Error("Не вдалося завантажити повідомлення");
                const data = await res.json();
                setMessages(data);
            } catch (err) {
                setError(err.message);
            }
        };

        if (chat_id) {
            fetchMessages();
        }
    }, [chat_id, router]);

    return (
        <div className="max-w-4xl mx-auto p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold text-gray-800">Повідомлення</h1>
                <Link
                    href="/dashboard"
                    className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 transition-colors"
                >
                    Повернутися до чатів
                </Link>
            </div>

            {error && <p className="text-red-500 mb-4">{error}</p>}

            <div className="space-y-3">
                {messages.map((message) => (
                    <div
                        key={message.id}
                        className="bg-white p-3 rounded-md border-b border-gray-200 text-gray-700"
                    >
                        <p className="text-sm">{message.text}</p>
                        <p className="text-xs text-gray-500 mt-1">{new Date(message.date).toLocaleString()}</p>
                    </div>
                ))}
            </div>
        </div>
    );
}
Стилі для карток повідомлень (мінімалізм):

bg-white p-3 rounded-md border-b border-gray-200: Білий фон, відступи, тонка нижня межа.
text-gray-700: Темно-сірий текст для контенту.
text-sm і text-xs text-gray-500: Менший розмір для тексту і дати, світло-сірий для дати.
Кнопка "Повернутися":

bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600: Зелений фон, білий текст, ефект при наведенні.
Як це виглядає?
Чати: Прості білі картки з нижньою межею, без зайвих тіней, із плавним переходом кольору при наведенні.
Повідомлення: Такі ж мінімалістичні картки, із текстом і датою в компактному форматі.
Кнопка: Зелена, у стилі решти кнопок, розміщена праворуч від заголовка.
Перевірка
Скопіюй оновлений dashboard.js у client/pages/.
Створи файл client/pages/chats/[chat_id].js і встав код вище.
Перезапусти клієнт:
bash
Wrap
Copy
cd client
npm run dev
Перейди до чатів із dashboard (клікни на назву чату) і перевір стилі та кнопку.
Якщо потрібні зміни
Хочеш інший колір (наприклад, більше зеленого чи сірого)? Скажи!
Потрібен інший розмір шрифту чи відступи? Дай знати, я адаптую.
Сподіваюся, це додасть твому дизайну мінімалістичної елегантності! 😊






нажаль в мене VM1460 dashboard.js:78


           POST http://localhost:8000/send-code 429 (Too Many Requests) зачекайте 25532 секунд.. це скільки?


Ой, помилка 429 Too Many Requests із повідомленням "Зачекайте 25532 секунд" означає, що Telegram наклав обмеження на запити з твого API_ID і API_HASH через надто часті спроби надсилання коду. Давай розберемо, що це означає і як із цим впоратися.

Що сталося?
Код 429: Telegram повертає цей статус, коли ти перевищила ліміт запитів (FloodWaitError).
25532 секунди: Це час очікування в секундах, який Telegram просить зачекати перед наступною спробою. Якщо перевести:
25532 ÷ 60 = 425 хвилин ≈ 7 годин.
Ти не зможеш відправляти нові коди на цей номер із цього API_ID протягом 7 годин.
Чому так?

Telegram має суворі обмеження на кількість запитів для авторизації (наприклад, send_code_request), щоб запобігти спаму.
Ми багато разів тестували /send-code, і це перевищило ліміт.
Як це виправити?
Оскільки це обмеження від Telegram, ми не можемо його обійти прямо зараз із поточним API_ID і номером телефону. Але є кілька варіантів:

1. Зачекати 7 годин
Просто почекай 7 годин (до ~20:00 за твоїм часом, якщо помилка сталася о 13:00 28 лютого 2025). Після цього обмеження зніметься автоматично.
2. Використати інший номер телефону
Спробуй інший номер (наприклад, +380... іншого телефону) із тим же API_ID. Обмеження прив’язане до комбінації номера і API, тож новий номер може спрацювати.
3. Отримати нові API_ID і API_HASH
Зайди на https://my.telegram.org, увійди з іншого номера, створи новий додаток і отримай нові API_ID та API_HASH. Онови їх у server/.env:
text
Wrap
Copy
API_ID=новий_api_id
API_HASH=новий_api_hash
JWT_SECRET=your_secret_key_here
Перезапусти сервер:
bash
Wrap
Copy
source venv/Scripts/activate
uvicorn main:app --reload
4. Зменшити частоту запитів (для майбутнього)
Щоб уникнути цього надалі, додамо ліміт на повторні запити в /send-code. Оновлю dashboard.js, щоб показувати користувачу час очікування і блокувати кнопку.

Оновлений client/pages/dashboard.js
Ось код із обробкою 429 і мінімалістичними стилями:

javascript
Wrap
Copy
import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Dashboard() {
    const [phone, setPhone] = useState("");
    const [code, setCode] = useState("");
    const [chats, setChats] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [isCodeSent, setIsCodeSent] = useState(false);
    const [error, setError] = useState("");
    const [message, setMessage] = useState("");
    const [isCodeDisabled, setIsCodeDisabled] = useState(false); // Додано для блокування кнопки
    const [waitTime, setWaitTime] = useState(0); // Час очікування
    const router = useRouter();
    const [twoFactorPassword, setTwoFactorPassword] = useState("");

    useEffect(() => {
        const checkConnection = async () => {
            const token = localStorage.getItem("token");
            console.log("Токен із localStorage:", token);
            if (!token) {
                console.log("Токен відсутній, перенаправлення на /login");
                router.push("/login");
                return;
            }

            try {
                const res = await fetch("http://localhost:8000/check-connection", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 401) {
                    console.log("Токен невалідний, перенаправлення на /login");
                    localStorage.removeItem("token");
                    router.push("/login");
                    return;
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося перевірити підключення");
                }

                const data = await res.json();
                setIsConnected(data.connected);
            } catch (err) {
                setError(err.message);
            }
        };

        checkConnection();
    }, [router]);

    useEffect(() => {
        if (waitTime > 0) {
            const timer = setInterval(() => {
                setWaitTime((prev) => {
                    if (prev <= 1) {
                        setIsCodeDisabled(false);
                        return 0;
                    }
                    return prev - 1;
                });
            }, 1000);
            return () => clearInterval(timer);
        }
    }, [waitTime]);

    const sendCode = async (e) => {
        e.preventDefault();
        setError("");
        setMessage("");

        try {
            const token = localStorage.getItem("token");
            if (!token) {
                router.push("/login");
                return;
            }

            const res = await fetch("http://localhost:8000/send-code", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ phone }),
            });

            const data = await res.json();
            if (!res.ok) {
                if (res.status === 429) {
                    const waitSeconds = parseInt(data.detail.match(/\d+/)[0], 10);
                    setWaitTime(waitSeconds);
                    setIsCodeDisabled(true);
                    throw new Error(`Зачекайте ${Math.ceil(waitSeconds / 60)} хвилин`);
                }
                throw new Error(data.detail || "Помилка відправки коду");
            }

            setIsCodeSent(true);
            setMessage(data.detail);
        } catch (err) {
            setError(err.message);
        }
    };

    const connectTelegram = async (e) => {
        e.preventDefault();
        setError("");
        setMessage("");

        try {
            const token = localStorage.getItem("token");
            if (!token) return router.push("/login");

            const body = { code: code.trim() };
            if (twoFactorPassword) body.password = twoFactorPassword;

            const res = await fetch("http://localhost:8000/connect-telegram", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(body),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Помилка підключення");
            }

            setIsConnected(true);
            await new Promise((resolve) => setTimeout(resolve, 1000));
            await fetchChats();
        } catch (err) {
            setError(err.message);
        }
    };

    const fetchChats = async (retries = 3) => {
        const token = localStorage.getItem("token");
        if (!token) {
            router.push("/login");
            return;
        }

        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                const res = await fetch("http://localhost:8000/chats", {
                    headers: { Authorization: `Bearer ${token}` },
                });

                if (res.status === 500) {
                    console.log(`Спроба ${attempt + 1}: Помилка 500, повтор через 1 секунду...`);
                    if (attempt < retries - 1) {
                        await new Promise((resolve) => setTimeout(resolve, 1000));
                        continue;
                    }
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || "Не вдалося завантажити чати");
                }

                const data = await res.json();
                setChats(data);
                break;
            } catch (err) {
                if (attempt === retries - 1) {
                    setError(err.message);
                }
            }
        }
    };

    useEffect(() => {
        if (isConnected) {
            fetchChats();
        }
    }, [isConnected]);

    const handleLogoutTelegram = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://localhost:8000/logout-telegram", {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error("Не вдалося вийти з Telegram");
            setIsConnected(false);
            setIsCodeSent(false);
            setPhone("");
            setCode("");
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6 text-gray-800">Панель управління</h1>

            {error && <p className="text-red-500 mb-4">{error}</p>}
            {message && <p className="text-green-500 mb-4">{message}</p>}

            {!isConnected ? (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4 text-gray-700">Підключіть Telegram</h2>

                    {!isCodeSent ? (
                        <form onSubmit={sendCode} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть номер телефону"
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-green-500"
                            />
                            <input
                                type="password"
                                placeholder="Пароль 2FA (якщо потрібно)"
                                value={twoFactorPassword}
                                onChange={(e) => setTwoFactorPassword(e.target.value)}
                                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-green-500"
                            />
                            <button
                                type="submit"
                                disabled={isCodeDisabled}
                                className={`w-full p-2 rounded transition-colors ${
                                    isCodeDisabled
                                        ? "bg-gray-400 text-white cursor-not-allowed"
                                        : "bg-green-500 text-white hover:bg-green-600"
                                }`}
                            >
                                {isCodeDisabled
                                    ? `Зачекайте ${Math.ceil(waitTime / 60)} хв`
                                    : "Отримати код"}
                            </button>
                        </form>
                    ) : (
                        <form onSubmit={connectTelegram} className="space-y-4">
                            <input
                                type="text"
                                placeholder="Введіть код з Telegram"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                className="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-green-500"
                            />
                            <button
                                type="submit"
                                className="w-full bg-green-500 text-white p-2 rounded hover:bg-green-600 transition-colors"
                            >
                                Підключити
                            </button>
                        </form>
                    )}
                </div>
            ) : (
                <div>
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-xl text-gray-700">Ваші чати</h2>
                        <button
                            onClick={handleLogoutTelegram}
                            className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600 transition-colors"
                        >
                            Змінити акаунт
                        </button>
                    </div>

                    <div className="space-y-3">
                        {chats.map((chat) => (
                            <div
                                key={chat.id}
                                className="bg-white p-3 rounded-md border-b border-gray-200 hover:bg-gray-50 transition-colors"
                            >
                                <Link
                                    href={`/chats/${chat.id}`}
                                    className="text-gray-800 hover:text-green-600 font-medium transition-colors"
                                >
                                    {chat.name}
                                </Link>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
Зміни
Обробка 429:
Додано стан isCodeDisabled і waitTime.
Якщо сервер повертає 429, витягуємо кількість секунд із data.detail (наприклад, 25532), переводимо в хвилини і блокуємо кнопку.
Кнопка стає сірою (bg-gray-400) і показує час очікування (наприклад, "Зачекайте 425 хв").
Таймер оновлює waitTime щосекунди, поки не дійде до 0, тоді кнопка розблоковується.
Стилі: Залишив мінімалістичні стилі для чатів із попереднього коду.
Що робити зараз?
Чекати: Ти вже отримала 429, тож із номером +380963048847 і поточним API_ID код не відправиться до ~20:00 сьогодні (28 лютого 2025). Можеш просто протестувати пізніше.
Новий номер: Спробуй інший номер телефону прямо зараз із цим кодом.
Нові API ключі: Отримай нові API_ID і API_HASH на https://my.telegram.org і онови server/.env.
Скопіюй цей код у client/pages/dashboard.js, перезапусти клієнт:

bash
Wrap
Copy
cd client
npm run dev
Спробуй із новим номером, і якщо буде 429, ти побачиш повідомлення типу "Зачекайте X хвилин" замість помилки.

Скільки це — 25532 секунди?
25532 ÷ 60 = 425 хвилин ≈ 7 годин. Тобі просто попався довгий ліміт через часті тести.
Дай знати, якщо хочеш щось ще підправити чи спробувати інший підхід!






Це я спробую трохи пізніше. А тепер давай перейдемо до того як мені зробити щоб я могла скинути ссилку на репозиторій і людина прочитавши інструкцію в ред мі змогла у себе запустити цей проект?


Чудово, давай підготуємо твій репозиторій так, щоб будь-хто міг його клонувати, прочитати інструкцію в README.md і запустити проєкт на своїй машині. Оскільки у тебе клієнт (Next.js) і сервер (FastAPI) в одному репозиторії, ми організуємо все чітко і додамо детальну інструкцію.

Крок 1: Організація структури репозиторію
Припускаю, що твій репозиторій виглядає так:

text
Wrap
Copy
your-repo/
├── client/
│   ├── pages/
│   │   ├── dashboard.js
│   │   ├── chats/[chat_id].js
│   │   └── ... (інші файли)
│   ├── package.json
│   └── ... (інші файли Next.js)
├── server/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── .env  (не додаємо до git)
│   ├── .env.example
│   └── ... (інші файли)
├── .gitignore
└── README.md
Якщо структура інша, напиши, і я адаптую інструкцію.

Крок 2: Перевірка залежностей
Клієнт (client/package.json): Переконайся, що у package.json є всі потрібні залежності. Якщо ти додавала щось вручну, онови:
bash
Wrap
Copy
cd client
npm install
Твій package.json має виглядати приблизно так:
json
Wrap
Copy
{
  "name": "socialhub-client",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start"
  },
  "dependencies": {
    "next": "latest",
    "react": "latest",
    "react-dom": "latest"
  }
}
Сервер (server/requirements.txt): Створи або онови requirements.txt:
bash
Wrap
Copy
cd server
pip freeze > requirements.txt
Переконайся, що там є:
text
Wrap
Copy
fastapi
uvicorn
sqlalchemy
aiosqlite
telethon
python-jose[cryptography]
passlib[bcrypt]
python-dotenv
Крок 3: Налаштування .gitignore
Переконайся, що .gitignore у корені репозиторію виключає чутливі файли:

text
Wrap
Copy
# Віртуальні оточення
venv/
.env

# Локальні бази даних
*.db

# Node.js
node_modules/
.next/

# Інше
__pycache__/
*.pyc
Крок 4: Створення .env.example
У папці server/ створи файл server/.env.example із шаблоном:

text
Wrap
Copy
API_ID=your_telegram_api_id
API_HASH=your_telegram_api_hash
JWT_SECRET=your_secret_key_here
Крок 5: Написання README.md
У корені репозиторію створи або онови README.md із докладною інструкцією:

markdown
Wrap
Copy
# SocialHub

Проєкт для підключення до Telegram через веб-інтерфейс, перегляду чатів і повідомлень. Складається з клієнта на Next.js і сервера на FastAPI.

## Структура
- `client/` - фронтенд (Next.js)
- `server/` - бекенд (FastAPI)

## Вимоги
- **Node.js**: v16 або новіше (https://nodejs.org/)
- **Python**: 3.9+ (https://www.python.org/)
- **Git**: для клонування репозиторію (https://git-scm.com/)

## Налаштування та запуск

### 1. Клонуйте репозиторій
```bash
git clone https://github.com/your-username/your-repo.git
cd your-repo
2. Налаштуйте сервер
Перейдіть до папки сервера:
bash
Wrap
Copy
cd server
Створіть віртуальне оточення та активуйте його:
Linux/Mac:
bash
Wrap
Copy
python3 -m venv venv
source venv/bin/activate
Windows (CMD):
bash
Wrap
Copy
python -m venv venv
venv\Scripts\activate
Windows (Git Bash):
bash
Wrap
Copy
python -m venv venv
source venv/Scripts/activate
Встановіть залежності:
bash
Wrap
Copy
pip install -r requirements.txt
Скопіюйте server/.env.example у server/.env і заповніть:
bash
Wrap
Copy
cp .env.example .env
API_ID і API_HASH: отримайте на https://my.telegram.org.
JWT_SECRET: введіть будь-який секретний ключ (наприклад, "mysecretkey123").
3. Налаштуйте клієнт
Перейдіть до папки клієнта:
bash
Wrap
Copy
cd ../client
Встановіть залежності:
bash
Wrap
Copy
npm install
4. Запустіть проєкт
Запустіть сервер (із папки server):
У новому терміналі:
bash
Wrap
Copy
cd server
source venv/bin/activate  # або venv\Scripts\activate для Windows
uvicorn main:app --reload
Запустіть клієнт (із папки client):
У іншому терміналі:
bash
Wrap
Copy
cd client
npm run dev
5. Використання
Відкрийте браузер на http://localhost:3000.
Зареєструйтесь, увійдіть і підключіть Telegram за допомогою номера телефону.
Переглядайте чати та повідомлення.
Нотатки
База даних: Використовується SQLite (socialhub.db). Для кращої продуктивності можна замінити на PostgreSQL, але це не обов’язково.
Обмеження Telegram: Якщо отримаєте помилку "429 Too Many Requests", зачекайте вказаний час або використайте інший номер телефону чи нові API_ID/API_HASH.
Порти: Сервер працює на http://localhost:8000, клієнт — на http://localhost:3000.
Вирішення проблем
Якщо сервер не запускається: перевірте, чи встановлені всі залежності (requirements.txt) і чи правильно заповнений .env.
Якщо клієнт не працює: перевірте package.json і виконайте npm install.
text
Wrap
Copy

---

### Крок 6: Підготовка репозиторію
1. Переконайся, що всі файли оновлені:
   - `client/pages/dashboard.js`
   - `client/pages/chats/[chat_id].js`
   - `server/main.py`, `server/database.py`, `server/models.py`
   - `server/requirements.txt`
   - `server/.env.example`
   - `.gitignore`
   - `README.md`

2. Додай файли до git:
   ```bash
   git add .
   git commit -m "Додано інструкцію та підготовлено репозиторій для запуску"
Відправ на GitHub:
bash
Wrap
Copy
git push origin main
(Заміни main на твою гілку, якщо вона інша).
Крок 7: Перевірка
Клонуй репозиторій у нову папку:
bash
Wrap
Copy
git clone https://github.com/your-username/your-repo.git test-clone
cd test-clone
Дотримуйся інструкцій із README.md і перевір, чи все запускається.
Результат
Тепер ти можеш скинути посилання на свій репозиторій (наприклад, https://github.com/your-username/your-repo), і будь-хто з базовими знаннями зможе:

Клонувати проєкт.
Встановити залежності.
Налаштувати .env.
Запустити сервер і клієнт.
Якщо потрібні зміни в README.md (наприклад, додати скріншоти чи уточнити щось), скажи — я допоможу! 😊






Крок 5: Написання README.md
У корені репозиторію створи або онови README.md із докладною інструкцією: - а можна повну інструкцію для мого проекту?


Звісно, давай створимо повну інструкцію в README.md, яка точно відповідатиме твоєму проєкту SocialHub із клієнтом на Next.js і сервером на FastAPI. Я врахую всі особливості, які ми обговорили: структуру, залежності, обробку помилок Telegram, стилі тощо. Ось детальний README.md для твого репозиторію:

README.md
markdown
Wrap
Copy
# SocialHub

SocialHub — це веб-додаток для підключення до Telegram через браузер, перегляду списку чатів та їхніх повідомлень. Клієнт побудований на Next.js із мінімалістичним дизайном, а сервер — на FastAPI з базою даних SQLite.

## Особливості
- Реєстрація та автентифікація користувачів.
- Підключення до Telegram через номер телефону.
- Перегляд списку чатів із мінімалістичними картками.
- Перегляд повідомлень у вибраному чаті з кнопкою повернення до списку чатів.
- Обробка помилок Telegram (наприклад, "Too Many Requests").

## Структура
- **`client/`**: Фронтенд на Next.js
  - `pages/dashboard.js`: Головна сторінка з підключенням Telegram і списком чатів.
  - `pages/chats/[chat_id].js`: Сторінка повідомлень у чаті.
- **`server/`**: Бекенд на FastAPI
  - `main.py`: Основний файл із ендпоінтами.
  - `database.py`: Налаштування бази SQLite.
  - `models.py`: Модель користувача.

## Вимоги
- **Node.js**: v16 або новіше ([завантажити](https://nodejs.org/)).
- **Python**: 3.9+ ([завантажити](https://www.python.org/)).
- **Git**: для клонування репозиторію ([завантажити](https://git-scm.com/)).

## Налаштування та запуск

### 1. Клонуйте репозиторій
```bash
git clone https://github.com/your-username/socialhub.git
cd socialhub
2. Налаштуйте сервер
Перейдіть до папки сервера:
bash
Wrap
Copy
cd server
Створіть віртуальне оточення та активуйте його:
Linux/Mac:
bash
Wrap
Copy
python3 -m venv venv
source venv/bin/activate
Windows (CMD):
bash
Wrap
Copy
python -m venv venv
venv\Scripts\activate
Windows (Git Bash):
bash
Wrap
Copy
python -m venv venv
source venv/Scripts/activate
Встановіть залежності:
bash
Wrap
Copy
pip install -r requirements.txt
Якщо requirements.txt відсутній, встановіть вручну:
bash
Wrap
Copy
pip install fastapi uvicorn sqlalchemy aiosqlite telethon python-jose[cryptography] passlib[bcrypt] python-dotenv
Скопіюйте server/.env.example у server/.env і заповніть:
bash
Wrap
Copy
cp .env.example .env
Вміст .env:
text
Wrap
Copy
API_ID=your_telegram_api_id
API_HASH=your_telegram_api_hash
JWT_SECRET=your_secret_key_here
API_ID і API_HASH: отримайте на my.telegram.org.
JWT_SECRET: будь-який секретний ключ (наприклад, "mysecretkey123").
3. Налаштуйте клієнт
Перейдіть до папки клієнта:
bash
Wrap
Copy
cd ../client
Встановіть залежності:
bash
Wrap
Copy
npm install
4. Запустіть проєкт
Запустіть сервер (із папки server):
У новому терміналі:
bash
Wrap
Copy
cd server
source venv/bin/activate  # або venv\Scripts\activate для Windows
uvicorn main:app --reload
Сервер буде доступний на http://localhost:8000.
Запустіть клієнт (із папки client):
У іншому терміналі:
bash
Wrap
Copy
cd client
npm run dev
Клієнт буде доступний на http://localhost:3000.
5. Використання
Відкрийте браузер на http://localhost:3000.
Зареєструйтесь або увійдіть.
Введіть номер телефону (наприклад, +380...) і натисніть "Отримати код".
Дочекайтесь коду в Telegram (SMS або дзвінок, до 1-2 хвилин).
Введіть код і підключіться.
Переглядайте чати та повідомлення.
Скріншоти
(Додайте скріншоти, якщо хочете, наприклад, через GitHub Issues і вставте посилання сюди)

Нотатки
База даних: Проєкт використовує SQLite (socialhub.db) у папці server/. Вона автоматично створюється при першому запуску.
Обмеження Telegram: Якщо отримаєте помилку "429 Too Many Requests" (наприклад, "Зачекайте 425 хвилин"), це обмеження Telegram:
Спробуйте інший номер телефону.
Або отримайте нові API_ID і API_HASH на my.telegram.org.
Порти: Переконайтеся, що порти 8000 (сервер) і 3000 (клієнт) вільні.
Вирішення проблем
Сервер не запускається:
Перевірте, чи всі залежності встановлені (pip install -r requirements.txt).
Переконайтеся, що .env заповнений правильно.
Перегляньте логи в терміналі.
Клієнт не працює:
Виконайте npm install у папці client/.
Перевірте, чи сервер запущений на http://localhost:8000.
Код не приходить:
Перевірте номер телефону (має бути у форматі +код країни...).
Зачекайте 1-2 хвилини, перевірте дзвінки (Telegram може дзвонити).
Якщо затримка довга, оновіть API_ID/API_HASH.
Внесок
Форкніть репозиторій.
Створіть гілку (git checkout -b feature/your-feature).
Закомітьте зміни (git commit -m "Додано вашу фічу").
Відправте на GitHub (git push origin feature/your-feature).
Створіть Pull Request.
Автор
[Your Name] (https://github.com/your-username)
text
Wrap
Copy

---

### Як це використовувати?
1. Скопіюй цей текст у файл `README.md` у корені твого репозиторію (`socialhub/`).
2. Заміни:
   - `your-username` на твій GitHub username (наприклад, `batalova`).
   - `your-repo` на назву твого репозиторію (наприклад, `socialhub`).
   - `[Your Name]` на твоє ім’я, якщо хочеш вказати авторство.
3. Додай файли до git:
   ```bash
   git add README.md
   git commit -m "Додано детальну інструкцію в README.md"
   git push origin main
Чому ця інструкція повна?
Структура: Описано, що де лежить.
Вимоги: Указано всі потрібні інструменти з посиланнями.
Кроки: Детально розписано для Linux/Mac і Windows (включаючи Git Bash).
Використання: Прості інструкції для користувача.
Нотатки та вирішення проблем: Враховано специфіку Telegram і SQLite.
Внесок: Додано для тих, хто захоче допомагати.
Перевірка
Клонуй репозиторій у нову папку:
bash
Wrap
Copy
git clone https://github.com/your-username/socialhub.git test-clone
cd test-clone
Дотримуйся інструкцій із README.md і перевір, чи все запускається.
Тепер ти можеш скинути посилання на свій репозиторій (наприклад, https://github.com/your-username/socialhub), і будь-хто зможе запустити проєкт! Якщо потрібні зміни чи скріншоти, дай знати — додамо! 😊






## Налаштування та запуск

### 1. Клонуйте репозиторій
```bash
git clone https://github.com/your-username/socialhub.git
cd socialhub - а далі? як користувачу далі діяти? можна все в одному файлі чіткі інструкції ред мі


Ось повна і чітка інструкція для README.md, яка охоплює всі кроки від клонування до запуску в одному файлі. Я розпишу все так, щоб користувач із мінімальними знаннями міг запустити твій проєкт SocialHub без додаткових питань.

README.md
markdown
Wrap
Copy
# SocialHub

SocialHub — це веб-додаток для підключення до Telegram через браузер, перегляду списку чатів та їхніх повідомлень. Клієнт побудований на Next.js із мінімалістичним дизайном, а сервер — на FastAPI з базою даних SQLite.

## Особливості
- Реєстрація та автентифікація користувачів.
- Підключення до Telegram через номер телефону.
- Перегляд списку чатів із мінімалістичними картками.
- Перегляд повідомлень у вибраному чаті з кнопкою повернення до списку чатів.
- Обробка помилок Telegram (наприклад, "Too Many Requests").

---

## Налаштування та запуск

Ця інструкція проведе вас через усі кроки для запуску проєкту на вашому комп’ютері.

### 1. Клонуйте репозиторій
Спочатку завантажте проєкт із GitHub:
```bash
git clone https://github.com/your-username/socialhub.git
cd socialhub
2. Встановіть необхідне програмне забезпечення
Переконайтеся, що у вас встановлені:

Git: завантажити тут.
Node.js: v16 або новіше (завантажити тут).
Python: 3.9+ (завантажити тут). Після встановлення перевірте версії:
bash
Wrap
Copy
git --version
node --version
python --version  # або python3 --version на Linux/Mac
3. Налаштуйте сервер
Сервер працює на Python і FastAPI.

Перейдіть до папки сервера:
bash
Wrap
Copy
cd server
Створіть віртуальне оточення:
Linux/Mac:
bash
Wrap
Copy
python3 -m venv venv
Windows (CMD):
bash
Wrap
Copy
python -m venv venv
Windows (Git Bash):
bash
Wrap
Copy
python -m venv venv
Активуйте віртуальне оточення:
Linux/Mac:
bash
Wrap
Copy
source venv/bin/activate
Windows (CMD):
bash
Wrap
Copy
venv\Scripts\activate
Windows (Git Bash):
bash
Wrap
Copy
source venv/Scripts/activate
Після цього у терміналі з’явиться (venv) перед командним рядком.
Встановіть залежності:
bash
Wrap
Copy
pip install -r requirements.txt
Якщо requirements.txt немає, встановіть вручну:
bash
Wrap
Copy
pip install fastapi uvicorn sqlalchemy aiosqlite telethon python-jose[cryptography] passlib[bcrypt] python-dotenv
Налаштуйте файл .env:
Скопіюйте приклад:
bash
Wrap
Copy
cp .env.example .env
Відкрийте server/.env у текстовому редакторі (наприклад, Notepad або VS Code) і заповніть:
text
Wrap
Copy
API_ID=your_telegram_api_id
API_HASH=your_telegram_api_hash
JWT_SECRET=your_secret_key_here
API_ID і API_HASH: отримайте на my.telegram.org (увійдіть, створіть додаток, скопіюйте ключі).
JWT_SECRET: введіть будь-який рядок (наприклад, "mysecretkey123").
4. Налаштуйте клієнт
Клієнт працює на Node.js і Next.js.

Перейдіть до папки клієнта:
bash
Wrap
Copy
cd ../client
Встановіть залежності:
bash
Wrap
Copy
npm install
5. Запустіть проєкт
Тепер запустіть сервер і клієнт у різних терміналах.

Запустіть сервер:
Відкрийте перший термінал, перейдіть до server/:
bash
Wrap
Copy
cd server
source venv/bin/activate  # або venv\Scripts\activate для Windows
uvicorn main:app --reload
Ви побачите повідомлення типу [INFO] Application startup complete і сервер запуститься на http://localhost:8000.
Запустіть клієнт:
Відкрийте другий термінал, перейдіть до client/:
bash
Wrap
Copy
cd client
npm run dev
Клієнт запуститься на http://localhost:3000.
6. Використовуйте додаток
Відкрийте браузер і перейдіть за адресою http://localhost:3000.
Зареєструйтесь або увійдіть (наприклад, username: "test123", password: "password123").
Введіть номер телефону (наприклад, +380963048847) і натисніть "Отримати код".
Дочекайтесь коду в Telegram (SMS або дзвінок, до 1-2 хвилин).
Введіть код і натисніть "Підключити".
Переглядайте список чатів і клікайте на них, щоб побачити повідомлення.
Вирішення проблем
Сервер не запускається:
Перевірте, чи активовано віртуальне оточення ((venv) у терміналі).
Переконайтеся, що .env заповнений правильно.
Перегляньте логи в терміналі (наприклад, відсутність модулів — виконайте pip install ...).
Клієнт не працює:
Перевірте, чи сервер запущений (http://localhost:8000/health має повернути {"status": "OK"}).
Виконайте npm install у client/.
Помилка "429 Too Many Requests":
Telegram обмежив запити. Зачекайте вказаний час (наприклад, "425 хвилин" ≈ 7 годин) або:
Спробуйте інший номер телефону.
Отримайте нові API_ID і API_HASH на my.telegram.org.
Код не приходить:
Перевірте формат номера (+код країни...).
Зачекайте 1-2 хвилини, перевірте дзвінки (Telegram може дзвонити).
Структура проєкту
client/: Фронтенд (Next.js)
pages/dashboard.js: Підключення Telegram і список чатів.
pages/chats/[chat_id].js: Повідомлення в чаті.
server/: Бекенд (FastAPI)
main.py: Ендпоінти API.
database.py: Налаштування SQLite.
models.py: Модель користувача.
Нотатки
База даних (socialhub.db) зберігається в server/.
Проєкт використовує SQLite через простоту, але має затримки ("database is locked") при частих запитах — це оброблено на клієнті.
Автор
[Your Name] (https://github.com/your-username)
text
Wrap
Copy

---

### Як це використовувати?
1. Скопіюй цей текст у файл `README.md` у корені твого репозиторію (`socialhub/`).
2. Заміни:
   - `your-username` на твій GitHub username (наприклад, `batalova`).
   - `[Your Name]` на твоє ім’я (наприклад, "Anna Batalova"), якщо хочеш вказати авторство.
3. Додай до git і відправ:
   ```bash
   git add README.md
   git commit -m "Додано повну інструкцію в README.md"
   git push origin main
Чому це чітко?
Крок за кроком: Усі дії від клонування до запуску розписані послідовно.
Варіанти для ОС: Враховано Linux/Mac і Windows (CMD/Git Bash).
Вирішення проблем: Описано найпоширеніші помилки з рішеннями.
Простота: Інструкція зрозуміла навіть новачкам.
Перевірка
Клонуй у нову папку:
bash
Wrap
Copy
git clone https://github.com/your-username/socialhub.git test-clone
cd test-clone
Дотримуйся інструкцій із README.md і перевір, чи все запускається.
Тепер можеш скинути посилання (наприклад, https://github.com/your-username/socialhub), і будь-хто запустить проєкт! Якщо потрібні зміни (скріншоти, більше деталей), скажи! 😊






Ні, потрібно все щоб одним кліком скопіювати. в Мене є таке, але як воно буде виглядати?
SocialHub – Telegram Chat Viewer
📌 SocialHub is a web application that allows you to connect a Telegram account, view chats, and read messages.

🚀 Technologies
Frontend: Next.js
Backend: FastAPI
Authentication: JWT

⚡ Main Features
✅ User registration & login via JWT
✅ Connect a Telegram account
✅ View chat list
✅ Read messages in selected chats
✅ Disconnect from Telegram

🔧 Installation & Setup
1️⃣ Clone the repository
git clone https://github.com/your-username/socialhub.git
cd socialhub

2️⃣ Run the backend (FastAPI)
📌 Install dependencies
cd server
python -m venv venv  # Create a virtual environment
source venv/Scripts/activate  # (Windows) Activate
# or
source venv/bin/activate  # (Mac/Linux)
pip install -r requirements.txt  # Install dependencies

📌 Start FastAPI server
python -m uvicorn main:app --reload
✅ Backend is running at: http://127.0.0.1:8000

3️⃣ Run the frontend (Next.js)
📌 Install dependencies
cd ../client
npm install  # or yarn install
📌 Start Next.js
npm run dev  # or yarn dev
✅ Frontend is running at: http://localhost:3000

🔑 Configuration
Before running, create a .env file in the server/ directory with the following variables:
API_ID=your_telegram_api_id
API_HASH=your_telegram_api_hash
JWT_SECRET=your_secret_key

🤝 Contact
Author: [Your GitHub](https://github.com/batalova-kira)
Feedback? Open an Issue. 🚀


Ось твій README.md із усією інформацією в одному блоці, який можна скопіювати одним кліком. Я зберіг твій стиль із емодзі та адаптував його для чіткості й повноти, врахувавши всі особливості проєкту SocialHub. Ось як це виглядатиме:

README.md
markdown
Wrap
Copy
# SocialHub – Telegram Chat Viewer

📌 SocialHub is a web application that allows you to connect a Telegram account, view chats, and read messages.

## 🚀 Technologies
- **Frontend**: Next.js
- **Backend**: FastAPI
- **Authentication**: JWT
- **Database**: SQLite

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
⚠️ Troubleshooting
"429 Too Many Requests": Telegram limits requests. Wait the specified time (e.g., "425 minutes" ≈ 7 hours), or use a different phone number or new API_ID/API_HASH.
Code not arriving: Check phone number format (+countrycode...), wait 1-2 minutes, or check for a call from Telegram.
Server errors: Ensure .env is configured and dependencies are installed (pip install -r requirements.txt).
Client errors: Verify the backend is running (http://127.0.0.1:8000/health should return {"status": "OK"}).
🤝 Contact
Author: Kira Batalova

Feedback? Open an Issue. 🚀

text
Wrap
Copy

---

### Як це виглядає?
- **Заголовок**: "SocialHub – Telegram Chat Viewer" — чітко і з назвою.
- **Технології**: Перераховано з SQLite для повноти.
- **Функціонал**: Усі ключові можливості з акцентом на дизайн і кнопку повернення.
- **Інструкція**: Компактно, із командами в блоках коду, враховано Windows/Linux/Mac.
- **Конфігурація**: Окремий розділ із поясненнями.
- **Використання**: Покроковий опис для користувача.
- **Troubleshooting**: Враховано наші помилки (429, затримки коду).
- **Контакт**: Твій GitHub із запрошенням до зворотного зв’язку.

---

### Як додати?
1. Скопіюй весь текст вище одним кліком (Ctrl+A, Ctrl+C).
2. Відкрий `README.md` у корені репозиторію (`socialhub/`) у текстовому редакторі (наприклад, VS Code).
3. Встав текст (Ctrl+V) і збережи.
4. Додай до git і відправ:
   ```bash
   git add README.md
   git commit -m "Додано повну інструкцію в README.md"
   git push origin main
Перевірка
Клонуй у нову папку:
bash
Wrap
Copy
git clone https://github.com/batalova-kira/socialhub.git test-clone
cd test-clone
Дотримуйся інструкцій із README.md.
Тепер користувач може скопіювати README.md одним кліком і запустити проєкт! Якщо хочеш додати скріншоти чи змінити щось, скажи! 😊






після  Clone the repository все в одному великому вікні


Ось оновлений README.md, де після "Clone the repository" усі кроки об’єднані в один великий блок коду для зручного копіювання одним кліком. Я зберіг твій стиль із емодзі та адаптував інструкцію:

README.md
markdown
Wrap
Copy
# SocialHub – Telegram Chat Viewer

📌 SocialHub is a web application that allows you to connect a Telegram account, view chats, and read messages.

## 🚀 Technologies
- **Frontend**: Next.js
- **Backend**: FastAPI
- **Authentication**: JWT
- **Database**: SQLite

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
2️⃣ Setup and Run
bash
Wrap
Copy
# Install required software:
# - Git: https://git-scm.com/
# - Node.js (v16+): https://nodejs.org/
# - Python (3.9+): https://www.python.org/
# Check versions:
git --version
node --version
python --version  # or python3 --version on Linux/Mac

# Setup backend (FastAPI):
cd server
python -m venv venv  # Create virtual environment
# Activate it:
# Windows (CMD): venv\Scripts\activate
# Windows (Git Bash): source venv/Scripts/activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt  # Install dependencies (fastapi, uvicorn, sqlalchemy, aiosqlite, telethon, python-jose[cryptography], passlib[bcrypt], python-dotenv)
# Create and configure .env:
cp .env.example .env
# Edit server/.env with your text editor (e.g., Notepad or VS Code):
# API_ID=your_telegram_api_id (get from https://my.telegram.org)
# API_HASH=your_telegram_api_hash (get from https://my.telegram.org)
# JWT_SECRET=your_secret_key (e.g., "mysecretkey123")
# Start FastAPI server (in this terminal):
python -m uvicorn main:app --reload
# Backend runs at: http://127.0.0.1:8000

# Setup frontend (Next.js):
cd ../client
npm install  # Install dependencies
# Start Next.js (open a new terminal for this):
npm run dev
# Frontend runs at: http://localhost:3000

# How to use:
# 1. Open http://localhost:3000 in your browser
# 2. Register (e.g., username: "test123", password: "password123") or login
# 3. Enter Telegram phone number (e.g., +380963048847) and click "Get Code"
# 4. Wait for code in Telegram (SMS or call, up to 1-2 minutes)
# 5. Enter code and click "Connect"
# 6. View chats and messages

🤝 Contact
Author: https://github.com/batalova-kira

Feedback? Open an https://github.com/batalova-kira/socialhub/issues. 🚀

````
