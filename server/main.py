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
        await asyncio.sleep(0.5)
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
        await asyncio.sleep(2)
        print(f"Fetching chats for user {current_user.id}")
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()

        is_authorized = await client.is_user_authorized()
        print(f"User authorized: {is_authorized}")
        if not is_authorized:
            await client.disconnect()
            raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")

        dialogs = await client.get_dialogs()
        await client.disconnect()

        result = [{"id": d.id, "name": d.name} for d in dialogs]
        print(f"Чати отримано для {current_user.id}: {result}")
        return result
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
        print(f"User {current_user.id} has no telegram_phone")
        raise HTTPException(status_code=400, detail="Telegram не підключено")

    try:
        client = TelegramClient(f"sessions/session_{current_user.id}", API_ID, API_HASH)
        await client.connect()
        print(f"Fetching messages for chat_id: {chat_id}, user: {current_user.id}")

        if not await client.is_user_authorized():
            await client.disconnect()
            print("User not authorized")
            raise HTTPException(status_code=400, detail="Сесія не авторизована")

        print(f"Requesting messages for chat_id: {chat_id}")
        messages = await client.get_messages(chat_id, limit=20)
        print(f"Received {len(messages)} messages for chat_id: {chat_id}")
        for msg in messages:
            print(f"Message ID: {msg.id}, Text: {msg.text if msg.text else '[No text]'}")
        
        await client.disconnect()

        result = [{"id": m.id, "text": m.text if m.text else "[No text]", "date": m.date.isoformat()} for m in messages]
        print(f"Returning messages: {result}")
        return result
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