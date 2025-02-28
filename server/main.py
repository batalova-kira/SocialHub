import os
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
from telethon.errors import SessionPasswordNeededError  
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
    code: str  # Обов'язкове поле
    password: Optional[str] = None  # Необов'язкове поле
    phone: Optional[str] = None  # Додаємо як необов'язкове

class TelegramSession(BaseModel):
    phone: str
    phone_code_hash: str
    client: Optional[types.User] = None  # Зберігаємо клієнт

    # Тимчасове сховище для сесій (можна замінити на Redis або БД)
temp_sessions = {}

# Залежності
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

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
            raise HTTPException(401, "Невірний токен")

        result = await db.execute(select(User).filter(User.username == username))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(401, "Користувача не знайдено")
        
        return user
    except JWTError as e:
        raise HTTPException(401, f"Помилка токена: {str(e)}")

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
    if not current_user.telegram_phone:
        return {"connected": False}
    return {"connected": True}

# Підключення Telegram
@app.post("/connect-telegram")
async def connect_telegram(
    auth: TelegramConnect, 
    current_user: User = Depends(get_current_user)
):
    try:
        # Отримуємо сесію
        session_data = temp_sessions.get(current_user.id)
        if not session_data or not session_data.client:
            raise HTTPException(400, "Спочатку отримайте код")
        
        client = session_data.client
        
        # Авторизація
        try:
            await client.sign_in(
                phone=session_data.phone,
                code=auth.code,
                phone_code_hash=session_data.phone_code_hash,
                password=auth.password or None
            )
        except SessionPasswordNeededError:
            raise HTTPException(400, "Потрібен пароль 2FA")
        
        # Оновлення статусу користувача
        current_user.telegram_phone = session_data.phone
        await client.disconnect()
        del temp_sessions[current_user.id]
        
        return {"status": "Connected"}
    
    except Exception as e:
        print(f"Помилка авторизації: {str(e)}")
        raise HTTPException(400, f"Помилка: {str(e)}")

# Отримання чатів
@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user)):
    if not current_user.telegram_phone:
        raise HTTPException(status_code=400, detail="Telegram не підключено")
    
    client = TelegramClient(f'session_{current_user.telegram_phone}', API_ID, API_HASH)
    await client.connect()

    if not await client.is_user_authorized():
        raise HTTPException(status_code=400, detail="Необхідно авторизуватися в Telegram")
    
    dialogs = await client.get_dialogs()
    return [{"id": d.id, "name": d.name} for d in dialogs]

# Отримання коду
@app.post("/send-code")
async def send_code(
    data: TelegramSendCode, 
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    try:
        # Перевірка існуючих сесій
        if current_user.id in temp_sessions:
            await temp_sessions[current_user.id].client.disconnect()
            del temp_sessions[current_user.id]

        # Ініціалізація клієнта
        client = TelegramClient(
            session=StringSession(),  # Використовуємо in-memory сесію
            api_id=int(API_ID),
            api_hash=API_HASH
        )
        await client.connect()
        
        # Відправка коду
        sent_code = await client.send_code_request(data.phone)
        
        # Зберігаємо дані
        temp_sessions[current_user.id] = {
            "phone": data.phone,
            "phone_code_hash": sent_code.phone_code_hash,
            "client": client.session.save()  # Зберігаємо сесію як строку
        }
        
        return {"detail": "Код відправлено"}
    
    except FloodWaitError as e:
        raise HTTPException(429, detail=f"Зачекайте {e.seconds} секунд")
    except Exception as e:
        print(f"Помилка відправки: {str(e)}")
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
    return {"status": "OK"}