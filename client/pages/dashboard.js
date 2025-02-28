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
