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
                const res = await fetch(
                    "http://localhost:8000/check-connection",
                    {
                        headers: { Authorization: `Bearer ${token}` },
                    }
                );

                if (res.status === 401) {
                    console.log("Токен невалідний, перенаправлення на /login");
                    localStorage.removeItem("token");
                    router.push("/login");
                    return;
                }

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
                    console.log(
                        `Спроба ${
                            attempt + 1
                        }: Помилка 500, повтор через 1 секунду...`
                    );
                    if (attempt < retries - 1) {
                        await new Promise((resolve) =>
                            setTimeout(resolve, 1000)
                        );
                        continue;
                    }
                }

                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(
                        data.detail || "Не вдалося завантажити чати"
                    );
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
            <h1 className="text-2xl font-bold mb-6 text-gray-800">
                Панель управління
            </h1>

            {error && <p className="text-red-500 mb-4">{error}</p>}
            {message && <p className="text-green-500 mb-4">{message}</p>}

            {!isConnected ? (
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4 text-gray-700">
                        Підключіть Telegram
                    </h2>

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
                                placeholder="If you have 2-factor authentication, enter your password"
                                value={twoFactorPassword}
                                onChange={(e) =>
                                    setTwoFactorPassword(e.target.value)
                                }
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
