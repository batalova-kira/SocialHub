import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function Dashboard() {
    const [phone, setPhone] = useState("");
    const [code, setCode] = useState("");
    const [chats, setChats] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [error, setError] = useState("");
    const router = useRouter();

    // Перевірка статусу підключення Telegram
    useEffect(() => {
        const checkConnection = async () => {
            try {
                const token = localStorage.getItem("token");
                const res = await fetch(
                    "http://localhost:8000/check-connection",
                    {
                        headers: {
                            Authorization: `Bearer ${token}`,
                        },
                    }
                );

                if (res.ok) {
                    setIsConnected(true);
                    fetchChats();
                }
            } catch (err) {
                console.error("Connection check failed:", err);
            }
        };

        checkConnection();
    }, []);

    // Підключення Telegram
    const connectTelegram = async (e) => {
        e.preventDefault();

        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://localhost:8000/connect-telegram", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({ phone, code }),
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Connection failed");
            }

            setIsConnected(true);
            fetchChats();
        } catch (err) {
            setError(err.message);
        }
    };

    // Отримання чатів
    const fetchChats = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch("http://localhost:8000/chats", {
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });

            if (!res.ok) throw new Error("Failed to fetch chats");

            const data = await res.json();
            setChats(data);
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6">Панель управління</h1>

            {!isConnected ? (
                // Форма підключення Telegram
                <div className="bg-white p-6 rounded-lg shadow-md">
                    <h2 className="text-xl mb-4">Підключіть Telegram</h2>
                    {error && <p className="text-red-500 mb-4">{error}</p>}
                    <form onSubmit={connectTelegram} className="space-y-4">
                        <input
                            type="text"
                            placeholder="Номер телефону"
                            value={phone}
                            onChange={(e) => setPhone(e.target.value)}
                            className="w-full p-2 border rounded"
                        />
                        <input
                            type="text"
                            placeholder="Код підтвердження"
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
                    {error && <p className="text-red-500 mb-4">{error}</p>}
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
