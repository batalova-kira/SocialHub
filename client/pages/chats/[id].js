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
                const res = await fetch(
                    `http://localhost:8000/chats/${chat_id}/messages`,
                    {
                        headers: { Authorization: `Bearer ${token}` },
                    }
                );
                if (!res.ok)
                    throw new Error("Не вдалося завантажити повідомлення");
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
                <h1 className="text-2xl font-bold text-gray-800">
                    Повідомлення
                </h1>
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
                        <p className="text-xs text-gray-500 mt-1">
                            {new Date(message.date).toLocaleString()}
                        </p>
                    </div>
                ))}
            </div>
        </div>
    );
}
