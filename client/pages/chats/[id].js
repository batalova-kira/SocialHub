import { useState, useEffect } from "react";
import { useRouter } from "next/router";
import Link from "next/link";

export default function ChatMessages() {
    const [messages, setMessages] = useState([]);
    const [error, setError] = useState("");
    const router = useRouter();
    const { id } = router.query; // Змінено з chat_id на id

    useEffect(() => {
        console.log("useEffect triggered, router.query:", router.query);
        console.log("id from query:", id);

        const fetchMessages = async () => {
            const token = localStorage.getItem("token");
            if (!token || !id) {
                console.log("No token or id, redirecting to /login");
                router.push("/login");
                return;
            }

            try {
                console.log("Fetching messages for id:", id);
                const res = await fetch(
                    `http://localhost:8000/chats/${id}/messages`,
                    {
                        headers: { Authorization: `Bearer ${token}` },
                    }
                );
                console.log("Response status:", res.status);

                if (!res.ok) {
                    const errorData = await res.json();
                    console.log("Error data:", errorData);
                    throw new Error(
                        errorData.detail ||
                            "Не вдалося завантажити повідомлення"
                    );
                }

                const data = await res.json();
                console.log("Messages received:", data);
                setMessages(data);
            } catch (err) {
                console.error("Fetch error:", err.message);
                setError(err.message);
            }
        };

        if (router.isReady && id) {
            fetchMessages();
        } else {
            console.log("Waiting for router to be ready or id to be defined");
        }
    }, [id, router.isReady, router]); // Змінено chat_id на id

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
                {messages.length > 0 ? (
                    messages.map((message) => (
                        <div
                            key={message.id}
                            className="bg-white p-3 rounded-md border-b border-gray-200 text-gray-700"
                        >
                            <p className="text-sm">{message.text}</p>
                            <p className="text-xs text-gray-500 mt-1">
                                {new Date(message.date).toLocaleString()}
                            </p>
                        </div>
                    ))
                ) : (
                    <p className="text-gray-500">Немає повідомлень</p>
                )}
            </div>
        </div>
    );
}
