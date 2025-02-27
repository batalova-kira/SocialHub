import { useRouter } from "next/router";
import { useEffect, useState } from "react";

export default function ChatMessages() {
    const [messages, setMessages] = useState([]);
    const [error, setError] = useState("");
    const router = useRouter();
    const { id } = router.query;

    useEffect(() => {
        const fetchMessages = async () => {
            try {
                const token = localStorage.getItem("token");
                const res = await fetch(
                    `http://localhost:8000/chats/${id}/messages`,
                    {
                        headers: {
                            Authorization: `Bearer ${token}`,
                        },
                    }
                );

                if (!res.ok) throw new Error("Failed to fetch messages");

                const data = await res.json();
                setMessages(data);
            } catch (err) {
                setError(err.message);
            }
        };

        if (id) fetchMessages();
    }, [id]);

    return (
        <div className="max-w-4xl mx-auto p-6">
            <h1 className="text-2xl font-bold mb-6">Повідомлення</h1>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            <div className="space-y-4">
                {messages.map((msg) => (
                    <div key={msg.id} className="p-4 border rounded">
                        <p className="text-gray-600 text-sm">
                            {new Date(msg.date).toLocaleString()}
                        </p>
                        <p className="mt-2">{msg.text}</p>
                    </div>
                ))}
            </div>
        </div>
    );
}
