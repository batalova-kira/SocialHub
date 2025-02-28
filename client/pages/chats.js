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
