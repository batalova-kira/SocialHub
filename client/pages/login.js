import { useState } from "react";
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

            console.log("Отримано токен:", data.access_token); // Лог для дебагу
            localStorage.setItem("token", data.access_token);
            router.push("/dashboard");
        } catch (err) {
            setError(err.message);
        }
    };

    // localStorage.setItem("token", data.access_token);
    // console.log("Токен збережено:", localStorage.getItem("token"));

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
