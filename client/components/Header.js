import { useRouter } from "next/router";

export default function Header() {
    const router = useRouter();

    const handleLogout = async () => {
        localStorage.removeItem("token");
        router.push("/login");
    };

    return (
        <header className="bg-gray-800 text-white p-4">
            <div className="container mx-auto flex justify-between items-center">
                <h1 className="text-xl">SocialHub</h1>
                <button
                    onClick={handleLogout}
                    className="bg-red-500 hover:bg-red-600 px-4 py-2 rounded"
                >
                    Вийти
                </button>
            </div>
        </header>
    );
}
