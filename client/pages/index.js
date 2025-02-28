import { useEffect } from "react";
import { useRouter } from "next/router";

export default function HomePage() {
    const router = useRouter();

    useEffect(() => {
        const token = localStorage.getItem("token");
        router.push(token ? "/dashboard" : "/login");
    }, []);

    return null; // Або індикатор завантаження
}
