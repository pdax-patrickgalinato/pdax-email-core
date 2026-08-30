import { createRoot } from "react-dom/client";
import App from "./App";
import "jsvectormap/dist/jsvectormap.css";
import "./app.css";

// Passkeys require a DNS rpId. 127.0.0.1 is rejected as "invalid domain".
if (location.hostname === "127.0.0.1" || location.hostname === "[::1]") {
  const next = new URL(location.href);
  next.hostname = "localhost";
  location.replace(next.href);
}

const root = document.getElementById("app");
if (!root) throw new Error("Missing #app");
createRoot(root).render(<App />);
