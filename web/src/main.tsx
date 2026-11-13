import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

const prefersDark = window.matchMedia("(prefers-color-scheme: dark)");
const applyTheme = () => {
  document.documentElement.classList.toggle("dark", prefersDark.matches);
};
applyTheme();
prefersDark.addEventListener("change", applyTheme);

const root = document.getElementById("root");
if (!root) {
  throw new Error("missing root element");
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
