import React, { Suspense } from "react";
import { createRoot } from "react-dom/client";
import App from "./app";
import "./styles.css";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("No #root element found in index.html");

// useAgentChat calls React.use() to fetch persisted conversation history —
// that suspends the component tree. Suspense catches it and shows a fallback
// until the fetch resolves, instead of React silently unmounting everything.
createRoot(rootEl).render(
  <Suspense fallback={<div style={{ background: "#090b0e", height: "100vh" }} />}>
    <App />
  </Suspense>
);
