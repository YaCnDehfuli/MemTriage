import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { ReportProvider } from "./state/reportStore";
import { AppProvider } from "./state/store";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AppProvider>
      <ReportProvider>
        <App />
      </ReportProvider>
    </AppProvider>
  </StrictMode>,
);
