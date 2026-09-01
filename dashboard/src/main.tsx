import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { AppRoutes } from "./app/AppRoutes";
import { DashboardProvider } from "./app/state";
import "./styles/global.css";

createRoot(document.getElementById("root")!).render(
  <BrowserRouter>
    <DashboardProvider>
      <AppRoutes />
    </DashboardProvider>
  </BrowserRouter>,
);
