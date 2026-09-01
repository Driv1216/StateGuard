import { Route, Routes } from "react-router-dom";

import { FailureLabPage } from "../features/failure-lab/FailureLabPage";
import { FindingsPage } from "../features/findings/FindingsPage";
import { SafetyGraphPage } from "../features/graph/SafetyGraphPage";
import { OverviewPage } from "../features/overview/OverviewPage";
import { ProjectSetupPage } from "../features/setup/ProjectSetupPage";
import { Shell } from "./Shell";

export function AppRoutes() {
  return <Routes>
    <Route element={<Shell />}>
      <Route path="/" element={<OverviewPage />} />
      <Route path="/graph" element={<SafetyGraphPage />} />
      <Route path="/failure-lab" element={<FailureLabPage />} />
      <Route path="/findings" element={<FindingsPage />} />
      <Route path="/setup" element={<ProjectSetupPage />} />
    </Route>
  </Routes>;
}
