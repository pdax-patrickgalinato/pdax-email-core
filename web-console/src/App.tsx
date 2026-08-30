import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import Login from "./pages/Login";
import ConsoleLayout from "./pages/ConsoleLayout";
import Overview from "./pages/Overview";
import Quarantine from "./pages/Quarantine";
import Analyze from "./pages/Analyze";
import Senders from "./pages/Senders";
import Campaigns from "./pages/Campaigns";
import Workers from "./pages/Workers";
import Audit from "./pages/Audit";
import Settings from "./pages/Settings";
import OrgContext from "./pages/OrgContext";
import Notifications from "./pages/Notifications";
import UserManagement from "./pages/UserManagement";
import Profile from "./pages/Profile";
import Detail from "./pages/Detail";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/login.html" element={<Navigate to="/login" replace />} />
        <Route element={<ConsoleLayout />}>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/index.html" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<Overview />} />
          <Route path="/queue" element={<Navigate to="/workers" replace />} />
          <Route path="/quarantine" element={<Quarantine />} />
          <Route path="/analyze" element={<Analyze />} />
          <Route path="/senders" element={<Senders />} />
          <Route path="/campaigns" element={<Campaigns />} />
          <Route path="/workers" element={<Workers />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/settings/organization" element={<OrgContext />} />
          <Route path="/settings/notifications" element={<Notifications />} />
          <Route path="/settings/users" element={<UserManagement />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/mail/:id" element={<Detail />} />
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
