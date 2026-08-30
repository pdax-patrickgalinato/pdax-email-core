import { NavLink } from "react-router-dom";

export default function SettingsNav() {
  return (
    <nav className="tabs settings-subnav" aria-label="Settings sections">
      <NavLink to="/settings" end className={({ isActive }) => "tab" + (isActive ? " active" : "")}>
        Gateway
      </NavLink>
      <NavLink to="/settings/organization" className={({ isActive }) => "tab" + (isActive ? " active" : "")}>
        Organization
      </NavLink>
      <NavLink to="/settings/notifications" className={({ isActive }) => "tab" + (isActive ? " active" : "")}>
        Notifications
      </NavLink>
      <NavLink to="/settings/users" className={({ isActive }) => "tab" + (isActive ? " active" : "")}>
        Users & SSO
      </NavLink>
    </nav>
  );
}
