import { MemoryRouter } from "react-router-dom";
import { render, type RenderOptions } from "@testing-library/react";
import { ConsoleProvider } from "../context/ConsoleContext";
import { adminUser } from "./fixtures";
import type { AuthUser, Org } from "../types";
import type { Dispatch, ReactElement, ReactNode, SetStateAction } from "react";

type Options = {
  user?: AuthUser;
  route?: string;
  org?: Org | null;
} & Omit<RenderOptions, "wrapper">;

export function renderWithConsole(ui: ReactElement, opts: Options = {}) {
  const { user = adminUser, route = "/overview", org = { display_name: "PDAX" }, ...rest } = opts;
  const noop = () => {};
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <MemoryRouter initialEntries={[route]}>
        <ConsoleProvider
          user={user}
          setUser={noop as Dispatch<SetStateAction<AuthUser | null>>}
          org={org}
          setOrg={noop as Dispatch<SetStateAction<Org | null>>}
        >
          {children}
        </ConsoleProvider>
      </MemoryRouter>
    );
  }
  return render(ui, { wrapper: Wrapper, ...rest });
}
