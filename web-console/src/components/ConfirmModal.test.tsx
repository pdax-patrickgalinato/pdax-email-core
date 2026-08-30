import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ConfirmModal from "./ConfirmModal";
import { renderWithConsole } from "../test/render";
import { useConsole } from "../context/ConsoleContext";
import { useEffect } from "react";

function SeedConfirm() {
  const { setConfirm } = useConsole();
  useEffect(() => {
    setConfirm({
      kind: "release",
      id: "msg-1",
      title: "Release this message?",
      body: "It will be delivered to the mailbox.",
      detail: "From: alice@example.com",
      confirmLabel: "Release",
    });
  }, [setConfirm]);
  return <ConfirmModal />;
}

describe("ConfirmModal", () => {
  it("renders the pending action and closes on cancel", async () => {
    const user = userEvent.setup();
    renderWithConsole(<SeedConfirm />);
    expect(await screen.findByRole("heading", { name: "Release this message?" })).toBeInTheDocument();
    expect(screen.getByText("From: alice@example.com")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("heading", { name: "Release this message?" })).not.toBeInTheDocument();
  });
});
