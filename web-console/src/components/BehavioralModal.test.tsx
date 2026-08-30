import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import BehavioralModal from "./BehavioralModal";
import { renderWithConsole } from "../test/render";
import { useConsole } from "../context/ConsoleContext";
import { useEffect } from "react";

function SeedBehavioral() {
  const { setBehavioral } = useConsole();
  useEffect(() => {
    setBehavioral({
      title: "Shared shortener",
      sub: "Same landing host across senders",
      emails: [{ sender: "phish@example.com", verdict: "MALICIOUS", message_id: "<abc@x>", seen_at: 1700000000 }],
    });
  }, [setBehavioral]);
  return <BehavioralModal />;
}

describe("BehavioralModal", () => {
  it("lists prior flagged copies", async () => {
    renderWithConsole(<SeedBehavioral />);
    expect(await screen.findByRole("heading", { name: "Shared shortener" })).toBeInTheDocument();
    expect(screen.getByText("phish@example.com")).toBeInTheDocument();
    expect(screen.getByText("MALICIOUS")).toBeInTheDocument();
  });
});
