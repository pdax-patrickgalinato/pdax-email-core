import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { ICON, isAdmin, ui } from "../lib/dashboard";
import { api } from "../lib/api";
import { errorMessage } from "../lib/errors";
import { EmptyState } from "../components/ui";
import SettingsNav from "../components/SettingsNav";
import type { ListEntry, Org, OrgNote } from "../types";

type ListName = "allowlist" | "blocklist";

const EMPTY_LISTS = { allowlist: [] as ListEntry[], blocklist: [] as ListEntry[] };

function listKey(entry: ListEntry): string {
  const kind = entry.address ? "address" : "domain";
  return kind + ":" + (entry.address || entry.domain || "");
}

function SenderListCard({
  name,
  title,
  sub,
  entries,
  busy,
  onAdd,
  onRemove,
}: {
  name: ListName;
  title: string;
  sub: string;
  entries: ListEntry[];
  busy: boolean;
  onAdd: (name: ListName, body: { type: string; value: string; note: string }) => Promise<void>;
  onRemove: (name: ListName, value: string) => void;
}) {
  const [type, setType] = useState("address");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h2>{title}</h2>
          <div className="card-sub">{sub}</div>
        </div>
        <span className="user-role">{entries.length}</span>
      </div>
      <form
        style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "12px" }}
        autoComplete="off"
        onSubmit={async (ev) => {
          ev.preventDefault();
          const v = value.trim();
          if (!v) return;
          await onAdd(name, { type, value: v, note: note.trim() });
          setValue("");
          setNote("");
        }}
      >
        <select
          className="search-input"
          style={{ width: "110px", flexShrink: 0 }}
          value={type}
          onChange={(e) => setType(e.target.value)}
          aria-label={title + " match type"}
        >
          <option value="address">Address</option>
          <option value="domain">Domain</option>
        </select>
        <input
          className="search-input"
          style={{ flex: 1, minWidth: "180px" }}
          placeholder="user@example.com or example.com"
          required
          value={value}
          onChange={(e) => setValue(e.target.value)}
        />
        <input
          className="search-input"
          style={{ flex: 1, minWidth: "140px" }}
          placeholder="Why this sender (optional)"
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
        <button type="submit" className="btn btn-sm" disabled={busy}>
          Add
        </button>
      </form>
      <div style={{ overflowX: "auto" }}>
        <table className="data-table" style={{ minWidth: "480px" }}>
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Note</th>
              <th style={{ width: "80px" }} />
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => {
              const t = e.address ? "address" : "domain";
              const v = e.address || e.domain || "";
              return (
                <tr key={listKey(e)}>
                  <td>
                    <span className="verdict-chip verdict-low">{t}</span>
                  </td>
                  <td style={{ fontFamily: "monospace", fontSize: "13px" }}>{v}</td>
                  <td style={{ color: "var(--ink-muted)", fontSize: "12px" }}>{e.note || ""}</td>
                  <td>
                    <button type="button" className="btn btn-sm btn-danger" onClick={() => onRemove(name, v)}>
                      Remove
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {!entries.length ? (
        <EmptyState>
          {name === "blocklist"
            ? "No blocked senders yet. Addresses and domains here always quarantine."
            : "No trusted senders yet. Addresses and domains here always deliver."}
        </EmptyState>
      ) : null}
    </div>
  );
}

export default function OrgContext() {
  const admin = isAdmin();
  const [notes, setNotes] = useState<OrgNote[]>([]);
  const [noteText, setNoteText] = useState("");
  const [noteBusy, setNoteBusy] = useState(false);
  const [noteErr, setNoteErr] = useState("");
  const [noteQ, setNoteQ] = useState("");
  const [editingId, setEditingId] = useState("");
  const [editText, setEditText] = useState("");
  const [lists, setLists] = useState(EMPTY_LISTS);
  const [listBusy, setListBusy] = useState(false);

  async function reloadNotes() {
    const org = await api<Org>("/api/org");
    setNotes(org.context_notes || []);
  }

  async function reloadLists() {
    setLists(await api<{ allowlist: ListEntry[]; blocklist: ListEntry[] }>("/api/lists"));
  }

  useEffect(() => {
    if (!admin) return;
    reloadNotes().catch(() => {});
    reloadLists().catch(() => {});
  }, [admin]);

  const filteredNotes = useMemo(() => {
    const q = noteQ.trim().toLowerCase();
    if (!q) return notes;
    return notes.filter((n) => n.text.toLowerCase().includes(q));
  }, [notes, noteQ]);

  if (!admin) return <Navigate to="/overview" replace />;

  async function addNote(ev: FormEvent) {
    ev.preventDefault();
    const text = noteText.trim();
    if (!text || noteBusy) return;
    setNoteBusy(true);
    setNoteErr("");
    try {
      const body = await api<{ context_notes?: OrgNote[] }>("/api/org/context", {
        method: "POST",
        body: JSON.stringify({ text }),
      });
      setNotes(body.context_notes || []);
      setNoteText("");
      if (ui.onToast) ui.onToast(ICON.good, "Context note added — applies on the next email");
    } catch (err) {
      setNoteErr(errorMessage(err));
    } finally {
      setNoteBusy(false);
    }
  }

  async function saveEdit(id: string) {
    const text = editText.trim();
    if (!text) return;
    setNoteBusy(true);
    setNoteErr("");
    try {
      const body = await api<{ context_notes?: OrgNote[] }>("/api/org/context/" + encodeURIComponent(id), {
        method: "PATCH",
        body: JSON.stringify({ text }),
      });
      setNotes(body.context_notes || []);
      setEditingId("");
      setEditText("");
      if (ui.onToast) ui.onToast(ICON.good, "Context note updated — applies on the next email");
    } catch (err) {
      setNoteErr(errorMessage(err));
    } finally {
      setNoteBusy(false);
    }
  }

  async function removeNote(id: string) {
    setNoteBusy(true);
    try {
      const body = await api<{ context_notes?: OrgNote[] }>("/api/org/context/" + encodeURIComponent(id), {
        method: "DELETE",
      });
      setNotes(body.context_notes || []);
      if (editingId === id) {
        setEditingId("");
        setEditText("");
      }
      if (ui.onToast) ui.onToast(ICON.good, "Context note removed");
    } catch (err) {
      if (ui.onToast) ui.onToast(ICON.warning, errorMessage(err));
    } finally {
      setNoteBusy(false);
    }
  }

  async function addListEntry(list: ListName, body: { type: string; value: string; note: string }) {
    setListBusy(true);
    try {
      await api("/api/lists/" + encodeURIComponent(list), {
        method: "POST",
        body: JSON.stringify(body),
      });
      await reloadLists();
      if (ui.onToast) {
        ui.onToast(
          ICON.good,
          list === "blocklist"
            ? "Blocklisted " + body.value + " — always quarantine"
            : "Allowlisted " + body.value + " — always deliver"
        );
      }
    } catch (err) {
      if (ui.onToast) ui.onToast(ICON.warning, errorMessage(err));
    } finally {
      setListBusy(false);
    }
  }

  async function removeListEntry(list: ListName, value: string) {
    try {
      await api("/api/lists/" + encodeURIComponent(list) + "/" + encodeURIComponent(value), {
        method: "DELETE",
      });
      await reloadLists();
      if (ui.onToast) ui.onToast(ICON.good, "Removed " + value);
    } catch (err) {
      if (ui.onToast) ui.onToast(ICON.warning, errorMessage(err));
    }
  }

  return (
    <section className="page active">
      <SettingsNav />

      <div className="settings-section">
        <div className="settings-section-label">Organizational context</div>
        <div className="card">
          <div className="card-head">
            <div>
              <h2>Facts the AI should keep using</h2>
              <div className="card-sub">
                Mailbox roles, what the company does, who typically emails whom. Injected into every content-AI
                assessment. Advisory only — does not override detection scores. Edits apply on the next email, no
                restart.
              </div>
            </div>
            <span className="user-role">{notes.length}</span>
          </div>
          <form
            style={{ display: "flex", flexDirection: "column", gap: "10px", marginBottom: "16px" }}
            autoComplete="off"
            onSubmit={addNote}
          >
            <label style={{ fontSize: "13px", fontWeight: 500 }}>
              Add a context note
              <textarea
                className="search-input org-context-input"
                rows={3}
                maxLength={2000}
                placeholder="e.g. support@pdax.ph is the customer-support inbox where clients raise concerns."
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
              />
            </label>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
              <button type="submit" className="btn btn-sm btn-primary" disabled={noteBusy || !noteText.trim()}>
                {noteBusy ? "Saving…" : "Add context"}
              </button>
              <span style={{ fontSize: "12px", color: "var(--ink-muted)" }}>{noteText.length} / 2000</span>
            </div>
            {noteErr ? <div className="users-error show">{noteErr}</div> : null}
          </form>
          {notes.length > 4 ? (
            <input
              className="search-input"
              type="search"
              placeholder="Search notes…"
              value={noteQ}
              onChange={(e) => setNoteQ(e.target.value)}
              style={{ marginBottom: "8px" }}
            />
          ) : null}
          {filteredNotes.map((n) => (
            <div key={n.id} className="org-context-item">
              {editingId === n.id ? (
                <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "8px" }}>
                  <textarea
                    className="search-input org-context-input"
                    rows={3}
                    maxLength={2000}
                    value={editText}
                    onChange={(e) => setEditText(e.target.value)}
                    aria-label="Edit context note"
                  />
                  <div style={{ display: "flex", gap: "8px" }}>
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      disabled={noteBusy || !editText.trim()}
                      onClick={() => saveEdit(n.id)}
                    >
                      Save
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => {
                        setEditingId("");
                        setEditText("");
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <p>{n.text}</p>
                  <div style={{ display: "flex", gap: "6px", flexShrink: 0 }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => {
                        setEditingId(n.id);
                        setEditText(n.text);
                        setNoteErr("");
                      }}
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm btn-danger"
                      disabled={noteBusy}
                      onClick={() => removeNote(n.id)}
                    >
                      Remove
                    </button>
                  </div>
                </>
              )}
            </div>
          ))}
          {!notes.length ? (
            <EmptyState>
              No organizational context yet. Add facts so the AI can interpret mail in this environment, then keep
              refining them as you learn more.
            </EmptyState>
          ) : null}
          {notes.length && !filteredNotes.length ? (
            <EmptyState>No notes match that search.</EmptyState>
          ) : null}
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-label">Sender blocklist</div>
        <SenderListCard
          name="blocklist"
          title="Always quarantine"
          sub="Hard override — these addresses and domains are treated as hostile regardless of score. Takes effect on the next email."
          entries={lists.blocklist || []}
          busy={listBusy}
          onAdd={addListEntry}
          onRemove={removeListEntry}
        />
      </div>

      <div className="settings-section">
        <div className="settings-section-label">Trusted senders</div>
        <SenderListCard
          name="allowlist"
          title="Always deliver"
          sub="Hard override — these addresses and domains skip quarantine regardless of score. Use sparingly for known-good partners."
          entries={lists.allowlist || []}
          busy={listBusy}
          onAdd={addListEntry}
          onRemove={removeListEntry}
        />
      </div>
    </section>
  );
}
