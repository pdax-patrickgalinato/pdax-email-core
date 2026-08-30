/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly MODE: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

interface Window {
  __SEG_CURRENT_USER__?: import("./types").AuthUser | null;
  Chart?: unknown;
}
