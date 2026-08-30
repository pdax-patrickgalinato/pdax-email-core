import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/** world.js is a UMD snippet (`jsVectorMap.addMap(...)`) that expects a global.
 *  Vite inlines it into the ESM bundle, where that name is not in scope. */
function jsvectormapWorld(): Plugin {
  return {
    name: "jsvectormap-world",
    enforce: "pre",
    transform(code, id) {
      const file = id.split("?")[0].replace(/\\/g, "/");
      if (!file.endsWith("/jsvectormap/dist/maps/world.js")) return null;
      if (code.includes("from \"jsvectormap\"")) return null;
      return {
        code: `import jsVectorMap from "jsvectormap";\n${code}`,
        map: null,
      };
    },
  };
}

export default defineConfig({
  plugins: [react(), jsvectormapWorld()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      // Same host as the API so session cookies and WebAuthn rpId match.
      // changeOrigin stays false: FastAPI reads Host for passkey origins.
      "/api": {
        target: "http://127.0.0.1:8765",
        changeOrigin: false,
        timeout: 360_000,
        proxyTimeout: 360_000,
      },
    },
  },
  preview: {
    port: 4173,
    strictPort: true,
  },
});
