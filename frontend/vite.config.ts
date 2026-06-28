import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The frontend talks to the TS orchestrator (default :8000) for the audit
// pipeline and reads the AuditRegistry contract directly via wagmi for /verify.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/audit": "http://127.0.0.1:8000",
      "/attest": "http://127.0.0.1:8000",
      "/verify": "http://127.0.0.1:8000",
      "/history": "http://127.0.0.1:8000",
      "/health": "http://127.0.0.1:8000",
    },
  },
});
