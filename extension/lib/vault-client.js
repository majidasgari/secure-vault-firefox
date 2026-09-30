/*
 * Client for the Secure Vault browser bridge.
 *
 * The vault app (desktop or `vault.web`) serves a loopback-only HTTP listener (default
 * http://127.0.0.1:8788/). A browser cannot read the vault's token files — that is why the
 * server hands a *separate*, deliberately narrow token to a loopback client that asks for it
 * with `X-Vault-Claim: 1` (POST /api/session/claim, scope "browser"). That token is only valid
 * for `/api/autofill/*`, whose three calls are: status, match (metadata only) and reveal (the
 * fields of one already-matched entry, always audited in the vault).
 *
 * This file holds no credential and never stores one: it returns what the vault answers and
 * nothing is written to disk except the port and the token.
 */
(function (global) {
  "use strict";

  /** Default listener port (the vault's own default; Settings → Web shows the real one). */
  const DEFAULT_PORT = 8788;

  /** Ports probed when the configured one does not answer (the vault picks a free one if busy). */
  const PROBE_PORTS = [8788, 8789, 8790, 8791, 8792, 8793, 8794, 8795, 8796, 8797, 8798];

  /** A typed failure the UI can branch on (code mirrors the vault's error codes). */
  class VaultError extends Error {
    constructor(code, status, details) {
      super(code);
      this.name = "VaultError";
      this.code = code;
      this.status = status || 0;
      this.details = details || {};
    }
  }

  /** Does a vault web server answer on this port? Uses the public catalogue endpoint. */
  async function probePort(port) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/i18n?lang=fa`, {
        cache: "no-store"
      });
      if (!response.ok) return false;
      const data = await response.json().catch(() => null);
      return Boolean(data && Array.isArray(data._languages) && typeof data["app.title"] === "string");
    } catch (error) {
      return false;
    }
  }

  class VaultClient {
    constructor() {
      this.port = DEFAULT_PORT;
      this.token = "";
      this.configured = false;
    }

    /** Load the saved port/token from extension storage (the event page may have been unloaded). */
    async configure() {
      if (this.configured) return this;
      const stored = await browser.storage.local.get({
        port: DEFAULT_PORT,
        token: "",
        tokenPort: 0
      });
      this.port = Number(stored.port) || DEFAULT_PORT;
      if (stored.token && Number(stored.tokenPort) === this.port) {
        this.token = String(stored.token);
      }
      this.configured = true;
      return this;
    }

    baseUrl() {
      return `http://127.0.0.1:${this.port}`;
    }

    /** Remember the port (and drop a token that belonged to another port). */
    async setPort(port) {
      const value = Number(port) || DEFAULT_PORT;
      if (value !== this.port) {
        this.token = "";
        await browser.storage.local.set({ port: value, token: "", tokenPort: 0 });
      }
      this.port = value;
      return value;
    }

    async saveToken() {
      await browser.storage.local.set({ token: this.token, tokenPort: this.port });
    }

    async forgetToken() {
      this.token = "";
      await browser.storage.local.set({ token: "", tokenPort: 0 });
    }

    /** Ask the vault for the narrow browser token (loopback-only, custom header required). */
    async claim() {
      const response = await fetch(`${this.baseUrl()}/api/session/claim`, {
        method: "POST",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-Vault-Claim": "1" },
        body: JSON.stringify({ scope: "browser" })
      }).catch(() => null);
      if (!response) throw new VaultError("VAULT_NOT_RUNNING", 0, { port: this.port });
      const data = await response.json().catch(() => null);
      if (response.status === 401 || response.status === 403) {
        throw new VaultError("CLAIM_DENIED", response.status, {});
      }
      if (!data || data.ok !== true || !data.token) {
        const info = (data && data.error) || {};
        throw new VaultError(info.code || "CLAIM_FAILED", response.status, info.details || {});
      }
      // The reply must say it is the browser scope. A vault built before the bridge existed
      // answers with the *web* token instead — which can read and write the whole vault — so it
      // is refused rather than stored (the add-on never holds more than it needs).
      if (data.scope !== "browser") {
        throw new VaultError("BRIDGE_MISSING", response.status, { scope: String(data.scope || "") });
      }
      this.token = String(data.token);
      await this.saveToken();
      return this.token;
    }

    /** One authenticated JSON request; 401 clears the cached token and re-raises. */
    async request(path, options) {
      const opts = options || {};
      const method = opts.method || "GET";
      const headers = {};
      if (opts.token !== false) {
        if (!this.token) await this.claim();
        headers["X-Vault-Token"] = this.token;
      }
      const init = { method, headers, cache: "no-store" };
      if (opts.body !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(opts.body);
      }
      const response = await fetch(`${this.baseUrl()}${path}`, init).catch(() => {
        throw new VaultError("VAULT_NOT_RUNNING", 0, { port: this.port });
      });
      const data = await response.json().catch(() => null);
      if (response.status === 404 && path.indexOf("/api/autofill/") === 0) {
        // The listener answered, but it has no bridge: that is an old build, not "no entry for
        // this site" — saying the wrong one sent the user looking for a missing credential.
        throw new VaultError("BRIDGE_MISSING", 404, { path: path });
      }
      if (response.status === 401) {
        await this.forgetToken();
        throw new VaultError("UNAUTHORIZED", 401, {});
      }
      if (!data) throw new VaultError("INVALID_RESPONSE", response.status, {});
      if (data.ok !== true) {
        const info = data.error || {};
        // Keep the vault's own message: several distinct refusals share PERMISSION_DENIED and
        // only the message says which one it was (host_mismatch, too_many_reveals, …).
        const details = Object.assign({}, info.details || {});
        if (info.message) details.message = info.message;
        throw new VaultError(info.code || "ERROR", response.status, details);
      }
      return data.result;
    }

    /** Find the vault when the configured port is dead (it may have taken a free port). */
    async discover() {
      const candidates = [this.port].concat(PROBE_PORTS.filter((port) => port !== this.port));
      for (const port of candidates) {
        if (await probePort(port)) {
          if (port !== this.port) await this.setPort(port);
          return port;
        }
      }
      return 0;
    }

    /**
     * Run one bridge call, recovering from the two things that change under a long-lived client:
     * the vault rotates its browser token on every start, and its port can move.
     */
    async call(path, options) {
      try {
        return await this.request(path, options);
      } catch (error) {
        if (error.code === "UNAUTHORIZED") {
          await this.claim();
          return await this.request(path, options);
        }
        if (error.code === "VAULT_NOT_RUNNING") {
          const found = await this.discover();
          if (found) {
            this.token = "";
            return await this.request(path, options);
          }
        }
        throw error;
      }
    }

    /** Bridge state: enabled switch, lock state, credential count. */
    async status() {
      return this.call("/api/autofill/status?t=" + Date.now());
    }

    /** Credential candidates for a page host (metadata only — never a password). */
    async match(host, url) {
      return this.call("/api/autofill/match", {
        method: "POST",
        body: { host: host, url: url || "" }
      });
    }

    /** The fields of one matched entry (the vault audits this call). */
    async reveal(path, host) {
      return this.call("/api/autofill/reveal", {
        method: "POST",
        body: { path: path, host: host || "" }
      });
    }
  }

  global.SecureVaultClient = VaultClient;
  global.SecureVaultError = VaultError;
  global.SecureVaultProbe = probePort;
  global.SecureVaultDefaults = { port: DEFAULT_PORT, probePorts: PROBE_PORTS };
})(globalThis);
