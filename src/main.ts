// Meron Mail for Obsidian.
// Step 1: connection and login check against an IMAP (993, TLS) and SMTP
// (587, STARTTLS) server. The full mail view comes later.
import { App, Notice, Plugin, PluginSettingTab, Setting } from "obsidian";
import * as net from "net";
import * as tls from "tls";

interface MeronSettings {
  imapHost: string;
  imapPort: number;
  smtpHost: string;
  smtpPort: number;
  username: string;
  password: string;
  // Hex SHA-256 fingerprint (e.g. "AB:CD:...") of a self-signed certificate
  // the user has accepted. Empty means normal certificate validation.
  pinnedFingerprint: string;
}

const DEFAULT_SETTINGS: MeronSettings = {
  imapHost: "100.107.227.53",
  imapPort: 993,
  smtpHost: "100.107.227.53",
  smtpPort: 587,
  username: "",
  password: "",
  pinnedFingerprint: "",
};

const TIMEOUT_MS = 15000;

/** Reads from `socket` until `done(buffer)` returns true, or fails on timeout/close. */
function readUntil(
  socket: net.Socket | tls.TLSSocket,
  done: (buffer: string) => boolean,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => finish(new Error("Timed out waiting for the server")), TIMEOUT_MS);
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      if (done(buffer)) finish(null);
    };
    const onError = (err: Error) => finish(err);
    const onClose = () => finish(new Error("Connection closed by the server"));
    const finish = (err: Error | null) => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
      if (err) reject(err);
      else resolve(buffer);
    };
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

/**
 * Checks the server certificate. With a pinned fingerprint, only that certificate
 * is accepted. Without one, the certificate must be trusted by the system; if it
 * is not (for example self-signed), the error shows its fingerprint so the user
 * can check it and pin it.
 */
function verifyCertificate(
  socket: tls.TLSSocket,
  pinnedFingerprint: string,
): void {
  const seen = socket.getPeerCertificate().fingerprint256 ?? "";
  if (pinnedFingerprint !== "") {
    if (seen.toUpperCase() !== pinnedFingerprint.toUpperCase()) {
      throw new Error(`The server certificate does not match the pinned fingerprint (server sent ${seen}).`);
    }
    return;
  }
  if (!socket.authorized) {
    throw new Error(
      `The server certificate is not trusted (${socket.authorizationError}). ` +
        `Its SHA-256 fingerprint is ${seen}. If this is your server, paste that into ` +
        `"Pinned certificate SHA-256" in the settings and test again.`,
    );
  }
}

function connectTls(
  host: string,
  port: number,
  pinnedFingerprint: string,
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    // Always complete the handshake and decide in verifyCertificate, so the
    // fingerprint can be shown. Nothing is sent before that check passes.
    const socket = tls.connect({
      host,
      port,
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false,
    });
    socket.setTimeout(TIMEOUT_MS, () => socket.destroy(new Error("Connection timed out")));
    socket.once("secureConnect", () => {
      try {
        verifyCertificate(socket, pinnedFingerprint);
      } catch (err) {
        socket.destroy();
        reject(err);
        return;
      }
      socket.setTimeout(0);
      resolve(socket);
    });
    socket.once("error", reject);
  });
}

function connectPlain(host: string, port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    socket.setTimeout(TIMEOUT_MS, () => socket.destroy(new Error("Connection timed out")));
    socket.once("connect", () => {
      socket.setTimeout(0);
      resolve(socket);
    });
    socket.once("error", reject);
  });
}

/** Logs in over IMAP on port 993 (implicit TLS) and logs out again. */
export async function checkImap(s: MeronSettings): Promise<string> {
  const socket = await connectTls(s.imapHost, s.imapPort, s.pinnedFingerprint);
  try {
    await readUntil(socket, (b) => /^\* (OK|PREAUTH)/m.test(b));
    socket.write(`a1 LOGIN "${escapeImap(s.username)}" "${escapeImap(s.password)}"\r\n`);
    const reply = await readUntil(socket, (b) => /^a1 (OK|NO|BAD)/m.test(b));
    if (!/^a1 OK/m.test(reply)) {
      const line = reply.split("\r\n").find((l) => l.startsWith("a1 ")) ?? "";
      throw new Error(`IMAP login failed: ${line}`);
    }
    socket.write("a2 LOGOUT\r\n");
    return "IMAP login succeeded (TLS, port " + s.imapPort + ").";
  } finally {
    socket.destroy();
  }
}

/** Authenticates over SMTP on port 587: STARTTLS, then AUTH PLAIN. Nothing is sent. */
export async function checkSmtp(s: MeronSettings): Promise<string> {
  const socket = await connectPlain(s.smtpHost, s.smtpPort);
  try {
    await readUntil(socket, endsWithFinalLine("220"));
    socket.write("EHLO meron.local\r\n");
    await readUntil(socket, endsWithFinalLine("250"));
    socket.write("STARTTLS\r\n");
    await readUntil(socket, endsWithFinalLine("220"));

    const secure = await upgradeToTls(socket, s.smtpHost, s.pinnedFingerprint);
    try {
      secure.write("EHLO meron.local\r\n");
      await readUntil(secure, endsWithFinalLine("250"));
      const token = Buffer.from(`\0${s.username}\0${s.password}`, "utf8").toString("base64");
      secure.write(`AUTH PLAIN ${token}\r\n`);
      const reply = await readUntil(secure, endsWithFinalLine("235", "535", "534", "530", "454"));
      const last = lastLine(reply);
      if (!last.startsWith("235 ")) {
        throw new Error(`SMTP login failed: ${last}`);
      }
      secure.write("QUIT\r\n");
      return "SMTP login succeeded (STARTTLS, port " + s.smtpPort + ").";
    } finally {
      secure.destroy();
    }
  } finally {
    socket.destroy();
  }
}

function upgradeToTls(
  socket: net.Socket,
  host: string,
  pinnedFingerprint: string,
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({
      socket,
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false,
    });
    secure.once("secureConnect", () => {
      try {
        verifyCertificate(secure, pinnedFingerprint);
      } catch (err) {
        secure.destroy();
        reject(err);
        return;
      }
      resolve(secure);
    });
    secure.once("error", reject);
  });
}

/** Done once the buffer ends with a complete final (non-continuation) reply line. */
function endsWithFinalLine(...codes: string[]): (b: string) => boolean {
  return (b) => {
    if (!b.endsWith("\r\n")) return false;
    const last = lastLine(b);
    return codes.some((c) => last.startsWith(c + " ") || last === c);
  };
}

function lastLine(b: string): string {
  const lines = b.split("\r\n").filter((l) => l.length > 0);
  return lines[lines.length - 1] ?? "";
}

function escapeImap(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export default class MeronMailPlugin extends Plugin {
  settings: MeronSettings = DEFAULT_SETTINGS;

  async onload(): Promise<void> {
    await this.loadSettings();
    this.addSettingTab(new MeronSettingTab(this.app, this));

    this.addCommand({
      id: "test-connection",
      name: "Test mail server connection",
      callback: () => void this.runConnectionTest(),
    });
  }

  async runConnectionTest(): Promise<void> {
    const s = this.settings;
    if (!s.username || !s.password) {
      new Notice("Meron Mail: enter a username and password in settings first.");
      return;
    }
    try {
      new Notice(await checkImap(s), 8000);
    } catch (err) {
      new Notice(`IMAP: ${errorText(err)}`, 30000);
      return;
    }
    try {
      new Notice(await checkSmtp(s), 8000);
    } catch (err) {
      new Notice(`SMTP: ${errorText(err)}`, 30000);
    }
  }

  async loadSettings(): Promise<void> {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

class MeronSettingTab extends PluginSettingTab {
  plugin: MeronMailPlugin;

  constructor(app: App, plugin: MeronMailPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display(): void {
    const { containerEl } = this;
    const s = this.plugin.settings;
    containerEl.empty();
    containerEl.createEl("h2", { text: "Meron Mail" });

    new Setting(containerEl).setName("IMAP host").addText((t) =>
      t.setValue(s.imapHost).onChange(async (v) => {
        s.imapHost = v.trim();
        await this.plugin.saveSettings();
      }),
    );
    new Setting(containerEl)
      .setName("IMAP port")
      .setDesc("993 uses SSL/TLS from the first byte.")
      .addText((t) =>
        t.setValue(String(s.imapPort)).onChange(async (v) => {
          s.imapPort = Number(v) || 993;
          await this.plugin.saveSettings();
        }),
      );
    new Setting(containerEl).setName("SMTP host").addText((t) =>
      t.setValue(s.smtpHost).onChange(async (v) => {
        s.smtpHost = v.trim();
        await this.plugin.saveSettings();
      }),
    );
    new Setting(containerEl)
      .setName("SMTP port")
      .setDesc("587 uses STARTTLS.")
      .addText((t) =>
        t.setValue(String(s.smtpPort)).onChange(async (v) => {
          s.smtpPort = Number(v) || 587;
          await this.plugin.saveSettings();
        }),
      );
    new Setting(containerEl).setName("Username").addText((t) =>
      t.setValue(s.username).onChange(async (v) => {
        s.username = v.trim();
        await this.plugin.saveSettings();
      }),
    );
    new Setting(containerEl)
      .setName("Password or app password")
      .setDesc("Stored in this vault's plugin data. Use an app password if your server offers one.")
      .addText((t) => {
        t.inputEl.type = "password";
        t.setValue(s.password).onChange(async (v) => {
          s.password = v;
          await this.plugin.saveSettings();
        });
      });
    new Setting(containerEl)
      .setName("Pinned certificate SHA-256 (optional)")
      .setDesc("For a self-signed server certificate. Leave empty to require a trusted certificate.")
      .addText((t) =>
        t.setPlaceholder("AB:CD:...").setValue(s.pinnedFingerprint).onChange(async (v) => {
          s.pinnedFingerprint = v.trim();
          await this.plugin.saveSettings();
        }),
      );
    new Setting(containerEl)
      .setName("Test connection")
      .setDesc("Logs in to IMAP and SMTP with these settings. Nothing is downloaded or sent.")
      .addButton((b) =>
        b.setButtonText("Test").setCta().onClick(() => void this.plugin.runConnectionTest()),
      );
  }
}
