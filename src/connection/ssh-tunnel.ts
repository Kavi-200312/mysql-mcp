import { spawn, ChildProcess } from "child_process";
import net from "net";
import { auditLogger } from "../audit/logger.js";

export interface SshTunnelOptions {
  enabled: boolean;
  sshHost: string;
  sshPort: number;
  sshUser: string;
  sshKeyPath?: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
  connectionTimeoutMs?: number;
}

export class SshTunnelManager {
  private tunnelProcess: ChildProcess | null = null;
  private options: SshTunnelOptions;
  private isClosing = false;

  constructor(options: SshTunnelOptions) {
    this.options = {
      ...options,
      connectionTimeoutMs: options.connectionTimeoutMs || 15000
    };
  }

  /**
   * Starts or verifies the SSH tunnel and waits until the local port accepts connections.
   */
  public async ensureTunnel(): Promise<void> {
    if (!this.options.enabled) {
      auditLogger.info("SSH tunnel disabled in configuration. Connecting directly to local port.");
      return;
    }

    const { localPort } = this.options;

    // Check if the local port is already reachable (e.g. existing active tunnel)
    const isAlreadyOpen = await this.checkPortOpen("127.0.0.1", localPort);
    if (isAlreadyOpen) {
      auditLogger.info(`Local port 127.0.0.1:${localPort} is already active and listening. Reusing existing tunnel.`);
      return;
    }

    if (!this.options.sshHost || !this.options.sshUser) {
      throw new Error("SSH tunnel is enabled but SSH_HOST or SSH_USER is not configured in .env");
    }

    auditLogger.info(
      {
        host: this.options.sshHost,
        user: this.options.sshUser,
        localPort,
        remoteTarget: `${this.options.remoteHost}:${this.options.remotePort}`
      },
      "Starting SSH tunnel..."
    );

    const sshArgs = [
      "-N", // Do not execute a remote command
      "-L",
      `127.0.0.1:${localPort}:${this.options.remoteHost}:${this.options.remotePort}`,
      "-p",
      String(this.options.sshPort),
      "-o",
      "ExitOnForwardFailure=yes",
      "-o",
      "ServerAliveInterval=30",
      "-o",
      "ServerAliveCountMax=3"
    ];

    if (this.options.sshKeyPath && this.options.sshKeyPath.trim().length > 0) {
      sshArgs.push("-i", this.options.sshKeyPath.trim());
    }

    sshArgs.push(`${this.options.sshUser}@${this.options.sshHost}`);

    let stderrOutput = "";

    try {
      this.tunnelProcess = spawn("ssh", sshArgs, {
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true
      });

      this.tunnelProcess.stderr?.on("data", (chunk: Buffer) => {
        stderrOutput += chunk.toString();
      });

      this.tunnelProcess.on("exit", (code, signal) => {
        if (!this.isClosing) {
          auditLogger.warn({ code, signal, stderr: stderrOutput }, "SSH tunnel process terminated unexpectedly");
        }
        this.tunnelProcess = null;
      });

      // Poll until local port is open or timeout reached
      await this.waitForPort("127.0.0.1", localPort, this.options.connectionTimeoutMs!);
      auditLogger.info(`SSH tunnel successfully established on 127.0.0.1:${localPort}`);
    } catch (err: unknown) {
      this.close();
      const errMsg = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to establish SSH tunnel: ${errMsg}. SSH output: ${stderrOutput.trim()}`);
    }
  }

  /**
   * Probes whether a TCP port is open.
   */
  private checkPortOpen(host: string, port: number): Promise<boolean> {
    return new Promise(resolve => {
      const socket = new net.Socket();
      socket.setTimeout(1000);

      socket.once("connect", () => {
        socket.destroy();
        resolve(true);
      });

      socket.once("timeout", () => {
        socket.destroy();
        resolve(false);
      });

      socket.once("error", () => {
        socket.destroy();
        resolve(false);
      });

      socket.connect(port, host);
    });
  }

  /**
   * Polls until the port is reachable or timeout expires.
   */
  private async waitForPort(host: string, port: number, timeoutMs: number): Promise<void> {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      if (this.tunnelProcess && this.tunnelProcess.exitCode !== null) {
        throw new Error(`SSH process exited prematurely with code ${this.tunnelProcess.exitCode}`);
      }

      const isOpen = await this.checkPortOpen(host, port);
      if (isOpen) {
        return;
      }
      await new Promise(r => setTimeout(r, 250));
    }
    throw new Error(`Timed out waiting for tunnel port ${host}:${port} after ${timeoutMs}ms`);
  }

  /**
   * Cleanly closes the tunnel.
   */
  public close(): void {
    this.isClosing = true;
    if (this.tunnelProcess) {
      try {
        this.tunnelProcess.kill("SIGTERM");
      } catch {
        // Ignore kill errors
      }
      this.tunnelProcess = null;
    }
  }
}
