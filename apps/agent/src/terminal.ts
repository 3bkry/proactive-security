import * as pty from "node-pty";
import { EventEmitter } from "events";
import { log } from "@sentinel/core";
import os from "os";

export class TerminalManager extends EventEmitter {
    private ptyProcess: pty.IPty | null = null;
    private shell: string;

    constructor() {
        super();
        this.shell = os.platform() === "win32" ? "powershell.exe" : "bash";
    }

    public start() {
        if (this.ptyProcess) return;

        this.ptyProcess = pty.spawn(this.shell, [], {
            name: "xterm-color",
            cols: 80,
            rows: 30,
            cwd: process.env.HOME,
            env: process.env as any,
        });

        this.ptyProcess.onData((data) => {
            // Emit data for UI or Agent processing
            this.emit("data", data);
        });

        this.ptyProcess.onExit(({ exitCode, signal }) => {
            log(`Terminal exited with code ${exitCode}, signal ${signal}`);
            this.ptyProcess = null;
            this.emit("exit", exitCode);
        });

        log(`Terminal started: ${this.shell}`);
    }

    public write(data: string) {
        if (this.ptyProcess) {
            this.ptyProcess.write(data);
        }
    }

    public resize(cols: number, rows: number) {
        if (this.ptyProcess) {
            this.ptyProcess.resize(cols, rows);
        }
    }

    public kill() {
        if (this.ptyProcess) {
            this.ptyProcess.kill();
        }
    }
}
