import * as pty from "node-pty";
import { EventEmitter } from "events";
import { log } from "@sentinel/core";
import os from "os";
export class TerminalManager extends EventEmitter {
    ptyProcess = null;
    shell;
    constructor() {
        super();
        this.shell = os.platform() === "win32" ? "powershell.exe" : "bash";
    }
    start() {
        if (this.ptyProcess)
            return;
        this.ptyProcess = pty.spawn(this.shell, [], {
            name: "xterm-color",
            cols: 80,
            rows: 30,
            cwd: process.env.HOME,
            env: process.env,
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
    write(data) {
        if (this.ptyProcess) {
            this.ptyProcess.write(data);
        }
    }
    resize(cols, rows) {
        if (this.ptyProcess) {
            this.ptyProcess.resize(cols, rows);
        }
    }
    kill() {
        if (this.ptyProcess) {
            this.ptyProcess.kill();
        }
    }
}
//# sourceMappingURL=terminal.js.map