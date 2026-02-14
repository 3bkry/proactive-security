import http from 'http';
import { log } from "@sentinel/core";

export class WebhookServer {
    private server: http.Server;
    private port: number;
    private onAlertCallback: (alert: any) => void;

    constructor(port: number = 3000, onAlert: (alert: any) => void) {
        this.port = port;
        this.onAlertCallback = onAlert;
        this.server = http.createServer(this.handleRequest.bind(this));
    }

    public start() {
        this.server.listen(this.port, () => {
            log(`[Webhook] Listening on port ${this.port} for Wazuh alerts`);
        });
    }

    private handleRequest(req: http.IncomingMessage, res: http.ServerResponse) {
        if (req.method === 'POST' && req.url === '/wazuh-alert') {
            let body = '';
            req.on('data', chunk => {
                body += chunk.toString();
            });
            req.on('end', () => {
                try {
                    const alert = JSON.parse(body);
                    log(`[Webhook] Received Wazuh alert: ${alert.rule?.description || "Unknown"}`);
                    this.onAlertCallback(alert);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ status: 'received' }));
                } catch (e) {
                    log(`[Webhook] Error parsing alert: ${e}`);
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'invalid json' }));
                }
            });
        } else {
            res.writeHead(404);
            res.end();
        }
    }
}
