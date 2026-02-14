
import { WebhookServer } from "../webhook.js";
import { AIManager } from "../integrations/ai.js";
import http from 'http';
import assert from 'assert';

async function testWebhook() {
    console.log("Testing WebhookServer...");

    let receivedAlert: any = null;
    const port = 3001;

    const webhook = new WebhookServer(port, (alert) => {
        receivedAlert = alert;
    });

    webhook.start();

    // Allow server to start
    await new Promise(resolve => setTimeout(resolve, 500));

    const payload = JSON.stringify({
        rule: { level: 10, description: "Test Alert" },
        data: { srcip: "1.2.3.4" }
    });

    const req = http.request({
        hostname: 'localhost',
        port: port,
        path: '/wazuh-alert',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': payload.length
        }
    }, (res) => {
        assert.strictEqual(res.statusCode, 200);
        res.on('data', () => { });
        res.on('end', () => {
            console.log("Webhook response received.");
        });
    });

    req.on('error', (e) => {
        console.error(`Problem with request: ${e.message}`);
        process.exit(1);
    });

    req.write(payload);
    req.end();

    // Wait for callback
    await new Promise(resolve => setTimeout(resolve, 500));

    assert.ok(receivedAlert, "Alert should have been received");
    assert.strictEqual(receivedAlert.rule.description, "Test Alert");
    console.log("WebhookServer Test Passed ✅");
    process.exit(0); // Exit successfully
}

testWebhook().catch(err => {
    console.error("Test Failed:", err);
    process.exit(1);
});
