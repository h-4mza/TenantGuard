import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class AlertHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        print("=" * 60, flush=True)
        print("[ALERT WEBHOOK RECEIVED]", flush=True)
        try:
            payload = json.loads(post_data.decode('utf-8'))
            status = payload.get('status', 'unknown')
            alerts = payload.get('alerts', [])
            print(f"Overall Status: {status} | Total Alerts: {len(alerts)}", flush=True)
            for idx, alert in enumerate(alerts, 1):
                labels = alert.get('labels', {})
                annotations = alert.get('annotations', {})
                rule = labels.get('alertname', 'Unknown')
                severity = labels.get('severity', 'Unknown')
                mitre = labels.get('mitre_technique', 'N/A')
                summary = annotations.get('summary', 'No summary')
                print(f"  [{idx}] Rule: {rule} | Severity: {severity} | MITRE: {mitre}", flush=True)
                print(f"      Summary: {summary}", flush=True)
                print(f"      Labels: {labels}", flush=True)
            print("-" * 60, flush=True)
            print("Raw Payload:", flush=True)
            print(json.dumps(payload, indent=2), flush=True)
        except Exception as e:
            print(f"Error parsing alert payload ({e}): {post_data.decode('utf-8', errors='replace')}", flush=True)
        print("=" * 60, flush=True)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "received"}\n')

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "alert_receiver_ready"}\n')

    def log_message(self, format, *args):
        # Suppress default noisy access logs to keep stdout focused on alerts
        pass

if __name__ == '__main__':
    port = 8080
    print(f"[*] Starting TenantGuard Alert Receiver on port {port}...", flush=True)
    server = HTTPServer(('0.0.0.0', port), AlertHandler)
    server.serve_forever()
