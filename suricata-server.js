// suricata-server.js - Mock Suricata log server
const http = require('http');

const mockSuricataAlerts = [
  {
    timestamp: new Date().toISOString(),
    alert: {
      signature: "ET SCAN Potential SSH Scan",
      category: "Attempted Information Leak",
      severity: 2
    },
    src_ip: "203.0.113.45",
    dest_ip: "192.168.1.100",
    dest_port: 22,
    proto: "TCP",
    event_type: "alert"
  },
  {
    timestamp: new Date(Date.now() - 300000).toISOString(),
    alert: {
      signature: "ET POLICY Curl User-Agent",
      category: "Potential Corporate Privacy Violation",
      severity: 3
    },
    src_ip: "198.51.100.23",
    dest_ip: "192.168.1.100",
    dest_port: 80,
    proto: "TCP",
    event_type: "alert"
  },
  {
    timestamp: new Date(Date.now() - 600000).toISOString(),
    alert: {
      signature: "ET TROJAN Possible Malware Download",
      category: "A Network Trojan was detected",
      severity: 1
    },
    src_ip: "192.0.2.67",
    dest_ip: "192.168.1.150",
    dest_port: 443,
    proto: "TCP",
    event_type: "alert"
  }
];

const server = http.createServer((req, res) => {
  if (req.url === '/logs' && req.method === 'GET') {
    // Add some random new alerts occasionally
    if (Math.random() > 0.5) {
      const newAlert = {
        timestamp: new Date().toISOString(),
        alert: {
          signature: ["ET SCAN Nmap Scripting Engine", 
                     "ET WEB_SERVER SQL Injection Attempt",
                     "ET EXPLOIT Possible CVE-2023-1234 Exploit"][Math.floor(Math.random() * 3)],
          category: "Attempted Administrator Privilege Gain",
          severity: Math.floor(Math.random() * 3) + 1
        },
        src_ip: `10.0.0.${Math.floor(Math.random() * 255)}`,
        dest_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
        dest_port: [80, 443, 22, 3389][Math.floor(Math.random() * 4)],
        proto: "TCP",
        event_type: "alert"
      };
      mockSuricataAlerts.push(newAlert);
    }
    
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    });
    res.end(JSON.stringify(mockSuricataAlerts.slice(-20)));
  } else if (req.url === '/health') {
    res.writeHead(200);
    res.end('OK');
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

const PORT = 9999;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║       🔍 SURICATA MOCK SERVER                       ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  ✅ Running on: http://localhost:${PORT}               ║
║  📊 Logs:        http://localhost:${PORT}/logs         ║
║  🩺 Health:      http://localhost:${PORT}/health       ║
║                                                      ║
║  This simulates a real Suricata IDS server          ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
  `);
});