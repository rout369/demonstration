// server.js - Mock backend with security events
const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

// Error handling for uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// CORS configuration - allow all origins for development
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Serve static files (for dashboard.html)
app.use(express.static(__dirname));

// ... existing code ...
app.use(express.json());
app.use(express.static(__dirname));

app.use((req, res, next) => {
  const platform = req.headers['x-app-platform'];
  const userAgent = req.headers['user-agent'] || '';

  // 1. Detect if it's a Mobile Request (React Native uses okhttp on Android / CFNetwork on iOS)
  const isMobile = platform === 'react-native' || userAgent.includes('okhttp') || userAgent.includes('CFNetwork');

  if (isMobile) {
    // 2. Mobile-Specific Threat: Detect Rooted/Jailbroken simulation
    if (req.headers['x-device-integrity'] === 'fail') {
      logSecurityEvent('MOBILE_THREAT', {
        message: '🚨 SECURITY: Request from Compromised/Rooted Device',
        ip: req.ip,
        endpoint: req.originalUrl
      });
    }

    // 3. Detect Man-in-the-Middle (MITM) / Proxy patterns
    if (req.headers['proxy-connection'] || req.headers['via']) {
      logSecurityEvent('MITM_DETECTION', {
        message: '⚠️ MITM: Potential Interception Proxy Detected',
        ip: req.ip
      });
    }
  }
  next();
});


// Store for monitoring data
let securityEvents = [];
let apiMetrics = [];

// Initialize with some demo data
function initializeDemoData() {
  securityEvents = [];
  apiMetrics = [];
  
  logSecurityEvent('SYSTEM_START', { 
    message: 'Demo system initialized',
    timestamp: new Date().toISOString()
  });
  
  const testIps = ['192.168.1.1', '10.0.0.1', '172.16.0.1'];
  for (let i = 0; i < 5; i++) {
    const metric = {
      timestamp: new Date(Date.now() - (i * 60000)).toISOString(),
      endpoint: 'HEALTH_CHECK',
      method: 'GET',
      ip: testIps[Math.floor(Math.random() * testIps.length)],
      userAgent: 'Demo-Agent/1.0',
      status: 'success',
      responseTime: Math.floor(Math.random() * 80) + 20
    };
    apiMetrics.push(metric);
  }
}

// Initialize on startup
initializeDemoData();

// RESET ENDPOINT - This must be defined BEFORE other routes
app.post('/api/reset', (req, res) => {
  try {
    console.log('🔄 Reset request received');
    initializeDemoData();
    
    res.json({ 
      success: true, 
      message: 'Demo data reset successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Reset endpoint error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  try {
    logRequest(req, 'HEALTH_CHECK');
    res.json({ 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      uptime: process.uptime()
    });
  } catch (error) {
    console.error('Health endpoint error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Simulate brute force detection
    const failedAttempts = countFailedLogins(username);
    if (failedAttempts > 5) {
      logSecurityEvent('BRUTE_FORCE_ATTEMPT', { 
        username, 
        ip: req.ip.replace('::ffff:', ''),
        attempts: failedAttempts 
      });
    }
    
    if (username === 'admin' && password === 'secure123') {
      logRequest(req, 'LOGIN_SUCCESS');
      res.json({ 
        token: 'fake-jwt-token-' + Date.now(), 
        role: 'admin',
        expiresIn: '24h'
      });
    } else {
      logRequest(req, 'LOGIN_FAILED');
      logSecurityEvent('AUTH_FAILURE', { 
        username, 
        ip: req.ip.replace('::ffff:', '') 
      });
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login endpoint error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Users endpoint
app.get('/api/users', (req, res) => {
  try {
    // Check for SQL injection patterns
    const query = req.query.search || '';
    if (query.includes("' OR '1'='1") || query.includes('; DROP') || query.includes('UNION SELECT')) {
      logSecurityEvent('SQL_INJECTION_ATTEMPT', { 
        query, 
        ip: req.ip.replace('::ffff:', ''),
        userAgent: req.headers['user-agent'] || 'unknown'
      });
    }
    
    logRequest(req, 'USER_LIST');
    res.json([
      { id: 1, name: 'John Doe', email: 'john@example.com', role: 'user' },
      { id: 2, name: 'Jane Smith', email: 'jane@example.com', role: 'admin' },
      { id: 3, name: 'Bob Johnson', email: 'bob@example.com', role: 'user' }
    ]);
  } catch (error) {
    console.error('Users endpoint error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Data upload endpoint
app.post('/api/data', (req, res) => {
  try {
    // Check for large payloads (potential DoS)
    const contentLength = parseInt(req.headers['content-length'] || '0');
    if (contentLength > 10000) { // 10KB limit
      logSecurityEvent('LARGE_PAYLOAD', { 
        size: contentLength,
        ip: req.ip.replace('::ffff:', '')
      });
      return res.status(413).json({ error: 'Payload too large. Maximum 10KB allowed.' });
    }
    
    logRequest(req, 'DATA_UPLOAD');
    res.json({ 
      received: true, 
      id: Date.now(),
      message: 'Data uploaded successfully',
      size: contentLength
    });
  } catch (error) {
    console.error('Data upload endpoint error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Attack simulation endpoint 
app.post('/api/simulate/attack', (req, res) => {
  try {
    const { attackType } = req.body;
    
    if (!attackType) {
      return res.status(400).json({ error: 'Attack type required' });
    }
    
    console.log(` Simulating attack: ${attackType}`);
    
    switch(attackType) {
      case 'brute-force':
        // Simulate 10 rapid login attempts
        for (let i = 0; i < 10; i++) {
          setTimeout(() => {
            logSecurityEvent('BRUTE_FORCE_SIMULATION', {
              attempt: i+1,
              username: 'attacker',
              ip: '192.168.1.' + (100 + i),
              timestamp: new Date().toISOString()
            });
          }, i * 100);
        }
        break;
        
      case 'sql-injection':
        logSecurityEvent('SQL_INJECTION_SIMULATION', {
          query: "admin' OR '1'='1' --",
          ip: '10.0.0.50',
          userAgent: 'Mozilla/5.0 (AttackBot)'
        });
        break;
        
      case 'ddos':
        // Simulate traffic spike
        logSecurityEvent('DDOS_SIMULATION', {
          requestsPerSecond: 1500,
          duration: '30s',
          endpoint: '/api/login',
          sourceIPs: ['203.0.113.1', '198.51.100.2', '192.0.2.3']
        });
        break;
        
      default:
        return res.status(400).json({ error: 'Unknown attack type' });
    }
    
    res.json({ 
      success: true,
      simulating: attackType,
      message: `Attack simulation "${attackType}" started`,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Attack simulation error:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

// Monitoring endpoints
app.get('/api/security/events', (req, res) => {
  try {
    res.json(securityEvents.slice(-50)); // Last 50 events
  } catch (error) {
    console.error('Security events endpoint error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/metrics', (req, res) => {
  try {
    res.json(apiMetrics.slice(-100));
  } catch (error) {
    console.error('Metrics endpoint error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper functions
function logRequest(req, endpoint) {
  const metric = {
    timestamp: new Date().toISOString(),
    endpoint: endpoint,
    method: req.method,
    ip: req.ip.replace('::ffff:', ''),
    userAgent: req.headers['user-agent'] || 'unknown',
    status: 'success',
    responseTime: Math.floor(Math.random() * 100) + 50 // 50-150ms
  };
  apiMetrics.push(metric);
  
  // Keep only last 1000 metrics
  if (apiMetrics.length > 1000) {
    apiMetrics = apiMetrics.slice(-1000);
  }
}

function logSecurityEvent(type, details) {
  const event = {
    id: Date.now() + Math.random(), // Ensure unique IDs
    timestamp: new Date().toISOString(),
    type: type,
    severity: getSeverity(type),
    details: details,
    status: 'detected'
  };
  securityEvents.push(event);
  
  // Keep only last 500 events
  if (securityEvents.length > 500) {
    securityEvents = securityEvents.slice(-500);
  }
  
  console.log(`SECURITY EVENT [${getSeverity(type)}]: ${type}`, details);
}

function getSeverity(type) {
  const severities = {
    'BRUTE_FORCE_ATTEMPT': 'HIGH',
    'BRUTE_FORCE_SIMULATION': 'HIGH',
    'SQL_INJECTION_ATTEMPT': 'CRITICAL',
    'SQL_INJECTION_SIMULATION': 'CRITICAL',
    'AUTH_FAILURE': 'MEDIUM',
    'LARGE_PAYLOAD': 'MEDIUM',
    'TRAFFIC_SPIKE': 'HIGH',
    'DDOS_SIMULATION': 'HIGH',
    'SYSTEM_START': 'INFO'
  };
  return severities[type] || 'LOW';
}

function countFailedLogins(username) {
  return securityEvents.filter(e => 
    e.type === 'AUTH_FAILURE' && 
    e.details.username === username
  ).length;
}

// Serve index.html as default route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html')); 
});

const PORT = process.env.PORT || 5000;

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║       🔒 SECURITY MONITORING DEMO SERVER            ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  ✅ Server running on: http://localhost:${PORT}       ║
║  📊 Dashboard:      http://localhost:${PORT}/        ║
║  🩺 Health Check:   http://localhost:${PORT}/api/health║ // if localhost not working use 127.0.0.1:port number
║                                                      ║
║     API Endpoints:                                   ║
║     • POST /api/login                                ║
║     • GET  /api/users?search=                        ║
║     • POST /api/data                                 ║
║     • POST /api/simulate/attack                      ║
║     • POST /api/reset                                ║
║     • GET  /api/security/events                      ║
║     • GET  /api/metrics                              ║
║                                                      ║
║  Press Ctrl+C to stop the server                     ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
  `);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server gracefully...');
  server.close(() => {
    console.log('✅ Server closed successfully');
    process.exit(0);
  });
});

// Keep process alive and generate automatic test traffic
setInterval(() => {
  if (Math.random() > 0.7) {
    const testIps = ['192.168.1.1', '10.0.0.1', '172.16.0.1'];
    const testEndpoint = ['HEALTH_CHECK', 'USER_LIST'][Math.floor(Math.random() * 2)];
    const metric = {
      timestamp: new Date().toISOString(),
      endpoint: testEndpoint,
      method: 'GET',
      ip: testIps[Math.floor(Math.random() * testIps.length)],
      userAgent: 'Demo-Agent/1.0',
      status: 'success',
      responseTime: Math.floor(Math.random() * 80) + 20
    };
    apiMetrics.push(metric);
  }
}, 5000);


