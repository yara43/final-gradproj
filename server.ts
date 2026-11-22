import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { db } from './src/server/database';
import { correlateBrowserTelemetry, TelemetryIngestPayload } from './src/server/correlationEngine';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Global Middlewares
  app.use(express.json({ limit: '1mb' }));

  // CORS headers for Chrome Extension communication
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-PhishGuard-Agent, X-Extension-Version');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  // ==========================================
  // PHISHGUARD API ROUTES
  // ==========================================

  // 1. Health & Server Status
  app.get('/api/health', (req, res) => {
    const stats = db.getStats();
    res.json({
      status: 'ok',
      service: 'PhishGuard Telemetry & Compound Correlation Engine',
      version: '1.0.0',
      uptimeSec: Math.round(process.uptime()),
      db: {
        totalScans: stats.totalScans,
        totalBlocked: stats.totalBlocked,
        totalIncidents: stats.totalIncidents,
        openIncidents: stats.openIncidents
      }
    });
  });

  // 2. Ingest Page Telemetry & Run Relational Correlation
  app.post('/api/telemetry', async (req, res) => {
    try {
      const payload: TelemetryIngestPayload = req.body;

      if (!payload || !payload.url) {
        return res.status(400).json({ error: 'Missing required field: url' });
      }

      // STRICT PRIVACY GUARANTEE:
      // Telemetry payload cannot contain raw passwords, card numbers, or session secrets.
      // Payload only contains boolean presence flags (e.g. hasPassword, hasPayment) and domain structures.

      const correlation = await correlateBrowserTelemetry(payload);

      // Persist telemetry record to database
      db.addTelemetry(correlation.telemetryRecord);

      // If an incident was generated, persist incident to database
      if (correlation.incident) {
        db.createOrUpdateIncident(correlation.incident);
      }

      return res.json({
        success: true,
        verdict: correlation.verdict,
        severity: correlation.severity,
        score: correlation.score,
        confidence: correlation.confidence,
        action: correlation.action,
        incidentId: correlation.incident?.incidentId || null,
        reasons: correlation.reasons,
        signals: correlation.signals,
        mitreTechniques: correlation.mitreTechniques,
        explanation: correlation.explanation,
        telemetryId: correlation.telemetryRecord.id
      });
    } catch (err: any) {
      console.error('[API /api/telemetry] Error:', err);
      return res.status(500).json({
        error: 'Correlation engine failure',
        message: err?.message || 'Internal server error'
      });
    }
  });

  // 3. Query Real Telemetry Logs
  app.get('/api/telemetry', (req, res) => {
    try {
      const { search, verdict, severity, actionTaken, limit } = req.query;
      const logs = db.getTelemetry({
        search: typeof search === 'string' ? search : undefined,
        verdict: typeof verdict === 'string' ? verdict : undefined,
        severity: typeof severity === 'string' ? severity : undefined,
        actionTaken: typeof actionTaken === 'string' ? actionTaken : undefined,
        limit: limit ? parseInt(limit as string, 10) : 100
      });
      res.json({ logs, total: logs.length });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to retrieve telemetry logs' });
    }
  });

  // 4. Query Security Incidents
  app.get('/api/incidents', (req, res) => {
    try {
      const { search, status, severity, limit } = req.query;
      const incidents = db.getIncidents({
        search: typeof search === 'string' ? search : undefined,
        status: typeof status === 'string' ? status : undefined,
        severity: typeof severity === 'string' ? severity : undefined,
        limit: limit ? parseInt(limit as string, 10) : 50
      });
      res.json({ incidents, total: incidents.length });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to retrieve incidents' });
    }
  });

  // 5. Get Single Incident by ID
  app.get('/api/incidents/:id', (req, res) => {
    const incident = db.getIncidentById(req.params.id);
    if (!incident) {
      return res.status(404).json({ error: 'Incident not found' });
    }
    res.json({ incident });
  });

  // 6. Update Incident Triage Status / Add Analyst Note
  app.patch('/api/incidents/:id', (req, res) => {
    try {
      const { status, assignedAnalyst, newNote } = req.body;
      const updated = db.updateIncident(req.params.id, {
        status,
        assignedAnalyst,
        newNote
      });

      if (!updated) {
        return res.status(404).json({ error: 'Incident not found' });
      }

      res.json({ success: true, incident: updated });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to update incident' });
    }
  });

  // 7. Standalone Correlation / Inspection Endpoint
  app.post('/api/correlate', async (req, res) => {
    try {
      const payload: TelemetryIngestPayload = req.body;
      if (!payload || !payload.url) {
        return res.status(400).json({ error: 'Missing url' });
      }

      const result = await correlateBrowserTelemetry(payload);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: 'Correlation failed', details: err?.message });
    }
  });

  // 8. Aggregated Metrics & Stats
  app.get('/api/stats', (req, res) => {
    res.json(db.getStats());
  });

  // 9. Reset / Clear Database
  app.post('/api/db/clear', (req, res) => {
    db.clearAll();
    res.json({ success: true, message: 'Database reset successfully' });
  });

  // ==========================================
  // VITE DEV MIDDLEWARE / STATIC PRODUCTION SERVING
  // ==========================================
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️  PhishGuard Full-Stack Platform running on http://0.0.0.0:${PORT}`);
    console.log(`📡 Telemetry Ingest: POST http://0.0.0.0:${PORT}/api/telemetry`);
    console.log(`🚨 Incident Stream:  GET  http://0.0.0.0:${PORT}/api/incidents`);
  });
}

startServer().catch(err => {
  console.error('[PhishGuard Server] Fatal startup error:', err);
  process.exit(1);
});
