const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const promClient = require('prom-client');

const app = express();

const register = new promClient.Registry();

// Define a custom metric for the count of open ports per IP
const openPortsCountGauge = new promClient.Gauge({
  name: 'nmap_open_ports_count',
  help: 'Total count of open ports found by nmap for an IP',
  labelNames: ['ip'],
  registers: [register],
});

// Function to read IPs from a TXT or CSV file
function readIPsFromFile(filePath) {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, { encoding: 'utf-8' }, (err, data) => {
      if (err) reject(err);
      else resolve(data.split('\n').filter(line => line.trim())); // Remove empty lines
    });
  });
}

// Define a Gauge for the last scan timestamp
const lastScanTimestamp = new promClient.Gauge({
  name: 'last_scan_timestamp',
  help: 'UNIX timestamp when the last nmap scan was completed',
  registers: [register],
});

// Function to run nmap, parse its output, and update metrics
async function updateMetrics() {
  const ipsToScan = await readIPsFromFile('hosts.txt');

  ipsToScan.forEach(ip => {
    exec(`nmap -sS -Pn -p- --open ${ip}`, (error, stdout, stderr) => {
      if (error) {
        console.error(`exec error: ${error}`);
        return;
      }

      // Parse nmap output to count open ports
      const openPortsCount = (stdout.match(/open/g) || []).length;

      // Update the gauge for this IP with the count of open ports
      openPortsCountGauge.labels(ip).set(openPortsCount);
    });
  });
    // After all scans are initiated (but not necessarily completed)
  // Update the timestamp. For precise timing, you may need to adjust this placement based on your logic
  lastScanTimestamp.set(Date.now());
}

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    console.error(err);
    res.status(500).end(err);
  }
});

// Start server
const port = 9910;
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);

  // Initially populate the metrics
  updateMetrics().then(() => {
    console.log('Initial metrics update completed.');
  }).catch(err => {
    console.error('Error during initial metrics update:', err);
  });

  // Schedule updateMetrics to run once a day
  setInterval(() => {
    updateMetrics().then(() => {
      console.log('Scheduled metrics update completed.');
    }).catch(err => {
      console.error('Error during scheduled metrics update:', err);
    });
  }, 24 * 60 * 60 * 1000); // 24 hours * 60 minutes * 60 seconds * 1000 milliseconds
});

