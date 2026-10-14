import React, { useState, useEffect } from 'react';
import './styles/blueprint.css';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [code, setCode] = useState(`resource "aws_security_group" "web_sg" {
  name = "demo-security-group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`);
  const [scanData, setScanData] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  const runScan = async () => {
    setIsScanning(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, filename: 'main.tf' })
      });
      const data = await res.json();
      setScanData(data);
    } catch (e) {
      console.error(e);
    } finally {
      setIsScanning(false);
    }
  };

  useEffect(() => {
    runScan();
  }, []);

  return (
    <div className="app-container">
      <div className="main-content">
        <header className="top-navbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontWeight: 800, color: 'var(--cyan-neon)' }}>INFRASHIELD</span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>The Living Security Blueprint</span>
          </div>
          <div style={{ fontWeight: 700, color: scanData?.gate_status === 'BLOCKED' ? 'var(--crimson-block)' : 'var(--emerald-pass)' }}>
            GATE: {scanData?.gate_status || 'SCANNING...'}
          </div>
        </header>
        <main className="content-area">
          <h1>Secure Your Infrastructure Before It Ships.</h1>
          <p>Discover misconfigurations. Visualize exposure. Repair vulnerabilities. Validate with confidence.</p>
        </main>
      </div>
    </div>
  );
}
