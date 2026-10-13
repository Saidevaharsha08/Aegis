import React from 'react'
import FeatureCard from '@/components/FeatureCard'

export default function IngestPage() {
  return (
    <div className="feature-page">
      <header className="feature-hero">
        <div className="eyebrow">ML-KEM-768 · API KEY</div>
        <h1>Telemetry Ingest</h1>
        <p>Securely send device telemetry to Aegis for feature mapping, detection, and explainability.</p>
      </header>

      <section className="feature-content">
        <div className="feature-section">
          <span className="feature-section-eyebrow">Edge Forwarder</span>
          <h2>Device Forwarder</h2>
          <p>Use our lightweight forwarder to push system logs and metrics to the detection pipeline.</p>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Auth &amp; Quota</span>
          <h2>Ingestion Security</h2>
          <p>All ingestion requests require an API key and are rate limited. Optional Redis-backed queue available for scale.</p>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">PQC Channels</span>
          <h2>Quantum-safe Transport</h2>
          <p>Ingestion channels are wrapped in NIST ML-KEM-768 key encapsulation for post-quantum confidentiality.</p>
        </div>
      </section>

      <div className="feature-grid" style={{ marginTop: 32 }}>
        <FeatureCard title="Threat Detection Console" href="/threats" description="Run XGBoost inference with SHAP explainability in real time." />
        <FeatureCard title="Audit Ledger" href="/ledger" description="Immutable SHA256 chain for detections and responses." />
        <FeatureCard title="Rule Optimizer" href="/optimizer" description="QAOA-inspired compact rule-set synthesis." />
      </div>
    </div>
  )
}
