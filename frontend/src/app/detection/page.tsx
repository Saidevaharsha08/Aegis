import React from 'react'
import Link from 'next/link'

export default function DetectionPage() {
  return (
    <div className="feature-page">
      <header className="feature-hero">
        <div className="eyebrow">XGBoost · SHAP</div>
        <h1>Detection &amp; Explanations</h1>
        <p>Run the IDS on mapped features, view SHAP-based explanations, and inspect alerts.</p>
      </header>

      <section className="feature-content">
        <div className="feature-section">
          <span className="feature-section-eyebrow">Live Inference</span>
          <h2>Real-time Detection</h2>
          <p>Stream telemetry into the model to get classification scores and confidence metrics in real time.</p>
          <Link href="/threats" className="feature-cta">Open Console →</Link>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">SHAP Attributions</span>
          <h2>Explainability</h2>
          <p>Understand why a sample was flagged using SHAP breakdowns and human-readable feature contributions.</p>
          <Link href="/threats" className="feature-cta">Inspect SHAP →</Link>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Alert Pipeline</span>
          <h2>Alert Routing</h2>
          <p>Detected threats are signed, hashed, and dispatched to the audit ledger and response playbooks.</p>
          <Link href="/response" className="feature-cta">View Playbooks →</Link>
        </div>
      </section>
    </div>
  )
}
