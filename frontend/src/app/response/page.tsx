import React from 'react'
import Link from 'next/link'

export default function ResponsePage() {
  return (
    <div className="feature-page">
      <header className="feature-hero">
        <div className="eyebrow">PLAYBOOKS · AUTO-CONTAIN</div>
        <h1>Automated Response</h1>
        <p>Define playbooks and automatic actions to contain and remediate detected threats.</p>
      </header>

      <section className="feature-content">
        <div className="feature-section">
          <span className="feature-section-eyebrow">Templates</span>
          <h2>Playbooks</h2>
          <p>Create response templates that can be triggered manually or automatically based on severity.</p>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Trigger Engine</span>
          <h2>Severity-based Dispatch</h2>
          <p>Route alerts to the right playbook based on threat score, attack type, and asset criticality.</p>
          <Link href="/threats" className="feature-cta">Run Detection →</Link>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Key Rotation</span>
          <h2>PQC Channel Rotation</h2>
          <p>Rotate ML-KEM-768 keypairs and re-establish quantum-safe channels as part of every containment.</p>
          <Link href="/ledger" className="feature-cta">Audit Trail →</Link>
        </div>
      </section>
    </div>
  )
}
