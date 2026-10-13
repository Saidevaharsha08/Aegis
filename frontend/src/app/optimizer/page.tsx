import React from 'react'
import Link from 'next/link'
import OptimizerClient from '@/components/OptimizerClient'

export default function OptimizerPage() {
  return (
    <div className="feature-page">
      <header className="feature-hero">
        <div className="eyebrow">QAOA · 0-1 KNAPSACK</div>
        <h1>Rule Optimizer (QAOA)</h1>
        <p>Quantum-inspired rule optimization for synthesizing compact firewall rule sets.</p>
      </header>

      <section className="feature-content">
        <div className="feature-section">
          <span className="feature-section-eyebrow">Solver</span>
          <h2>Knapsack Solver</h2>
          <p>Formulate rule-selection as a 0-1 knapsack and use QAOA-inspired approximations to search.</p>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Compact Sets</span>
          <h2>Minimal Rule Sets</h2>
          <p>Find the smallest set of high-coverage rules that preserves detection quality.</p>
        </div>

        <div className="feature-section">
          <span className="feature-section-eyebrow">Explainable</span>
          <h2>Per-rule Impact</h2>
          <p>Inspect each rule's marginal contribution to coverage before promoting it to production.</p>
        </div>
      </section>

      <div style={{ height: 24 }} />

      <OptimizerClient />
    </div>
  )
}
