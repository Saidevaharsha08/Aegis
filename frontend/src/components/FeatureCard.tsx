import React from 'react'
import Link from 'next/link'

type Props = {
  title: string
  href: string
  description: string
  badge?: string
}

export default function FeatureCard({ title, href, description, badge }: Props) {
  return (
    <Link href={href} className="feature-card">
      <div className="feature-card-inner">
        <div className="feature-card-head">
          <h3 className="feature-title">{title}</h3>
          {badge ? <span className="feature-badge">{badge}</span> : null}
        </div>
        <p className="feature-desc">{description}</p>
        <div className="feature-cta">Explore →</div>
      </div>
    </Link>
  )
}
