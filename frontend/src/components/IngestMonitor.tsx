"use client"
import React from 'react'

export default function IngestMonitor() {
    const [status, setStatus] = React.useState<any>(null)

    React.useEffect(() => {
        let mounted = true
        async function poll() {
            try {
                const r = await fetch('/api/ingest/status')
                const j = await r.json()
                if (mounted) setStatus(j)
            } catch (e) {
                if (mounted) setStatus({ error: String(e) })
            }
        }
        poll()
        const id = setInterval(poll, 5000)
        return () => { mounted = false; clearInterval(id) }
    }, [])

    return (
        <section className="ingest-monitor card">
            <h4 className="card-title">Ingest Queue</h4>
            {status ? (
                status.redis ? (
                    <div>
                        <div>Queue length: <strong>{status.queue_length}</strong></div>
                        <div className="muted">Redis connected</div>
                    </div>
                ) : (
                    <div>
                        <div className="muted">Redis not configured or error</div>
                        {status.message && <div className="muted">{status.message}</div>}
                    </div>
                )
            ) : (
                <div className="muted">Loading…</div>
            )}
        </section>
    )
}
