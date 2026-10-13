"use client"
import React, { useState } from 'react'

export default function DeviceSender() {
    const [host, setHost] = useState('localhost')
    const [port, setPort] = useState('8000')
    const [apiKey, setApiKey] = useState('')
    const [autoRespond, setAutoRespond] = useState(false)
    const [body, setBody] = useState(JSON.stringify({ features: { flow_duration: 100.0, total_fwd_packets: 5 } }, null, 2))
    const [resp, setResp] = useState<string | null>(null)
    const [loading, setLoading] = useState(false)
    const [quota, setQuota] = useState<any>(null)

    async function send() {
        setResp(null)
        setLoading(true)
        try {
            const url = `http://${host}:${port}/api/detect${autoRespond ? '?auto_respond=true' : ''}`
            const headers: Record<string, string> = { 'Content-Type': 'application/json' }
            if (apiKey) headers['X-API-Key'] = apiKey

            const r = await fetch(url, { method: 'POST', headers, body })
            const text = await r.text()
            setResp(`HTTP ${r.status}\n${text}`)
        } catch (e: any) {
            setResp(`Error: ${e.message || e}`)
        } finally {
            setLoading(false)
        }
    }

    async function fetchQuota() {
        try {
            const url = `http://${host}:${port}/api/detect/quota`
            const headers: Record<string, string> = {}
            if (apiKey) headers['X-API-Key'] = apiKey
            const r = await fetch(url, { headers })
            if (!r.ok) {
                setQuota({ error: `HTTP ${r.status}` })
                return
            }
            const j = await r.json()
            setQuota(j.quota)
        } catch (e: any) {
            setQuota({ error: e.message || e })
        }
    }

    React.useEffect(() => {
        // fetch quota when host/port/apiKey change
        let mounted = true
        fetchQuota()
        return () => { mounted = false }
    }, [host, port, apiKey])

    return (
        <section className="device-sender card">
            <h3 className="card-title">Send an event from this browser</h3>

            <div className="form-row">
                <label>Host</label>
                <input value={host} onChange={e => setHost(e.target.value)} className="form-control" />
                <label>Port</label>
                <input value={port} onChange={e => setPort(e.target.value)} className="form-control" />
            </div>

            <div className="form-row">
                <label>API Key (optional)</label>
                <input value={apiKey} onChange={e => setApiKey(e.target.value)} className="form-control" />
                <label className="checkbox-row">
                    <input
                        type="checkbox"
                        className="aegis-check"
                        checked={autoRespond}
                        onChange={e => setAutoRespond(e.target.checked)}
                    />
                    Auto respond
                </label>
            </div>

            <div>
                <label className="json-body-label">JSON body</label>
                <textarea
                    value={body}
                    onChange={e => setBody(e.target.value)}
                    rows={8}
                    className="form-control json-body-textarea"
                />
            </div>

            <div style={{ marginTop: 8 }}>
                <button className="sticker-btn" onClick={send} disabled={loading}>{loading ? 'Sending…' : 'Send Event'}</button>
                <div style={{ height: 8 }} />
                {resp && <pre className="mono-block">{resp}</pre>}
                {quota && (
                    <div style={{ marginTop: 8 }} className="quota-box">
                        {quota.error ? (
                            <div className="muted">Quota: {quota.error}</div>
                        ) : (
                            <div>
                                <div>Limit: {quota.limit} / min</div>
                                <div>Used: {quota.used}</div>
                                <div>Remaining: {quota.remaining}</div>
                                <div>Reset in: {quota.reset_seconds}s</div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </section>
    )
}
