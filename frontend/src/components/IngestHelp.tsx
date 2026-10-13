import React from 'react'

export default function IngestHelp() {
    return React.createElement(
        'section',
        { className: 'ingest-help card' },
        React.createElement('h3', { className: 'card-title' }, 'Ingest telemetry from devices'),
        React.createElement('p', { className: 'card-copy' }, 'Quick examples to send feature JSON from another laptop or the same machine.'),
        React.createElement(
            'div',
            { className: 'code-block' },
            React.createElement('div', { className: 'code-title' }, 'curl'),
            React.createElement('pre', null, 'curl -X POST http://<host>:<port>/api/detect -H "Content-Type: application/json" -d @scripts/example_event.json')
        ),
        React.createElement(
            'div',
            { className: 'code-block' },
            React.createElement('div', { className: 'code-title' }, 'Python forwarder'),
            React.createElement('pre', null, 'python scripts/device_forwarder.py --host 1.2.3.4 --port 8000 --file scripts/example_event.json')
        ),
        React.createElement('p', { className: 'muted' }, 'Tip: set ', React.createElement('code', null, 'DETECT_API_KEY'), ' in the backend and include ', React.createElement('code', null, '-H "X-API-Key: <key>"'), ' in your requests.')
    )
}
