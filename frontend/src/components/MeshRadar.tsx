'use client';

import React, { useMemo } from 'react';
import CyberRadar from './CyberRadar';
import { MeshState } from '@/lib/api';

interface MeshRadarProps {
  state: MeshState | null;
}

function hash01(s: string, salt: string): number {
  // Tiny string-hash → [0,100) so blips land on the radar canvas.
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i) + salt.charCodeAt(i % salt.length)) | 0;
  }
  return Math.abs(h) % 100;
}

export default function MeshRadar({ state }: MeshRadarProps) {
  const blips = useMemo(() => {
    const out: Array<{ label: string; type: string; intensity: number; x: number; y: number }> = [];
    if (!state) return out;
    for (const c of state.campaigns ?? []) {
      const ips = c.attacker_ips?.length ? c.attacker_ips : [c.campaign_id.slice(0, 16)];
      for (const ip of ips.slice(0, 2)) {
        const primary = c.services?.[0] ?? 'http';
        out.push({
          label: `${ip}:${primary === 'ssh' ? '22' : primary === 'smb' ? '445' : '80'}`,
          type: primary.toUpperCase(),
          intensity: Math.min(1, Math.max(0.15, c.severity / 10)),
          x: hash01(ip, c.campaign_id),
          y: hash01(c.campaign_id, ip),
        });
        if (out.length >= 8) break;
      }
      if (out.length >= 8) break;
    }
    return out;
  }, [state]);

  return (
    <div>
      <CyberRadar blips={blips} />
    </div>
  );
}