# CICIDS2017 Dataset Instructions

The Aegis IDS model is benchmarked on the CICIDS2017 dataset provided by the Canadian Institute for Cybersecurity (UNB).

## Downloading CICIDS2017 Dataset

1. Automated script:
   ```bash
   bash scripts/download_data.sh
   ```

2. Manual download:
   - Visit: https://www.unb.ca/cic/datasets/ids-2017.html
   - Download the CSV files (GeneratedLabelledFlows.zip)
   - Extract CSV files into this `data/` directory.

Files expected:
- `Monday-WorkingHours.pcap_ISCX.csv` (Benign baseline)
- `Tuesday-WorkingHours.pcap_ISCX.csv` (FTP-Patator, SSH-Patator)
- `Wednesday-workingHours.pcap_ISCX.csv` (DoS / DDoS, Heartbleed)
- `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` (Infiltration)
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (Web Attacks)
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (DDoS)
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (PortScan)
- `Friday-WorkingHours-Morning.pcap_ISCX.csv` (Botnet)
