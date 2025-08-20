# Attack Automation Scripts

This folder contains ready-to-run scripts used during the 5G Core security assessment.  Each script is self-contained and can be executed inside the *attacker* namespace created in the **Kubernetes Goat** cluster.

| Script | Purpose | Requirements |
|--------|---------|--------------|
| `pfcp_fuzz.py` | Fuzz the PFCP parser in the UPF by sending malformed headers and oversized packets. | Python 3.11, `scapy`, cluster DNS resolution to `my5gc-upf-pfcp.open5gs.svc.cluster.local`. |
| `gtp_spoof.py` | Inject spoofed GTP-U packets with invalid TEID to test UPF filtering. | Python 3.11, `scapy`, UDP/2152 reachability. |
| `mongo_enum.py` | Enumerate MongoDB without credentials to verify open access. | Python 3.11, `pymongo`, network access to `my5gc-mongo.open5gs`. |
| `ngap_inject.sh` | Send malformed NGAP fragments via SCTP to the AMF signalling port (38412). | `lksctp-tools` inside the container. |

## Quick Start

```bash
# In attacker namespace
kubectl exec -n attacker -it attacker-pod -- bash

# Install common python libs once
pip install scapy pymongo

# Run PFCP fuzzer
python3 /scripts/pfcp_fuzz.py
```

### Adding new scripts
1. Copy the file into `public/scripts/` so it is automatically served by the web-app.  
2. Reference it in the relevant attack scenario (`attackCmds`).  
3. Keep the table above updated. 