# Network Policy Templates

This directory contains reusable `NetworkPolicy` manifests referenced in the 5G Core security assessment.

| File | Purpose |
|------|---------|
| `default-deny-all.yaml` | Blocks **all** ingress/egress by default in the `open5gs` namespace. |
| `upf-pfcp-isolation.yaml` | Allows PFCP (UDP/8805) traffic **only** from pods labelled `role=control-plane` to the UPF. |
| `control-data-plane-isolation.yaml` | Enforces strict separation between control-plane and data-plane workloads. |
| `mongo-isolation.yaml` | Restricts MongoDB ingress to internal 5G Core pods; denies external access. |
| `ngap-isolation.yaml` | Allows NGAP (SCTP/38412) only from trusted RAN namespaces. |
| `gtp-filter.yaml` | Drops spoofed GTP-U packets and limits sources to authorised RAN IP ranges. |

## Usage

```bash
# Apply default deny in namespace
kubectl apply -f default-deny-all.yaml

# Apply PFCP isolation
kubectl apply -f upf-pfcp-isolation.yaml
```

Feel free to copy and adjust the selectors (`matchLabels`) to match your own deployment labels. 