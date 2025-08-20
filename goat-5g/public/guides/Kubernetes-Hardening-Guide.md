# Kubernetes Hardening Guide for 5G Core Deployments

This document consolidates best-practices from the CIS Kubernetes Benchmark v1.25, NSA/CISA Hardening Guidance and the upstream Kubernetes documentation ( _Protecting Cluster Components_ ). The recommendations are tailored to 5G Core workloads (Open5GS, SD-Core, OAI) running in the intentionally vulnerable **Kubernetes Goat** environment.

## 1. Cluster Baseline

| Area | Recommendation | Command / Reference |
|------|----------------|---------------------|
| Versioning | Keep the control-plane at **≥ v1.27** with latest security patches | `kubeadm upgrade plan` |
| RBAC | Enable the `NodeRestriction` admission plugin and remove default `system:masters` bindings | `kubectl get clusterrolebinding system:masters -o yaml` |
| TLS | API-server should be started with `--tls-cert-file` / `--tls-private-key-file` managed by cert-manager | https://cert-manager.io |
| Audit Logs | Enable audit logging (`--audit-log-path`) and forward to SIEM | `apiVersion: audit.k8s.io/v1` |
| Pod Security | Enforce PodSecurity Admission (`baseline`, `restricted`) | `kubectl label ns open5gs pod-security.kubernetes.io/enforce=restricted` |

## 2. Network Security (Zero-Trust)

1. Apply a **Default-Deny** `NetworkPolicy` in every namespace.
2. Segment traffic by plane (control vs data) and by function (UPF, SMF, AMF …).
3. Control **Egress** to avoid data exfiltration.
4. Use **Calico GlobalNetworkPolicy** to block GTP-U spoofing.

Example YAML:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: open5gs
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

## 3. Node Hardening

* Disable privileged containers on the kubelet: `--allow-privileged=false`.
* Enable **seccomp** and **AppArmor** (`RuntimeDefault`).
* Deploy Falco or Kube-Audit to detect runtime anomalies.

## 4. Container Security

* Use **distroless** images signed with Cosign.
* Run as non-root, read-only root filesystem, drop **all** Linux capabilities.
* Set `allowPrivilegeEscalation: false` and enable SELinux (RHEL/Fedora).

## 5. Supply-Chain

* CI/CD pipeline must scan images with Trivy (`--severity CRITICAL,HIGH`).
* Gate image admission with OPA-Gatekeeper (`K8sPSPRestricted`) and Sigstore signature verification.

## 6. Observability

* Expose PFCP/GTP-U metrics via Prometheus and Grafana dashboards.
* Export Calico Felix metrics for blocked traffic.
* Stream logs to Loki or Elasticsearch for long-term retention.

---
### References
* CIS Kubernetes Benchmark v1.25
* NSA/CISA Kubernetes Hardening Guidance v1.2
* CNCF – Best Practices for Securing Containers and Supply Chain 