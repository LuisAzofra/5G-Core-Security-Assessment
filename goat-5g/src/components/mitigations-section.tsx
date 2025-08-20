import { Shield, Lock, Network, Eye, FileX, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Progress } from "./ui/progress";

export function MitigationsSection() {
  const mitigationCategories = [
    {
      title: "Network Isolation & Zero Trust",
      icon: Network,
      color: "text-primary",
      progress: 100,
      controls: [
        "Calico CNI with strict NetworkPolicies",
        "Namespace-based traffic segmentation", 
        "Inter-pod communication restrictions",
        "Protocol-specific access controls (PFCP, GTP-U, NGAP)"
      ],
      explanation: "4/4 controls implemented",
      implemented: 4
    },
    {
      title: "RBAC & Access Control", 
      icon: Lock,
      color: "text-success",
      progress: 100,
      controls: [
        "Principle of least privilege RBAC",
        "Custom ServiceAccount per component",
        "Removed default cluster-admin bindings",
        "PodSecurityStandards enforcement"
      ],
      explanation: "4/4 controls implemented",
      implemented: 4
    },
    {
      title: "Container Security",
      icon: Shield, 
      color: "text-warning",
      progress: 100,
      controls: [
        "ReadOnlyRootFilesystem enforcement",
        "Dropped ALL Linux capabilities",
        "Non-root user execution",
        "Vulnerability scanning in CI/CD"
      ],
      explanation: "4/4 controls active (CI vulnerability scanning integrated)",
      implemented: 4
    },
    {
      title: "Protocol Hardening",
      icon: FileX,
      color: "text-danger", 
      progress: 100,
      controls: [
        "Input validation for 5G protocols",
        "Rate limiting on control interfaces",
        "Circuit breakers for malformed messages",
        "Protocol-specific monitoring"
      ],
      explanation: "4/4 controls active (circuit breakers deployed)",
      implemented: 4
    },
    {
      title: "Monitoring & Detection",
      icon: Eye,
      color: "text-primary-glow",
      progress: 100,
      controls: [
        "Calico Flow Logs for network monitoring",
        "Falco runtime security detection", 
        "API access audit logging",
        "Anomaly detection for 5G traffic"
      ],
      explanation: "4/4 controls active (anomaly detection enabled)",
      implemented: 4
    },
    {
      title: "Supply Chain Security",
      icon: AlertTriangle,
      color: "text-warning",
      progress: 100,
      controls: [
        "Image vulnerability scanning",
        "Signed container images (Cosign)",
        "Minimal distroless base images",
        "Automated security updates"
      ],
      explanation: "4/4 controls implemented",
      implemented: 4
    }
  ];

  const securityMetrics = [
    {
      metric: "Network Attack Surface",
      before: "100%",
      after: "15%", 
      reduction: "85%",
      explanation: "Reachable service/port combinations dropped from 100% to 15% after default-deny + component policies.",
      status: "success"
    },
    {
      metric: "Privilege Escalation Risk",
      before: "High",
      after: "Low",
      reduction: "90%",
      explanation: "Risk score scaled 10→1 (High=10, Low=1) yielding a 90% reduction.",
      status: "success"
    },
    {
      metric: "Protocol Abuse Resistance", 
      before: "Vulnerable",
      after: "Hardened",
      reduction: "95%",
      explanation: "Malformed protocol test-cases accepted fell from 100% to 5%.",
      status: "success"
    },
    {
      metric: "Inter-Component Access",
      before: "Unrestricted",
      after: "Zero Trust",
      reduction: "100%",
      explanation: "Unauthorized pod-to-pod requests blocked completely (100→0).",
      status: "success"
    }
  ];

  return (
    <section id="mitigations" className="py-20 bg-gradient-dark">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-6 bg-gradient-cyber bg-clip-text text-transparent">
            Security Mitigations & Hardening
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Comprehensive defense-in-depth strategy implementing Zero Trust principles for 5G Core infrastructure
          </p>
        </div>

        {/* Security Metrics */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {securityMetrics.map((metric, index) => (
            <Card key={index} className="bg-card/30 backdrop-blur border-success/20">
              <CardHeader className="pb-2">
                <CardDescription className="text-xs text-muted-foreground">
                  {metric.metric}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-danger">Before:</span>
                    <span className="text-danger">{metric.before}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-success">After:</span>
                    <span className="text-success">{metric.after}</span>
                  </div>
                  <div className="pt-2 space-y-2">
                    <Badge className="bg-success/20 text-success border-success/20">
                      ↓ {metric.reduction} Improvement
                    </Badge>
                    <p className="text-xs text-muted-foreground">{metric.explanation}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Mitigation Categories */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {mitigationCategories.map((category, index) => (
            <Card key={index} className="bg-card/50 backdrop-blur border-primary/20 hover:border-primary/40 transition-colors">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-primary/20 rounded-lg flex items-center justify-center">
                    <category.icon className={`w-5 h-5 ${category.color}`} />
                  </div>
                  <div className="flex-1">
                    <CardTitle className="text-lg">{category.title}</CardTitle>
                    <div className="flex items-center gap-2 mt-2">
                      <Progress value={category.progress} className="flex-1 h-2" />
                      <span className="text-sm text-muted-foreground">{category.progress}%</span>
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2">
                  {category.controls.map((control, controlIndex) => {
                    const implemented = controlIndex < (category.implemented ?? category.controls.length);
                    return (
                      <li key={controlIndex} className="text-sm flex items-start gap-2">
                        {implemented ? (
                          <svg className="w-3 h-3 text-success mt-1 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-7.363 7.364a1 1 0 01-1.414 0L3.293 9.707a1 1 0 011.414-1.414l4.237 4.237 6.656-6.657a1 1 0 011.414 0z" clipRule="evenodd"/></svg>
                        ) : (
                          <div className="w-3 h-3 border border-warning rounded mt-1 flex-shrink-0"></div>
                        )}
                        <span className={implemented ? "text-muted-foreground" : "text-warning"}>{control}</span>
                      </li>
                    );
                  })}
                </ul>
                <p className="text-xs text-muted-foreground mt-2">{category.explanation}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Implementation Timeline */}
        <div className="mt-16 bg-card/30 backdrop-blur border border-primary/20 rounded-lg p-6">
          <h3 className="text-xl font-semibold mb-6 text-primary">Implementation Timeline</h3>
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <div className="w-3 h-3 bg-success rounded-full"></div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span className="font-medium">Phase 1: Network Isolation</span>
                  <Badge className="bg-success/20 text-success border-success/20">Completed</Badge>
                </div>
                <p className="text-sm text-muted-foreground">NetworkPolicies and CNI hardening</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="w-3 h-3 bg-success rounded-full"></div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span className="font-medium">Phase 2: RBAC & Container Security</span>
                  <Badge className="bg-success/20 text-success border-success/20">Completed</Badge>
                </div>
                <p className="text-sm text-muted-foreground">Pod security standards and RBAC hardening</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="w-3 h-3 bg-success rounded-full"></div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span className="font-medium">Phase 3: Protocol Security</span>
                  <Badge className="bg-success/20 text-success border-success/20">Completed</Badge>
                </div>
                <p className="text-sm text-muted-foreground">5G protocol validation and monitoring</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="w-3 h-3 bg-success rounded-full"></div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span className="font-medium">Phase 4: Advanced Monitoring</span>
                  <Badge className="bg-success/20 text-success border-success/20">Completed</Badge>
                </div>
                <p className="text-sm text-muted-foreground">ML-based anomaly detection and response</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}