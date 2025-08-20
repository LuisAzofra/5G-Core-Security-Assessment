import { FileText, Download, ExternalLink, Code, Shield, Target } from "lucide-react";
import { Button } from "./ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { DownloadButton } from "./download-button";

export function DocumentationSection() {
  const documents = [
    {
      title: "Complete Security Assessment Report",
      description: "Comprehensive analysis of all 8 attack scenarios with detailed procedures, results, and mitigations",
      icon: FileText,
      type: "PDF Report",
      size: "2.3 MB",
      pages: "45 pages",
      link: "/5G-Core-Security-Assessment-Report.md",
      view: "/5G-Core-Security-Assessment-Report.md"
    },
    {
      title: "Kubernetes Hardening Guide", 
      description: "Step-by-step guide for implementing Zero Trust security policies and RBAC configurations",
      icon: Shield,
      type: "Implementation Guide",
      size: "1.8 MB", 
      pages: "32 pages",
      link: "/guides/Kubernetes-Hardening-Guide.md",
      view: "/guides/Kubernetes-Hardening-Guide.md"
    },
    {
      title: "Attack Automation Scripts",
      description: "Complete collection of Python scripts, YAML configurations, and testing tools used in assessments",
      icon: Code,
      type: "Source Code",
      size: "850 KB",
      pages: "Scripts",
      link: "/scripts/README.md",
      view: "/scripts/README.md",
      downloadName: "Attack Automation Scripts.md"
    },
    {
      title: "Network Policy Templates",
      description: "Production-ready NetworkPolicy configurations for 5G Core component isolation",
      icon: Target,
      type: "YAML Templates", 
      size: "95 KB",
      pages: "YAML files",
      link: "/network-policies/README.md",
      view: "/network-policies/README.md",
      downloadName: "Network Policy Templates.md"
    }
  ];

  const handleCopy = () => {
    navigator.clipboard.writeText(codeExample);
  };

  const codeExample = `# Example NetworkPolicy for UPF PFCP isolation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: upf-pfcp-isolation
  namespace: open5gs
spec:
  podSelector:
    matchLabels:
      app: upf
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: open5gs
    - podSelector:
        matchLabels:
          role: control-plane
    ports:
    - protocol: UDP
      port: 8805  # PFCP
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: open5gs`;

  return (
    <section id="documentation" className="py-20 bg-background">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-6 text-foreground">
            Technical Documentation
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Complete documentation, implementation guides, and automation scripts for 5G Core security assessment
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-8 mb-16">
          {documents.map((doc, index) => (
            <Card key={index} className="bg-card border-primary/20 hover:border-primary/40 transition-colors">
              <CardHeader>
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center">
                    <doc.icon className="w-6 h-6 text-primary" />
                  </div>
                  <div className="flex-1">
                    <CardTitle className="text-lg mb-2">{doc.title}</CardTitle>
                    <CardDescription>{doc.description}</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div className="flex gap-4 text-sm text-muted-foreground">
                    <span>{doc.type}</span>
                    <span>•</span>
                    <span>{doc.size}</span>
                    <span>•</span>
                    <span>{doc.pages}</span>
                  </div>
                  <div className="flex gap-2">
                    {doc.link ? (
                      <a href={doc.link} download={doc.downloadName ?? undefined} className="inline-flex">
                        <Button size="sm" variant="outline">
                          <Download className="w-4 h-4 mr-2" />
                          Download
                        </Button>
                      </a>
                    ) : index === 0 ? <DownloadButton /> : null}
                    <Button size="sm" variant="ghost" onClick={() => window.open(doc.view ?? doc.link ?? '/5G-Core-Security-Assessment-Report.md', '_blank')}>
                      <ExternalLink className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Code Example */}
        <div className="bg-card/50 backdrop-blur border border-primary/20 rounded-lg p-6">
          <h3 className="text-xl font-semibold mb-4 text-primary">Example: Network Policy Implementation</h3>
          <div className="bg-muted/20 rounded-lg p-4 overflow-x-auto max-h-72">
            <pre className="text-sm text-muted-foreground">
              <code>{codeExample}</code>
            </pre>
          </div>
          <div className="mt-4 flex gap-2">
            <Button asChild size="sm" variant="outline">
              <a href="/network-policies/upf-pfcp-isolation.yaml" target="_blank">
                <Code className="w-4 h-4 mr-2" />
                View Full Config
              </a>
            </Button>
            <Button size="sm" variant="ghost" onClick={handleCopy}>
              Copy to Clipboard
            </Button>
          </div>
        </div>

        {/* Key Findings Summary */}
        <div className="mt-16 grid md:grid-cols-3 gap-6">
          <Card className="text-center p-6 bg-danger/5 border-danger/20">
            <div className="text-3xl font-bold text-danger mb-2">8</div>
            <div className="text-sm text-muted-foreground">Critical vulnerabilities identified</div>
          </Card>
          
          <Card className="text-center p-6 bg-success/5 border-success/20">
            <div className="text-3xl font-bold text-success mb-2">100%</div>
            <div className="text-sm text-muted-foreground">Attack surface reduction achieved</div>
          </Card>
          
          <Card className="text-center p-6 bg-primary/5 border-primary/20">
            <div className="text-3xl font-bold text-primary mb-2">45</div>
            <div className="text-sm text-muted-foreground">Security controls implemented</div>
          </Card>
        </div>
      </div>
    </section>
  );
}