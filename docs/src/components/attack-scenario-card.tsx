import { useState } from "react";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "./ui/collapsible";
import { ChevronDown, Shield, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import { Tooltip, TooltipProvider, TooltipTrigger, TooltipContent } from "./ui/tooltip";

export interface AttackScenario {
  id: string;
  title: string;
  description: string;
  severity: "high" | "medium" | "low";
  status: "vulnerable" | "mitigated" | "testing";
  category: string;
  objective: string;
  procedure: string[];
  results: {
    before: string;
    after: string;
  };
  impact: string;
  mitigation: string;
  mitigationCmds?: string;
  attackCmds?: string;
  artifacts: string[];
  loot?: string;
}

interface AttackScenarioCardProps {
  scenario: AttackScenario;
}

export function AttackScenarioCard({ scenario }: AttackScenarioCardProps) {
  const [isOpen, setIsOpen] = useState(false);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high": return "bg-danger/20 text-danger border-danger/20";
      case "medium": return "bg-warning/20 text-warning border-warning/20";
      case "low": return "bg-success/20 text-success border-success/20";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "vulnerable": return <XCircle className="w-4 h-4 text-danger" />;
      case "mitigated": return <CheckCircle2 className="w-4 h-4 text-success" />;
      case "testing": return <AlertTriangle className="w-4 h-4 text-warning" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  return (
    <Card className="overflow-hidden bg-card/50 backdrop-blur border-primary/20 hover:border-primary/40 transition-all duration-300">
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              {getStatusIcon(scenario.status)}
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <CardTitle className="text-lg cursor-help underline decoration-dotted underline-offset-4">
                      {scenario.title}
                    </CardTitle>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs whitespace-pre-wrap">
                    {scenario.objective}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </div>
            <CardDescription className="text-muted-foreground">
              {scenario.description}
            </CardDescription>
          </div>
          <div className="flex flex-col gap-2 ml-4">
            <Badge className={getSeverityColor(scenario.severity)}>
              {scenario.severity.toUpperCase()}
            </Badge>
            <Badge variant="outline" className="text-xs">
              {scenario.category}
            </Badge>
          </div>
        </div>
      </CardHeader>

      <Collapsible open={isOpen} onOpenChange={setIsOpen}>
        <CollapsibleTrigger asChild>
          <Button variant="ghost" className="w-full justify-between p-4 h-auto">
            <span>View Details</span>
            <ChevronDown className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
          </Button>
        </CollapsibleTrigger>
        
        <CollapsibleContent>
          <CardContent className="pt-0">
            <div className="space-y-6">
              <div>
                <h4 className="font-semibold text-primary mb-2">Objective</h4>
                <p className="text-sm text-muted-foreground">{scenario.objective}</p>
              </div>

              <div>
                <h4 className="font-semibold text-primary mb-2">Attack Procedure</h4>
                <ol className="space-y-2">
                  {scenario.procedure.map((step, index) => (
                    <li key={index} className="text-sm text-muted-foreground flex gap-2">
                      <span className="text-primary font-mono">{index + 1}.</span>
                      <code className="font-mono whitespace-pre-wrap">{step}</code>
                    </li>
                  ))}
                </ol>
                {scenario.attackCmds && (
                  <pre className="text-sm text-muted-foreground whitespace-pre-wrap bg-muted/20 border border-muted/30 p-3 rounded-md mt-4">
                    {scenario.attackCmds}
                  </pre>
                )}
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                <div className="p-4 bg-danger/5 border border-danger/20 rounded-lg">
                  <h4 className="font-semibold text-danger mb-2 flex items-center gap-2">
                    <XCircle className="w-4 h-4" />
                    Before Mitigation
                  </h4>
                  <pre className="text-sm text-muted-foreground whitespace-pre-wrap">{scenario.results.before}</pre>
                </div>

                <div className="p-4 bg-success/5 border border-success/20 rounded-lg">
                  <h4 className="font-semibold text-success mb-2 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" />
                    After Mitigation
                  </h4>
                  <pre className="text-sm text-muted-foreground whitespace-pre-wrap">{scenario.results.after}</pre>
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-warning mb-2">Impact</h4>
                <p className="text-sm text-muted-foreground">{scenario.impact}</p>
              </div>

              {scenario.loot && (
                <div>
                  <h4 className="font-semibold text-warning mb-2">Exfiltrated Data Example</h4>
                  <pre className="text-sm text-muted-foreground whitespace-pre-wrap bg-muted/20 border border-warning/30 p-3 rounded-md">{scenario.loot}</pre>
                </div>
              )}

              <div>
                <h4 className="font-semibold text-success mb-2">Mitigation Strategy</h4>
                <p className="text-sm text-muted-foreground mb-2">{scenario.mitigation}</p>
                {scenario.mitigationCmds && (
                  <pre className="text-sm text-muted-foreground whitespace-pre-wrap bg-muted/20 border border-muted/30 p-3 rounded-md">{scenario.mitigationCmds}</pre>
                )}
              </div>

              <div>
                <h4 className="font-semibold text-primary mb-2">Artifacts Collected</h4>
                <ul className="space-y-1">
                  {scenario.artifacts.map((artifact, index) => (
                    <li key={index} className="text-sm text-muted-foreground font-mono bg-muted/20 p-2 rounded">
                      {artifact}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
}