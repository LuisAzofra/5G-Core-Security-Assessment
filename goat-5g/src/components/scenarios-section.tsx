import { useState } from "react";
import { AttackScenarioCard } from "./attack-scenario-card";
import { attackScenarios } from "../data/attack-scenarios";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";

export function ScenariosSection() {
  const [filter, setFilter] = useState<string>("all");

  const filteredScenarios = attackScenarios.filter(scenario => {
    if (filter === "all") return true;
    if (filter === "severity") return scenario.severity === "high";
    if (filter === "status") return scenario.status === "mitigated";
    return scenario.category.toLowerCase().includes(filter.toLowerCase());
  });

  const categories = Array.from(new Set(attackScenarios.map(s => s.category)));
  const stats = {
    total: attackScenarios.length,
    high: attackScenarios.filter(s => s.severity === "high").length,
    mitigated: attackScenarios.filter(s => s.status === "mitigated").length,
    medium: attackScenarios.filter(s => s.severity === "medium").length,
  };

  return (
    <section id="scenarios" className="py-20 bg-gradient-dark">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-6 bg-gradient-cyber bg-clip-text text-transparent">
            Attack Scenarios & Analysis
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Comprehensive security testing covering {attackScenarios.length} critical attack vectors against 5G Core components in Kubernetes environments
          </p>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-12">
          <div className="text-center p-4 bg-card/30 backdrop-blur rounded-lg border border-primary/20">
            <div className="text-3xl font-bold text-primary">{stats.total}</div>
            <div className="text-sm text-muted-foreground">Total Scenarios</div>
          </div>
          <div className="text-center p-4 bg-card/30 backdrop-blur rounded-lg border border-danger/20">
            <div className="text-3xl font-bold text-danger">{stats.high}</div>
            <div className="text-sm text-muted-foreground">High Severity</div>
          </div>
          <div className="text-center p-4 bg-card/30 backdrop-blur rounded-lg border border-warning/20">
            <div className="text-3xl font-bold text-warning">{stats.medium}</div>
            <div className="text-sm text-muted-foreground">Medium Severity</div>
          </div>
          <div className="text-center p-4 bg-card/30 backdrop-blur rounded-lg border border-success/20">
            <div className="text-3xl font-bold text-success">{stats.mitigated}</div>
            <div className="text-sm text-muted-foreground">Mitigated</div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2 mb-8">
          <Button
            variant={filter === "all" ? "default" : "outline"}
            onClick={() => setFilter("all")}
            className="mb-2"
          >
            All Scenarios
          </Button>
          <Button
            variant={filter === "severity" ? "default" : "outline"}
            onClick={() => setFilter("severity")}
            className="mb-2"
          >
            High Severity
          </Button>
          <Button
            variant={filter === "status" ? "default" : "outline"}
            onClick={() => setFilter("status")}
            className="mb-2"
          >
            Mitigated
          </Button>
          {categories.map(category => (
            <Badge
              key={category}
              variant={filter === category ? "default" : "outline"}
              className="cursor-pointer hover:bg-primary/20 mb-2"
              onClick={() => setFilter(category)}
            >
              {category}
            </Badge>
          ))}
        </div>

        {/* Scenarios Grid */}
        <div className="grid gap-6">
          {filteredScenarios.map((scenario) => (
            <AttackScenarioCard key={scenario.id} scenario={scenario} />
          ))}
        </div>

        {filteredScenarios.length === 0 && (
          <div className="text-center py-12">
            <p className="text-muted-foreground">No scenarios match the current filter.</p>
          </div>
        )}
      </div>
    </section>
  );
}