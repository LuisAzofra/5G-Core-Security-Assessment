import { Shield, Target, Lock, AlertTriangle } from "lucide-react";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { attackScenarios } from "../data/attack-scenarios";

export function HeroSection() {
  return (
    <section id="overview" className="min-h-screen flex items-center justify-center bg-gradient-dark relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0 opacity-20">
        <div className="absolute top-20 left-10 w-32 h-32 bg-primary/20 rounded-full blur-xl animate-float"></div>
        <div className="absolute bottom-40 right-20 w-24 h-24 bg-primary-glow/30 rounded-full blur-lg animate-float" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-1/2 left-1/3 w-16 h-16 bg-primary/25 rounded-full blur-md animate-float" style={{ animationDelay: '2s' }}></div>
      </div>

      <div className="container mx-auto px-4 relative z-10">
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-primary/20 rounded-full mb-8 animate-glow-pulse">
            <Shield className="w-10 h-10 text-primary" />
          </div>
          
          <h1 className="text-5xl md:text-7xl font-bold mb-6 bg-gradient-cyber bg-clip-text text-transparent">
            5G Core Security Assessment
          </h1>
          
          <p className="text-xl md:text-2xl text-muted-foreground mb-8 max-w-3xl mx-auto">
            Comprehensive security evaluation of Open5GS, SD-Core, and OAI 5G Core within Kubernetes Goat environment
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button asChild size="lg" className="bg-gradient-primary hover:opacity-90 transition-opacity">
              <a href="#scenarios">View Attack Scenarios</a>
            </Button>
            <Button asChild variant="outline" size="lg" className="border-primary/50 text-primary hover:bg-primary/10">
              <a href="/5G-Core-Security-Assessment-Report.md" download="5G-Core-Security-Assessment-Report.md">
                Download Documentation
              </a>
            </Button>
          </div>
        </div>

        <div className="grid md:grid-cols-4 gap-6 mt-16">
          <Card className="p-6 bg-card/50 backdrop-blur border-primary/20 hover:border-primary/40 transition-colors">
            <Target className="w-8 h-8 text-danger mb-4" />
            <h3 className="font-semibold text-lg mb-2">Attack Scenarios</h3>
            <p className="text-muted-foreground text-sm">{attackScenarios.length} comprehensive attack vectors tested against 5G Core components</p>
          </Card>

          <Card className="p-6 bg-card/50 backdrop-blur border-primary/20 hover:border-primary/40 transition-colors">
            <Lock className="w-8 h-8 text-warning mb-4" />
            <h3 className="font-semibold text-lg mb-2">Vulnerabilities</h3>
            <p className="text-muted-foreground text-sm">Critical security issues identified and documented</p>
          </Card>

          <Card className="p-6 bg-card/50 backdrop-blur border-primary/20 hover:border-primary/40 transition-colors">
            <Shield className="w-8 h-8 text-success mb-4" />
            <h3 className="font-semibold text-lg mb-2">Mitigations</h3>
            <p className="text-muted-foreground text-sm">Zero Trust policies and hardening strategies implemented</p>
          </Card>

          <Card className="p-6 bg-card/50 backdrop-blur border-primary/20 hover:border-primary/40 transition-colors">
            <AlertTriangle className="w-8 h-8 text-primary mb-4" />
            <h3 className="font-semibold text-lg mb-2">Results</h3>
            <p className="text-muted-foreground text-sm">Validated defense mechanisms and security improvements</p>
          </Card>
        </div>
      </div>
    </section>
  );
}