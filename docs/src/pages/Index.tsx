import { Navbar } from "../components/ui/navbar";
import { HeroSection } from "../components/hero-section";
import { ScenariosSection } from "../components/scenarios-section";
import { DocumentationSection } from "../components/documentation-section";
import { MitigationsSection } from "../components/mitigations-section";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <HeroSection />
      <ScenariosSection />
      <DocumentationSection />
      <MitigationsSection />
      
      <footer className="py-8 border-t border-border/40 bg-background/95 backdrop-blur">
        <div className="container mx-auto px-4 text-center">
          <p className="text-muted-foreground">
            5G Core Security Assessment Project • Kubernetes Goat • Open5GS • SD-Core • OAI
          </p>
          <p className="mt-2 text-xs text-muted-foreground">Made by Luis Azofra Begara</p>
        </div>
      </footer>
    </div>
  );
};

export default Index;