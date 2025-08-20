import { Shield, Menu } from "lucide-react";
import { Button } from "./button";
import { Sheet, SheetContent, SheetTrigger } from "./sheet";

const navItems = [
  { label: "Overview", href: "#overview" },
  { label: "Attack Scenarios", href: "#scenarios" },
  { label: "Documentation", href: "#documentation" },
  { label: "Mitigations", href: "#mitigations" }
];

export function Navbar() {
  return (
    <nav className="fixed top-0 w-full z-50 border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container relative flex h-16 items-center">
        <div className="flex items-center space-x-2">
          <Shield className="h-6 w-6 text-primary animate-glow-pulse" />
          <span className="font-bold text-xl bg-gradient-primary bg-clip-text text-transparent">
            5G Core Security Assessment
          </span>
        </div>
        
        <span className="hidden md:block absolute left-1/2 -translate-x-1/2 text-xs text-muted-foreground">
          Made by Luis Azofra Begara
        </span>

        <div className="hidden md:flex ml-auto space-x-6">
          {navItems.map((item) => (
            <a
              key={item.label}
              href={item.href}
              className="text-sm font-medium text-muted-foreground transition-colors hover:text-primary"
            >
              {item.label}
            </a>
          ))}
        </div>

        <Sheet>
          <SheetTrigger asChild>
            <Button variant="ghost" className="md:hidden ml-auto">
              <Menu className="h-5 w-5" />
            </Button>
          </SheetTrigger>
          <SheetContent>
            <div className="flex flex-col space-y-4 mt-4">
              {navItems.map((item) => (
                <a
                  key={item.label}
                  href={item.href}
                  className="text-sm font-medium text-muted-foreground transition-colors hover:text-primary"
                >
                  {item.label}
                </a>
              ))}
            </div>
          </SheetContent>
        </Sheet>
      </div>
    </nav>
  );
}