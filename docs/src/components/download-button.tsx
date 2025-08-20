import { Download } from "lucide-react";
import { Button } from "./ui/button";

export function DownloadButton() {
  const handleDownload = () => {
    // Create download link for the documentation
    const link = document.createElement('a');
    link.href = '/5G-Core-Security-Assessment-Report.md';
    link.download = '5G-Core-Security-Assessment-Report.md';
    link.target = '_blank';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <Button
      onClick={handleDownload}
      className="bg-primary hover:bg-primary/90 text-primary-foreground"
    >
      <Download className="w-4 h-4 mr-2" />
      Download Full Report
    </Button>
  );
}