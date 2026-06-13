import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "OpsWitness",
  description: "Evidence-first AI incident investigation for Splunk MCP"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
