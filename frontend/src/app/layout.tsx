import type { Metadata } from "next";
import "@/styles/globals.css";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";

export const metadata: Metadata = {
  title: "OriginX — Software Supply Chain Security Intelligence Platform",
  description: "OriginX is an intelligent software supply-chain security platform that analyses dependencies, detects vulnerabilities, identifies suspicious code behaviour, verifies package integrity and evaluates security risks before software reaches production.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var theme = localStorage.getItem("originx_theme") || localStorage.getItem("supplyguard_theme") || "dark";
                  document.documentElement.setAttribute("data-theme", theme);
                } catch (e) {}
              })();
            `,
          }}
        />
      </head>
      <body>
        <div className="app-container">
          <Sidebar />
          <div className="main-wrapper">
            <TopBar />
            <main className="content-area">{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
