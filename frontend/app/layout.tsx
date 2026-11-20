import type { Metadata } from "next";
import Script from "next/script";
import type { ReactNode } from "react";
import "./styles.css";

export const metadata: Metadata = {
  title: "AWS Security Monitor",
  description: "AWS cloud security monitoring platform",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <head>
        <Script src="/runtime-config.js" strategy="beforeInteractive" />
      </head>
      <body>{children}</body>
    </html>
  );
}
