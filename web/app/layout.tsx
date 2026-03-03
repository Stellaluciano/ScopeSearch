import "./globals.css";

export const metadata = {
  title: "ScopeSearch",
  description: "Authorized attack surface discovery and exposure monitoring",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="bg-amber-200 text-amber-900 p-3 text-center text-sm font-semibold">
          Only scan assets you own or are authorized to test.
        </div>
        {children}
      </body>
    </html>
  );
}
