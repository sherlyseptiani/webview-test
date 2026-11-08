import './globals.css';

export const metadata = {
  title: 'WebView Bridge Exposure — Security Evidence',
  description: 'Internal, display-only security demonstration. No network, no persistence.',
};

export const viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
