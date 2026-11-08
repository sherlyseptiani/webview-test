/** @type {import('next').NextConfig} */
// Static export: `next build` emits plain HTML/JS into ./out with no server.
// Serve that folder from the test host; the page then runs fully offline after load.
const nextConfig = {
  output: 'export',
  reactStrictMode: true,
  images: { unoptimized: true },
};

module.exports = nextConfig;
