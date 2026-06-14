import path from "node:path";

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  outputFileTracingRoot: path.join(process.cwd()),
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.OPSWITNESS_API_ORIGIN ?? "http://127.0.0.1:8000"}/:path*`
      }
    ];
  }
};

export default nextConfig;
