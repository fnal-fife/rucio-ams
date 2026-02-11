/** @type {import('next').NextConfig} */
const nextConfig = {
  distDir: 'build',
  experimental: {
    workerThreads: false,
    cpus: 1
  }
}

module.exports = nextConfig
