const path = require('path')
const CopyPlugin = require('copy-webpack-plugin')
const { execSync } = require('child_process')

// Generate rules.json before webpack processes anything
execSync('node scripts/generate-rules.js', { stdio: 'inherit' })

module.exports = {
  mode: 'production',
  devtool: 'source-map',
  entry: {
    background: './src/background/index.ts',
    content:    './src/content/index.ts',
    // Defenses (MAIN world — spoof/block)
    canvas:     './src/injected/canvas.ts',
    webrtc:     './src/injected/webrtc.ts',
    // Detectors (MAIN world — detect and report)
    audio:      './src/injected/audio.ts',
    webgl:      './src/injected/webgl.ts',
    fonts:      './src/injected/fonts.ts',
    hardware:   './src/injected/hardware.ts',
    // UI
    popup:      './src/popup/index.ts',
    dashboard:  './src/dashboard/index.ts',
    settings:   './src/settings/index.ts',
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    clean: true,
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: 'public', to: '.' },
        { from: 'src/popup/index.html',     to: 'popup.html' },
        { from: 'src/dashboard/index.html', to: 'dashboard.html' },
        { from: 'src/settings/index.html',  to: 'settings.html' },
      ],
    }),
  ],
  optimization: {
    // Keep output readable — good for portfolio / inspection
    minimize: false,
  },
}
