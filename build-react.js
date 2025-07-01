const esbuild = require('esbuild');
const path = require('path');

const inputPath = path.resolve(__dirname, 'frontend', 'index.js');
const outputPath = path.resolve(__dirname, 'public', 'js', 'react-bundle.js');

console.log(`Building React app from: ${inputPath}`);
console.log(`Outputting to: ${outputPath}`);

esbuild.build({
  entryPoints: [inputPath],
  bundle: true,        // Bundle all modules into a single file
  outfile: outputPath, // Output file path
  minify: true,        // Minify the output (optional, good for production)
  sourcemap: true,     // Generate a source map for debugging (optional)
  format: 'iife',      // Important: Use IIFE to expose to global scope (window)
  globalName: 'TechSevaReact', // Optional: Global variable name for your bundle if needed,
                               // though we explicitly attach renderLocationSearchInput to window.
  loader: {            // Configure loaders for different file types
    '.js': 'jsx',      // Treat .js files as JSX
    '.jsx': 'jsx',     // Treat .jsx files as JSX
  },
  define: {
    'process.env.NODE_ENV': '"production"', // Set Node.js environment variable for React optimization
  },
  // We are bundling React and ReactDOM, so no need for 'external'
  // external: ['react', 'react-dom'],
}).then(() => {
  console.log('✅ React app build successful!');
}).catch((error) => {
  console.error('❌ React app build failed:', error);
  process.exit(1); // Exit with error code
});
