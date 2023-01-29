// ex. scripts/build_npm.ts
import { build, emptyDir } from 'https://deno.land/x/dnt/mod.ts';

await emptyDir('./npm');

await build({
  entryPoints: [
    './mod.ts',
    {
      name: './app-check',
      path: './firebase/appcheck/verify.ts',
    },
  ],
  outDir: './npm',
  shims: {
    deno: true,
  },
  test: false,
  typeCheck: false,
  package: {
    // package.json properties
    name: '@lahirumaramba/edge-token-verifier',
    version: Deno.args[0]?.replace(/^v/, ''),
    description: 'Token Verifier for the Edge',
    license: 'Apache-2.0',
    repository: {
      type: 'git',
      url: 'git+https://github.com/lahirumaramba/edge_token_verifier.git',
    },
    bugs: {
      url: 'https://github.com/lahirumaramba/edge_token_verifier/issues',
    },
  },
  mappings: {
    'https://deno.land/x/jose@v4.11.2/index.ts': {
      name: 'jose',
      version: '^4.11.2',
      peerDependency: false,
    },
    'https://deno.land/x/jose@v4.11.2/types.d.ts': {
      name: 'jose',
      version: '^4.11.2',
      peerDependency: false,
    },
  },
});

// post build steps
Deno.copyFileSync('LICENSE', 'npm/LICENSE');
Deno.copyFileSync('README.md', 'npm/README.md');
