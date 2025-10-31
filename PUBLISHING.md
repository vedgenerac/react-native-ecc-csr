# Publishing to NPM

Guide for publishing `react-native-ecc-csr` to NPM.

## Prerequisites

1. NPM account (create at https://www.npmjs.com/signup)
2. Access to publish the package (for collaborators)
3. Git repository set up

## Pre-publish Checklist

- [ ] All tests pass
- [ ] Documentation is complete and accurate
- [ ] Version number updated in `package.json`
- [ ] CHANGELOG.md updated with new version
- [ ] README.md reviewed
- [ ] Example app works on both iOS and Android
- [ ] No uncommitted changes
- [ ] Git tags are up to date

## Publishing Steps

### 1. Login to NPM

```bash
npm login
```

Enter your NPM credentials.

### 2. Update Version

Follow semantic versioning (https://semver.org/):
- MAJOR version for incompatible API changes
- MINOR version for backwards-compatible functionality
- PATCH version for backwards-compatible bug fixes

```bash
# For patch release (1.0.0 -> 1.0.1)
npm version patch

# For minor release (1.0.0 -> 1.1.0)
npm version minor

# For major release (1.0.0 -> 2.0.0)
npm version major
```

### 3. Update CHANGELOG

Edit `CHANGELOG.md` and add the new version with changes:

```markdown
## [1.0.1] - 2024-10-30

### Fixed
- Bug fix description

### Added
- New feature description
```

### 4. Test Package Locally

```bash
# Build the package
npm pack

# This creates react-native-ecc-csr-1.0.0.tgz

# Test in a new React Native project
npm install /path/to/react-native-ecc-csr-1.0.0.tgz
```

### 5. Commit and Tag

```bash
git add .
git commit -m "Release v1.0.1"
git tag v1.0.1
git push origin main
git push origin v1.0.1
```

### 6. Publish to NPM

```bash
# Dry run (test without publishing)
npm publish --dry-run

# Publish
npm publish
```

### 7. Verify Publication

```bash
# Check on NPM
npm info react-native-ecc-csr

# Install from NPM in a test project
npm install react-native-ecc-csr
```

### 8. Create GitHub Release

1. Go to your GitHub repository
2. Click "Releases" → "Create a new release"
3. Select the tag (v1.0.1)
4. Add release notes from CHANGELOG
5. Publish release

## Post-publish

- [ ] Test installation from NPM
- [ ] Update documentation if needed
- [ ] Announce on social media/forums
- [ ] Monitor issues and feedback

## Troubleshooting

### "You do not have permission to publish"

Make sure you're logged in with the correct NPM account:

```bash
npm whoami
npm logout
npm login
```

### "Version already exists"

You need to update the version number:

```bash
npm version patch
npm publish
```

### "Package name already exists"

Choose a different package name in `package.json`.

## Beta/Alpha Releases

For pre-release versions:

```bash
# Update version with tag
npm version 1.1.0-beta.1

# Publish with tag
npm publish --tag beta
```

Install beta version:

```bash
npm install react-native-ecc-csr@beta
```

## Unpublishing

**WARNING:** Unpublishing is permanent and should be avoided.

```bash
# Unpublish specific version (within 72 hours)
npm unpublish react-native-ecc-csr@1.0.0

# Deprecate instead (recommended)
npm deprecate react-native-ecc-csr@1.0.0 "This version has a critical bug, please upgrade"
```

## Automated Publishing (GitHub Actions)

Create `.github/workflows/publish.yml`:

```yaml
name: Publish to NPM

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Add your NPM token to GitHub Secrets:
1. Generate token at https://www.npmjs.com/settings/tokens
2. Add to GitHub: Settings → Secrets → New repository secret
3. Name: `NPM_TOKEN`

## Version History

| Version | Date | Notes |
|---------|------|-------|
| 1.0.0 | 2024-10-30 | Initial release |

## Support

For publishing issues, contact the package maintainer.