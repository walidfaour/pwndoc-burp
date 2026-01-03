# Changelog

All notable changes to PwnDoc Burp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2025-03-09

### Fixed
- Ensured Update/Delete Finding tables keep hidden IDs so editing works even for older audits.
- Normalized finding ID detection (`_id`, `id`, or `findingId`) to support legacy data.
- Improved error messaging when a finding ID is missing during edit/delete actions.

## [1.0.1] - 2025-03-08

### Added
- Audit tab shortcuts to **Create**, **Update**, and **Delete** findings, mirroring context-menu workflows with automatic authentication and default-audit prompts.

### Changed
- Default audit selection now stores the audit type and clears all default-audit fields together to keep finding workflows consistent.
- Bumped extension/package version to **1.0.1**.

## [1.0.0] - 2025-12-28

### Added
- Initial release of PwnDoc Burp extension
- **Finding Management**
  - Create new findings directly from Burp Suite context menu
  - Update existing findings with new evidence
  - Auto-populate finding fields from vulnerability templates
  - Support for all standard PwnDoc finding fields

- **CVSS 3.1 Calculator**
  - Interactive calculator with clickable buttons
  - Real-time score and severity calculation
  - Visual feedback with color-coded severity levels
  - Automatic vector string generation

- **Vulnerability Library Integration**
  - Browse PwnDoc vulnerability templates
  - Search and filter templates
  - Category-based organization
  - One-click template population

- **Custom Fields Support**
  - Automatic loading of PwnDoc custom fields
  - Filtering by audit type (WEB, API, MOBILE, etc.)
  - Support for text, select, multi-select, checkbox, and date fields

- **Proof of Concept Upload**
  - Upload multiple screenshot files
  - Images embedded in finding's proof section
  - Support for PNG and JPG formats

- **Audit Management**
  - View all available audits
  - Filter audits by status
  - Direct access from context menu

- **Configuration**
  - Secure credential storage
  - Connection testing
  - Settings persistence across sessions

### Technical Details
- Built with Burp Suite Montoya API (2025.11)
- Java 21 compatibility
- Gradle build system with Shadow plugin
- Gson for JSON processing

---

## Future Plans

### Planned Features
- [ ] BApp Store submission
- [ ] TOTP/2FA authentication support
- [ ] Batch finding creation
- [ ] Finding templates within the extension
- [ ] Offline mode with sync
- [ ] Report generation integration

### Under Consideration
- Dark/Light theme support
- Keyboard shortcuts
- Finding duplication
- Export/Import configurations

---

[1.0.2]: https://github.com/walidfaour/pwndoc-burp/releases/tag/v1.0.2
[1.0.1]: https://github.com/walidfaour/pwndoc-burp/releases/tag/v1.0.1
[1.0.0]: https://github.com/walidfaour/pwndoc-burp/releases/tag/v1.0.0
