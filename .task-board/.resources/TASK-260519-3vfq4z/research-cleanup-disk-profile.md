# Research: Mac cleanup and disk profiling utilities

Date: 2026-05-19

## Products reviewed

- CleanMyMac / CleanMyMac X by MacPaw
- DaisyDisk
- OmniDiskSweeper
- GrandPerspective
- Pearcleaner / AppCleaner class utilities
- macOS built-in behavior around local snapshots and Trash

## Cleanup utility feature map

### CleanMyMac-style cleanup

CleanMyMac groups cleanup into broad modules rather than a raw filesystem walker:

- Smart Care combines cleanup, protection, performance, app update recommendations, and duplicate/download clutter. Cleanup scans system junk, mail attachments, trash bins, broken login items, and similar categories.
- System Junk includes user/system caches, user/system logs, downloads, old updates, unused disk images, document versions, iOS device backups, Xcode junk, broken login items/preferences, language files, and some binary slimming categories.
- It applies "smart selection" rules. Some categories are auto-selected, while risky or user-owned categories are not. Examples: large files are not selected automatically; some Xcode items like archives/module caches/simulators are excluded from automatic selection.
- Large & Old Files / My Clutter scans a selected location, filters files above a threshold (CleanMyMac docs mention 50 MB), groups by kind, size, and access date, and leaves deletion decisions to the user.
- App uninstaller scans applications and associated resources, groups apps by unused/vendor/store/etc., and removes app-related files. System apps are excluded because of macOS restrictions.
- Mail attachment cleanup removes locally cached attachment copies that can be recovered from the mail source; modified copies are treated differently.

Design takeaways:

- Separate "known safe generated data" from "user data review".
- Never auto-select or auto-delete large/old user files.
- Xcode cleanup needs finer categories: DerivedData/build products are safer than Archives, DeviceSupport, docs, or simulators.
- App leftovers are useful but fragile; they need review-first behavior and high-confidence ownership matching.

### App cleaner class

Pearcleaner/AppCleaner-style tools focus on app-associated files:

- Select or drag an `.app`.
- Enumerate related files under locations such as `~/Library/Application Support`, `~/Library/Caches`, `~/Library/Preferences`, `~/Library/Containers`, and `~/Library/LaunchAgents`.
- Show every path and size before removal.
- Prefer moving to Trash, not permanent deletion.
- Some tools have an optional monitor that detects app bundles moved to Trash and proposes leftover cleanup.

Design takeaways:

- This should be a later app-leftovers story, not part of first cleanup release.
- Matching must be conservative: bundle identifier, app name, vendor path, and plist ownership. Name-only matching can delete unrelated files.

## Disk profiler feature map

### DaisyDisk

DaisyDisk scans disks or folders and presents a visual disk map:

- Disk overview shows mounted volumes and free/used state.
- Scan results identify largest folders/files and support drill-down, preview, reveal in Finder, and deletion via collector.
- It explicitly models hidden space: the gap between total used space and scannable files. Causes include restricted folders, other users' homes, APFS volumes, Spotlight/document versions, filesystem overhead, local snapshots, and other purgeable data.
- Administrator scans can reveal restricted content, but are not always necessary.
- Purgeable space is mostly local Time Machine snapshots, caches, swap/sleep images, and temporary system files. macOS may reclaim it automatically, and calculations are asynchronous.
- App Store edition limitations affect admin scanning and purgeable-space operations.

Design takeaways:

- Our first disk profiler should be read-only and honest about "unaccounted/hidden" space.
- It should report permission-denied directories separately.
- It should not implement forced purgeable-space deletion in v1.
- It should distinguish apparent size from actual disk blocks where possible because APFS clones/sparse files/hard links can distort accounting.

### OmniDiskSweeper

OmniDiskSweeper is the simple version:

- Recursively scans a drive/folder.
- Shows entries largest-to-smallest.
- Lets the user open or move items to Trash.

Design takeaways:

- CLI v1 can provide this value with a stable table/tree output.
- "Top directories by size" and "top files by size" are high-value without UI.

### GrandPerspective

GrandPerspective visualizes disk usage as a treemap:

- Rectangles are proportional to file size and grouped by folder.
- Supports coloring by name, extension, file type, parent folder, hierarchy level, creation/modification/access time, etc.
- Supports filters and masks by name, path, size, file type, hard-link status, package status, and scan-time exclusion.
- Can reveal in Finder, Quick Look, delete from the view, rescan/compare, export scan results, and save/reload scan results.
- Full Disk Access improves scan coverage.

Design takeaways:

- CLI v1 does not need visualization, but should output structured JSON so a future UI/TUI can render tree maps.
- Filters/excludes are core, not polish.
- Save/reload scan results should be built in early.

## macOS behavior that matters

- Time Machine local snapshots are expected behavior. Apple says they are retained locally and counted as available storage because macOS removes them as space is needed.
- DaisyDisk documents purgeable space as outside normal scannable areas on APFS; forced purging is a special operation with delays and edition limitations.
- Moving to Trash is different from permanent deletion. Apple's FileManager exposes a trash operation; direct deletion APIs permanently remove files.

## Proposed product boundaries for mac-infra

### We should build

- Read-only disk profiler:
  - scan any target directory or volume
  - top directories/files
  - size by extension/type
  - permission-denied and skipped path reporting
  - JSON and text output
  - optional save/reload scan artifacts

- Safe cleanup:
  - scan-first summary
  - allowlisted categories only
  - target-folder cleanup for repo/build artifacts
  - Xcode generated-data cleanup with category switches
  - logs/cache cleanup with age thresholds
  - Trash-first removal by default
  - permanent deletion only with explicit flag

- Later app leftovers:
  - app bundle inspect
  - related file candidate list
  - confidence scoring and review
  - no automatic app leftover deletion in v1

### We should not build in v1

- Malware scanning
- RAM "cleaning"
- Binary slimming / language stripping
- Forced purgeable-space deletion
- Automatic duplicate deletion
- App uninstaller with name-only matching
- Browser/mail privacy cleanup without app-specific semantics

## Sources

- CleanMyMac Smart Care: https://macpaw.com/support/cleanmymac/knowledgebase/smart-care/
- CleanMyMac System Junk: https://macpaw.com/support/cleanmymac-x/knowledgebase/system-junk
- CleanMyMac Large & Old Files: https://macpaw.com/support/cleanmymac/knowledgebase/large-and-old
- CleanMyMac Uninstaller: https://macpaw.com/support/cleanmymac/knowledgebase/uninstaller
- CleanMyMac Mail Attachments: https://macpaw.com/support/cleanmymac-x/knowledgebase/mail-attachments
- DaisyDisk guide: https://daisydiskapp.com/guide/4/en/
- DaisyDisk hidden space: https://daisydiskapp.com/guide/4/en/HiddenSpace/
- DaisyDisk purgeable space: https://daisydiskapp.com/guide/4/en/PurgeableSpace
- DaisyDisk scanning as administrator: https://daisydiskapp.com/guide/4/en/AdminScan/
- DaisyDisk locating space wasters: https://daisydiskapp.com/guide/4/en/LocatingSpaceWasters/
- OmniDiskSweeper: https://www.omnigroup.com/products/omnidazzle/
- GrandPerspective App Store feature list: https://apps.apple.com/us/app/grandperspective/id1111570163?mt=12
- GrandPerspective views: https://grandperspectiv.sourceforge.net/HelpDocumentation/Views.html
- GrandPerspective filters/masks: https://grandperspectiv.sourceforge.net/HelpDocumentation/MasksAndFilters.html
- Pearcleaner: https://www.pearcleaner.com/
- Apple Time Machine local snapshots: https://support.apple.com/en-us/ht204015
- Apple FileManager: https://developer.apple.com/documentation/foundation/filemanager
