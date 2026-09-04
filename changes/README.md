# Changelog Fragments

Add fragments here for user-visible changes, using English prose.

Supported suffixes are `.feature.md`, `.bugfix.md`, and `.doc.md`. Use an issue
number as the filename prefix, or let Towncrier generate an anonymous identifier:

```bash
uv run --frozen towncrier create +.feature.md --content 'Describe the user-visible change.' --no-edit
```

At release time, preview and build the notes through the documented release
workflow, then synchronize `docs/changelog.md`. Remove consumed fragments after
their contents have been incorporated into `CHANGELOG.md`. This README is not a
release fragment and keeps the directory present in fresh checkouts.
