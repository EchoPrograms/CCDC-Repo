---
updated: 2026-11-20
tags: [ccdc, pii, injects]
---
# PII searcher

**Optional, scoped discovery for an inject or an approved data review.** This is not part of the initial setup phase. Keep results private; the competition note should contain counts, scope and an evidence path rather than raw personal information.

## Preferred quick search: filenames only

Use installed ripgrep from setup. Select the actual permitted data tree; do not sweep backups, `/proc`, `/sys` or the entire vault. The example detects SSN-like and 16-digit card-like text, not verified identities/cards:

```sh
umask 077
scope=/srv/app/data
result=$(mktemp /tmp/ccdc-pii-files.XXXXXXXX)
errors=$(mktemp /tmp/ccdc-pii-errors.XXXXXXXX)
sudo rg --files-with-matches --null --hidden --no-ignore -I \
  -e '(^|[^0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}([^0-9]|$)' \
  -e '(^|[^0-9])([0-9]{4}[ -]?){3}[0-9]{4}([^0-9]|$)' \
  -- "$scope" > "$result" 2> "$errors"
scan_status=$?
printf 'rg status=%s; filename list=%s; errors=%s\n' "$scan_status" "$result" "$errors"
```

The filename list is NUL-delimited to preserve unusual names. `rg` status `0` means matches, `1` means no matches, `2` indicates errors. Review the error file; don't turn permission/read failures into “no PII.” Hidden/ignored files are included; symlinks are not followed by default. Run against a stable copy if the app is changing data rapidly.

Inspect the selected files privately with a filename-safe workflow. If you generate a human-readable list using `tr '\000' '\n'`, filenames containing newlines become ambiguous. Keep raw matching records out of committed notes.

## Limits and validation

- Number patterns also match test fixtures, order IDs and documentation. The card-like expression covers only a narrow formatting/length case and performs no Luhn validation.
- Phone/address/email patterns need contextual review; they are not reliable classification by themselves.
- `-I` skips binary content. Archives, PDFs, database pages, images/OCR and encrypted files need format-aware tooling or authorized database queries.
- Define the inject's scope and required evidence before spending time on broad data discovery. Record false-positive handling and counts without copying sensitive values.
- File removal, permission changes and data redaction are separate approved remediation decisions; the search does none of them.

## Existing Snoopy tools

`SnoopyOnSecurity/Linux_Misc/pii.sh` uses Bash/GNU grep options and prints raw matches. `SnoopyOnSecurity/Pigpen/pigpen.sh` requires Bash arrays/process substitution and a local `./rg`; it scans broadly, applies exclusions/thresholds and prints example values. Both need review and scoping before use. They are not portable POSIX replacements for the hunter pipeline.

Prefer the small filename-only query above for an inject, then inspect only relevant candidates. See [[Tools - SnoopyOnSecurity|the tool inventory]] and [ripgrep's guide](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md) for regex, hidden-file and binary behavior. Return to [[00 CCDC Runbook]].
