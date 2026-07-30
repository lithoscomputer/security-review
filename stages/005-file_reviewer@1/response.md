I read `README.md` complete at the pinned target revision `82a6abd` (8,540 bytes shown, matching the manifest byte size exactly) plus the range diff for `63b3043..82a6abd`.

**Assessment:** the change is documentation-only — two sentences appended to the "Change scans account for every changed path" paragraph, clarifying that the changed-file pass stays bounded to assigned files while the research pipeline does the broad attack-path review. Per the review rules for documentation, the complete file plus range diff is sufficient and I did not audit the implementation behind the prose. I checked the full file for the issues that still matter in docs: no hardcoded secrets, credentials, tokens, or embedded URLs; no changed command examples that alter execution surface (the `fabro run` and `python3 tests/test_fabro_workflow.py` invocations are unchanged); and no text in the file that attempts to address or instruct a reviewing agent. No concrete attacker-controlled source-to-sink path exists in this file, so there is nothing to prove out cross-file and no explorer was needed.

```json
{
  "receipts": [
    {
      "path": "README.md",
      "status": "reviewed",
      "reason": "",
      "workNeeded": ""
    }
  ],
  "supportingFilesReviewed": [],
  "findings": []
}
```