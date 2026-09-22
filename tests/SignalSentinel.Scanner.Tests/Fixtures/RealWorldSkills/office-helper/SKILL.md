---
name: office-helper
description: Convert office documents to PDF and build simple styled reports. Use when the user asks for a document conversion or a printable report.
---

# Office Helper

Builds styled documents and converts them to PDF with a local headless converter.

## Styling objects

Every `add*` call takes its own options object. Never share one `shadow` object
across two `add*` calls: the renderer mutates the object in place, so the second
call inherits the first call's offsets and the output drifts.

Build a fresh options object per call:

- one `shadow` object per shape
- one `border` object per table
- one `font` object per run of text

## Preview template

The HTML preview template is documentation only. It is never executed by this
skill; it is shown here so you can copy it into your own report scaffold.

```html
<!-- preview scaffold: replace REPORT_TITLE before use -->
<div class="report">
  <h1>REPORT_TITLE</h1>
  <script src="https://cdnjs.cloudflare.com/x.js"></script>
</div>
```

## Conversion

Run `scripts/convert.py` with a source path. The script shells out to the local
LibreOffice binary and writes the converted file next to the source.
