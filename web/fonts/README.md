# Fonts

The two typefaces the UI uses, served by ansbui itself. They used to
be loaded from Google Fonts, which put a stylesheet from another
origin into the page that holds every password field.

| File | Typeface | Upstream release | SHA-256 |
|---|---|---|---|
| `InterVariable.woff2` | Inter, variable (weights 100–900) | [rsms/inter v4.1](https://github.com/rsms/inter/releases/tag/v4.1), `Inter-4.1.zip` → `web/InterVariable.woff2` | `693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3` |
| `JetBrainsMono-Regular.woff2` | JetBrains Mono 400 | [JetBrains/JetBrainsMono v2.304](https://github.com/JetBrains/JetBrainsMono/releases/tag/v2.304), `JetBrainsMono-2.304.zip` → `fonts/webfonts/` | `a9cb1cd82332b23a47e3a1239d25d13c86d16c4220695e34b243effa999f45f2` |
| `JetBrainsMono-Medium.woff2` | JetBrains Mono 500 | same archive | `086c48dfbea9ddaff1320f7e09399b8e2924e88ce67453721255db3bdbb5a353` |
| `JetBrainsMono-SemiBold.woff2` | JetBrains Mono 600 | same archive | `918edad542a1da608fd2ba8daebaff9ac802309103fe760eed465b8b4e47faf1` |

The files are the bytes from those archives, unmodified:

| Archive | SHA-256 |
|---|---|
| `Inter-4.1.zip` | `9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e` |
| `JetBrainsMono-2.304.zip` | `6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf` |

Verify after any update: `sha256sum web/fonts/*.woff2`. A test
(`internal/api/static_fonts_test.go`) fails if a file here does not
match this table or if the stylesheet names a font file that is not
here.

Both typefaces are under the SIL Open Font License 1.1:
`Inter-LICENSE.txt` and `JetBrainsMono-OFL.txt` are the licence files
from the same archives.

The `@font-face` rules are at the top of `../styles/tokens.css`.
Italics are not shipped (the old Google Fonts link did not request
them either); the browser slants the upright face where the UI asks
for italic.
