# XSS context contrasts

Optional synthetic examples for SKILL.md steps 2–3. These illustrate parser
models; they are not a probe sequence, authorization or session evidence.
The decision checkpoints and evidence requirements stay in SKILL.md.

### Context traces — synthetic source and responses, not session evidence

**Attribute boundaries.** An excerpt locates the marker in an attribute but leaves
its delimiter ambiguous. Competing double/single/unquoted hypotheses predict
different parses; an inert boundary test can distinguish them. A failed quote
probe does not settle the others. Use the delimiter directly when known.
Prefix + submitted input + suffix, with simulated complete returned tags:

| Source template | Submitted input | Returned tag / interpretation |
|---|---|---|
| `<input value="{input}" data-tail="t">` | `m" data-probe="yes` | `<input value="m" data-probe="yes" data-tail="t">`: new attribute, not execution. |
| `<input value='{input}' data-tail='t'>` | `m' data-probe='yes` | `<input value='m' data-probe='yes' data-tail='t'>`: matching single quote. |
| `<input value={input} data-tail=t>` | `m data-probe=yes` | `<input value=m data-probe=yes data-tail=t>`: whitespace ends the value. |
| `<input value="{input}" data-tail="t">` | `m&quot; data-probe=&quot;yes` | `<input value="m&quot; data-probe=&quot;yes" data-tail="t">`: decoded quotes remain value data. |

Raw `\"` is not an HTML quote escape. For the first template, the existing Phase 2
input `"><script>document.title='xsspoc-demo7'</script>` would yield
`<input value=""><script>document.title='xsspoc-demo7'</script>" data-tail="t">`.
The suffix is outside the completed script; predict this structure, then inspect
actual bytes and enclosing context under step 3, not just the attribute breakout.

**JavaScript boundaries.** For hypothesized source `const value='{input}';`, the
corpus quote-based marker predicts breakout if unescaped, string data if escaped.
Contrast simulated returned source, including the application's suffix:

```javascript
// Single-quoted breakout
const single='';document.title='xsspoc-demo7';//';
// Double-quoted breakout
const double="";document.title='xsspoc-demo7';//";
// Escaped quotes: marker text stays in the string
const escaped='\';document.title=\'xsspoc-demo7\';//';
// Quote-based input does not leave a template literal
const template=`';document.title='xsspoc-demo7';//`;
// Template interpolation is a different expression boundary
const interpolation=`${7 * 7}`;
```

Predict whether adjacent quotes/backslashes close the literal and whether `//`
consumes the suffix only to the next newline. Literal LF/CR, the two bytes `\n`,
backslash + physical newline and template newlines have different grammar. A
parse error rejects that assembly, not all JS hypotheses; test unresolved escaping
or delimiters from existing source. Acceptance or an unobserved computation is
not execution; apply step 3's deterministic-proof exception or `browser-required`.

**Nested parsers.** Submitted `x');document.title='xsspoc-demo7';//` could return as
`<button onclick="show('x&#39;);document.title=&#39;xsspoc-demo7&#39;;//')">go</button>`.
HTML decoding yields `show('x');document.title='xsspoc-demo7';//')`: encoding
did not neutralize that JS quote. Inspect decoded escaping and the trigger;
HTTP does not observe the click: `browser-required`. Similarly,
`<a href="javascript:document.title=&#39;xsspoc-demo7&#39;">go</a>` retains its scheme
after HTML decoding; inspect element, policy and navigation. Encoded URL text
alone does not establish percent/double decoding.

**Enclosing contexts.** Given inert `m`, compare enclosing source before Phase 2:

| Hypothetical output | Prediction → decision |
|---|---|
| `<p>m</p>` vs `<!--m-->` | HTML text vs comment data; test a compatible comment close only if justified. A script string inside the comment stays data. |
| `<textarea>m</textarea>` / `<title>m</title>` | `<script>` stays text; a matching enclosing end tag changes parsing. Inspect that boundary before claiming breakout. |
| `<template>m</template>` | Parsed contents are inert; later instantiation needs an evidenced path and execution assessment. |
| `<div style="color:m">` / `<style>p{color:m}</style>` | CSS is not JS; attribute quote/tag vs style end tag are distinct HTML breakout hypotheses. Inspect their suffixes. |

**Transformations: submitted input → simulated observed output → hypothesis → next decision.**
These examples assume complete captures; none establishes a universal sanitizer:

| Submitted input | Observed output | Interpretation and next decision |
|---|---|---|
| `<b>m</b>` | `&lt;b&gt;m&lt;/b&gt;` in HTML text | Data here; inspect evidenced later decoding/parsers before generalizing safety. |
| `'` | `\'` in JS source | Escape inserted; inspect adjacent backslashes, quote and newline. |
| `<script>m</script><b>m</b>` | `<b>m</b>` | Plausible script removal; surviving markup is not execution. Select a distinct context-supported test. |
| `<img src=x onerror="document.title='xsspoc-demo7'">` | `<img src=x>` | Handler removed; this trigger is neutralized. Do not try arbitrary event names. |
| `<b>m</b>` | `<b>m</b` | Complete capture: possible end-character removal; compare captures and consider step 3's compensating test. If capture is truncated, the missing bytes are unknown. |
| `javascript%3Adocument.title=1` | Same text in `href` | No percent-decode evidenced here; inspect URL handling before inferring another decode. |

Use only captured bytes for incomplete observations; name missing context, never
reconstruct it or use an inadmissible capture as terminal proof. Earlier phases'
observations can guide planning but do not become owned proof for this attempt.
Parsing references: [HTML tokenizer](https://html.spec.whatwg.org/multipage/parsing.html#tokenization),
[script contents](https://html.spec.whatwg.org/multipage/scripting.html#restrictions-for-contents-of-script-elements),
[template contents](https://html.spec.whatwg.org/multipage/scripting.html#the-template-element),
[ECMAScript literals](https://tc39.es/ecma262/multipage/ecmascript-language-lexical-grammar.html#sec-literals).

