TPL = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CrackStation — prototype __N__, __NAME__</title>
<style>
:root{
__PALETTE__
  --suc:#00FF00; --part:#FFFF00; --fail:#FF0000; --more:#DDDDDD;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"DejaVu Sans Mono",monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 var(--sans);
     display:flex;flex-direction:column;min-height:100vh}
a{color:var(--accent)}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px;width:100%}

/* ---------- masthead: the existing logo, on the black it was drawn for ---------- */
.masthead{background:#000}
.masthead .wrap{display:flex;align-items:center;padding-top:6px;padding-bottom:6px}
.logo{display:block;max-width:100%;height:auto;width:591px}

/* ---------- nav ---------- */
.nav{border-bottom:1px solid var(--rule);background:var(--panel)}
.nav .wrap{display:flex;align-items:center;gap:26px;min-height:60px;flex-wrap:wrap}
.nav ul{display:flex;gap:20px;list-style:none;margin:0;padding:0;align-items:center;width:100%}
.nav a.item{font-size:14px;text-decoration:none;color:var(--ink-dim);white-space:nowrap}
.nav a.item:hover,.nav a.item[aria-current]{color:var(--ink)}
.nav .ext{padding-left:20px;border-left:1px solid var(--rule);display:flex;gap:14px;align-items:center}
.nav .ext a{font-size:13px;color:var(--ink-dim);text-decoration:none;display:flex;align-items:center;gap:5px}
.nav .ext a:hover{color:var(--ink)}
.nav .ext img{height:16px;width:auto;opacity:.75}
#navtoggle,.burger{display:none}
@media(max-width:860px){
  .nav ul{display:none;width:100%;flex-direction:column;gap:0;align-items:stretch;margin:0 0 8px}
  .nav ul li{border-top:1px solid var(--rule)}
  .nav a.item{display:block;padding:12px 2px;font-size:15px}
  .nav .ext{border-left:0;padding:10px 0 0}
  .burger{display:block;margin-left:0;font:600 13px/1 var(--mono);letter-spacing:.08em;
          border:1px solid var(--rule);background:var(--field);color:var(--ink);padding:9px 12px;cursor:pointer}
  #navtoggle:checked ~ ul{display:flex}
}

/* ---------- instrument ---------- */
main{flex:1;padding:32px 0 56px}
h1{font:600 15px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--ink-dim);margin:0 0 12px}
.panel{background:var(--panel);border:1px solid var(--rule-strong)}
.io{display:flex;font-family:var(--mono)}
__GUTTERCSS__
.field{flex:1;min-width:0}
textarea{width:100%;border:0;background:var(--field);color:var(--ink);resize:vertical;
         font:__TASIZE__/1.7 var(--mono);padding:14px 16px;display:block;min-height:__TAMIN__;outline:0}
.controls{display:flex;align-items:center;gap:16px;padding:12px 16px;border-top:1px solid var(--rule);flex-wrap:wrap}
.captcha{width:302px;height:76px;border:1px solid var(--rule);background:var(--field);display:flex;
         align-items:center;justify-content:center;color:var(--gutter-ink);font:12px/1 var(--mono);letter-spacing:.08em}
button{margin-left:auto;font:600 14px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;
       background:var(--ink);color:var(--panel);border:0;padding:16px 30px;cursor:pointer}
button:hover{background:var(--accent);color:#06060a}
.supports{font:12px/1.6 var(--mono);color:var(--ink-dim);margin:10px 2px 0}
.supports b{color:var(--ink);font-weight:600}

/* ---------- status strip ---------- */
.strip{display:flex;flex-wrap:wrap;gap:0 22px;padding:11px 16px;background:var(--strip-bg);
       border:1px solid var(--rule-strong);border-top:0;font:13px/1.5 var(--mono);color:var(--ink-dim)}
.strip b{color:var(--ink);font-weight:600}

/* ---------- results: sized by content, never wrapped, never clipped ---------- */
.results-region{margin-top:__RTOP__}
table.results{border-collapse:collapse;font:__RSIZE__/1.45 var(--mono);width:auto}
table.results th{font:600 11px/1 var(--mono);letter-spacing:.11em;text-transform:uppercase;text-align:left;
                 padding:8px 9px;white-space:nowrap;border:1px solid var(--grid);
                 background:var(--thbg);color:var(--think)}
table.results td{padding:__RPAD__ 9px;border:1px solid var(--grid);color:#000;white-space:nowrap}
tr.suc{background:var(--suc)} tr.part{background:var(--part)}
tr.fail{background:var(--fail)} tr.more{background:var(--more);font-style:italic}
.matched{background:var(--suc);outline:1px solid rgba(0,0,0,.35)}
.legend{font:12px/1.6 var(--mono);color:var(--ink-dim);margin:12px 2px 0}
.download{margin:34px 0 0;text-align:center}
.download a{font:600 14px/1 var(--mono);letter-spacing:.06em;text-decoration:none;color:var(--ink);
            border:1px solid var(--rule-strong);padding:14px 22px;display:inline-block}
.download a:hover{background:var(--accent);color:#06060a;border-color:var(--accent)}
.prose{max-width:66ch;margin:48px 0 0}
.prose h2{font:600 15px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--ink-dim);
          border-bottom:1px solid var(--rule);padding-bottom:10px}

/* ---------- footer ---------- */
footer{background:var(--footbg);border-top:1px solid var(--rule);color:var(--ink-dim);
       font-size:13px;padding:20px 0 26px}
footer .wrap{display:flex;flex-wrap:wrap;gap:18px 30px;align-items:center}
footer a{color:var(--ink-dim);text-decoration:none}
footer a:hover{color:var(--ink)}
.hits{font:13px/1.5 var(--mono);font-variant-numeric:tabular-nums}
.hits b{color:var(--ink);font-weight:600}
.footlinks{display:flex;gap:14px;flex-wrap:wrap;margin-left:auto;align-items:center}
.footlinks img{height:31px;width:auto;vertical-align:middle;opacity:.8}
.tag{position:fixed;right:0;bottom:0;background:var(--ink);color:var(--bg);
     font:11px/1 var(--mono);padding:7px 10px;letter-spacing:.06em}
</style></head><body>

<header class="masthead"><div class="wrap">
  <a href="#"><img class="logo" src="../../static/images/crackstation_header.png" alt="CrackStation"></a>
</div></header>

<nav class="nav"><div class="wrap">
  <input type="checkbox" id="navtoggle"><label class="burger" for="navtoggle">MENU</label>
  <ul>
    <li><a class="item" href="#" aria-current="page">Cracker</a></li>
    <li><a class="item" href="#">Wordlist</a></li>
    <li><a class="item" href="#">Hashing Security</a></li>
    <li><a class="item" href="#">About</a></li>
    <li><a class="item" href="#">Contact</a></li>
    <li><a class="item" href="#">ToS &amp; Privacy</a></li>
    <li class="ext" style="margin-left:auto">
      <a href="https://defuse.ca/">Defuse.ca</a>
      <a href="https://twitter.com/defusesec"><img src="../../static/images/twitter.png" alt="">Twitter</a>
    </li>
  </ul>
</div></nav>

<main><div class="wrap">
  <h1>Free Password Hash Cracker</h1>

  <div class="panel">
    <div class="io">
__GUTTERHTML__
      <div class="field"><textarea spellcheck="false">5d41402abc4b2a76b9719d911017c592
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
e52cac67419a9a220000000000000000
9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
0000000000000000000000000000000000000000
not-a-hex-hash</textarea></div>
    </div>
    <div class="controls">
      <div class="captcha">RECAPTCHA</div>
      <button type="submit">Crack Hashes</button>
    </div>
  </div>

  <p class="supports"><b>Supports:</b> LM, NTLM, md2, md4, md5, md5(md5_hex), md5-half, sha1, sha224,
     sha256, sha384, sha512, ripeMD160, whirlpool, MySQL 4.1+ (sha1(sha1_bin)), QubesV3.1BackupDefaults</p>

  <div class="results-region">
__STRIP__
    <table class="results">
      <tr><th>Hash</th><th>Type</th><th>Result</th></tr>
      <tr class="suc"><td>5d41402abc4b2a76b9719d911017c592</td><td>md5</td><td>hello</td></tr>
      <tr class="suc"><td>aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d</td><td>sha1</td><td>hello</td></tr>
      <tr class="part"><td><span class="matched">e52cac67419a9a22</span>4a3b108f3fa6cb6d</td><td>LM</td><td>password</td></tr>
      <tr class="more"><td>e52cac67419a9a220000000000000000</td><td>&nbsp;</td><td>27,356 more not shown (of 27,376 total).</td></tr>
      <tr class="suc"><td>9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043</td><td>sha512</td><td>hello</td></tr>
      <tr class="fail"><td>0000000000000000000000000000000000000000</td><td>Unknown</td><td>Not found.</td></tr>
      <tr class="fail"><td>not-a-hex-hash</td><td>Unknown</td><td>Unrecognized hash format.</td></tr>
    </table>
    <p class="legend"><b>Colour codes:</b> green &middot; exact match &nbsp;&nbsp; yellow &middot; prefix match,
       the hash column shows what that word really hashes to with the <span class="matched">part yours matched</span>
       highlighted &nbsp;&nbsp; red &middot; not found</p>
  </div>

  <div class="download"><a href="#">Download CrackStation's Wordlist</a></div>

  <div class="prose">
    <h2>How CrackStation Works</h2>
    <p>CrackStation uses massive pre-computed lookup tables to crack password hashes. These tables store a
       mapping between the hash of a password and the correct password for that hash. The hash values are
       indexed so that it is possible to quickly search the database for a given hash.</p>
    <p>This only works for unsalted hashes. For information on password hashing systems that are not
       vulnerable to pre-computed lookup tables, see our <a href="#">hashing security page</a>.</p>
  </div>
</div></main>

<footer><div class="wrap">
  <span class="hits">Page Hits: <b>4,201,337</b></span>
  <span class="hits">Unique Hits: <b>1,204,881</b></span>
  <span class="footlinks">
    <a rel="license" href="http://creativecommons.org/licenses/by-sa/3.0/deed.en_US"><img src="../../static/images/cc-by-sa.png" alt="Creative Commons License"></a>
    <a href="https://defuse.ca/">Defuse Security</a>
    <a href="https://z.cash/">Zcash</a>
    <a href="https://defuse.ca/pastebin.htm">Secure Pastebin</a>
    <a href="https://github.com/defuse/crackstation-rust">Source Code</a>
  </span>
</div></footer>

<div class="tag">__N__ &middot; __TAG__</div>
</body></html>
'''

LIGHT = """  --bg:#f4f4f2; --panel:#ffffff; --ink:#111114; --ink-dim:#5c5c66;
  --rule:#d6d6d2; --rule-strong:#111114; --accent:#1a4fd6; --grid:#111114;
  --gutter-ink:#a8a8a4; --strip-bg:#ebebe8; --field:#fbfbfa;
  --thbg:#111114; --think:#ffffff; --footbg:#ebebe8;"""
DARK = """  --bg:#0b0b0e; --panel:#141419; --ink:#e9e9ee; --ink-dim:#83838f;
  --rule:#26262e; --rule-strong:#3a3a45; --accent:#7aa2ff; --grid:#111114;
  --gutter-ink:#4a4a56; --strip-bg:#1b1b22; --field:#0e0e12;
  --thbg:#1b1b22; --think:#c9c9d2; --footbg:#101014;"""

GUTTER_CSS = """.gutter{flex:0 0 44px;padding:14px 0;text-align:right;color:var(--gutter-ink);
        font:__TASIZE__/1.7 var(--mono);background:var(--field);
        border-right:1px solid var(--rule);user-select:none}
.gutter span{display:block;padding-right:10px}"""
GUTTER_HTML = """      <div class="gutter"><span>1</span><span>2</span><span>3</span><span>4</span><span>5</span><span>6</span></div>"""

STRIP = """    <div class="strip">
      <span><b>6</b> hashes</span><span><b>3</b> cracked</span><span><b>1</b> partial</span>
      <span><b>1</b> not found</span><span><b>1</b> unreadable</span><span><b>27,376</b> candidates examined</span>
    </div>
"""

VARIANTS = [
    ("1-light.html",         "1", "light instrument", "LIGHT",         LIGHT, True,  True,  "15px", "210px", "13px", "7px",  "18px"),
    ("2-dark.html",          "2", "dark console",     "DARK CONSOLE",  DARK,  True,  True,  "15px", "210px", "13px", "7px",  "18px"),
    ("3-results-first.html", "3", "results first",    "RESULTS FIRST", DARK,  False, False, "14px", "150px", "15px", "9px",  "18px"),
]

for fn, n, name, tag, pal, gutter, strip, tasize, tamin, rsize, rpad, rtop in VARIANTS:
    s = TPL
    s = s.replace("__PALETTE__", pal).replace("__N__", n).replace("__NAME__", name).replace("__TAG__", tag)
    s = s.replace("__GUTTERCSS__", GUTTER_CSS if gutter else "")
    s = s.replace("__GUTTERHTML__", GUTTER_HTML if gutter else "")
    s = s.replace("__STRIP__", STRIP if strip else "")
    s = s.replace("__TASIZE__", tasize).replace("__TAMIN__", tamin)
    s = s.replace("__RSIZE__", rsize).replace("__RPAD__", rpad).replace("__RTOP__", rtop)
    open(fn, "w").write(s)
    print("wrote", fn)
