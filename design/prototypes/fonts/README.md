Candidate typefaces for the page-content comparison in `7-fonts.html`.

All are open-licence and packaged by Debian, so they can be vendored into the
repository rather than fetched from a third party at runtime — which matters here,
because the Content-Security-Policy is `font-src 'self'` and pointing at Google Fonts
would mean loosening it for two more origins.

| family | licence | Debian package |
| --- | --- | --- |
| Source Sans 3 | OFL 1.1 | fonts-adobe-sourcesans3 |
| Inter | OFL 1.1 | fonts-inter |
| Atkinson Hyperlegible | OFL 1.1 | fonts-atkinson-hyperlegible-ttf |
| Charis SIL | OFL 1.1 | fonts-sil-charis |
| Caladea | OFL 1.1 | fonts-crosextra-caladea |
| EB Garamond | OFL 1.1 | fonts-ebgaramond |

These are the raw .otf/.ttf files, 4.2 MB in total, which is fine for a local
comparison and far too much to ship. Whatever wins gets subsetted to Latin and
converted to woff2 before it goes near the site — that typically lands a text face
around 20–40 KB per weight. Two weights of one sans and one serif should come to well
under 150 KB total.

Deleted along with the rest of design/prototypes before this branch merges.
