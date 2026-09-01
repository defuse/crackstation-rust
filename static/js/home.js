// Enables the submit button once the reCAPTCHA checkbox is solved, and disables it
// again when the token expires. Google's api.js calls these by name, wired up through
// the data-callback / data-expired-callback attributes on the widget.
//
// This lives in a file rather than inline in home.html so the Content-Security-Policy
// can allow scripts with `script-src 'self'` and no `'unsafe-inline'`. Inlining it again
// would silently stop it running: the button would never enable and nobody could submit
// a hash.
function onRecaptchaChecked() {
    document.getElementById("submitbutton").disabled = false;
}

function onRecaptchaExpired() {
    document.getElementById("submitbutton").disabled = true;
}
