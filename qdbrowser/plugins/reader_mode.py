"""Reader mode — injects a JS readability extractor and renders the
extracted article in a clean overlay. JS-heavy by design (per user
guidance: lean on JS when Python would be awkward).
"""

from qdbrowser.plugin import CommandProvider


READER_JS = r"""
(function(){
  if(window.__qdbReaderToggleHandled){
    // Already toggled — restore.
    document.body.innerHTML = window.__qdbReaderOriginal;
    document.body.style.cssText = window.__qdbReaderBodyStyle || '';
    window.__qdbReaderToggleHandled = false;
    return {ok:true, mode:'off'};
  }
  // Naive readability: collect <article>, <main>, longest <div> by text.
  function pickRoot(){
    let best = null, bestScore = 0;
    const candidates = Array.from(document.querySelectorAll(
      'article, main, [role=main], .article, .post, .entry-content'
    ));
    candidates.forEach(el=>{
      const score = (el.innerText||'').length;
      if(score>bestScore){bestScore=score;best=el;}
    });
    if(best && bestScore > 400) return best;
    // Fallback: pick the div with the most text.
    const divs = Array.from(document.querySelectorAll('div, section'));
    divs.forEach(el=>{
      const score = (el.innerText||'').length;
      if(score>bestScore){bestScore=score;best=el;}
    });
    return best || document.body;
  }
  const root = pickRoot();
  const title = (document.querySelector('h1') && document.querySelector('h1').innerText)
                || document.title || '';
  const html = root.innerHTML;
  window.__qdbReaderOriginal = document.body.innerHTML;
  window.__qdbReaderBodyStyle = document.body.style.cssText;
  document.body.style.cssText =
    'background:#f4ecd8;color:#222;font-family:Georgia,serif;'
    +'max-width:720px;margin:40px auto;padding:24px;line-height:1.6;'
    +'font-size:18px;';
  document.body.innerHTML = '<h1>'+ title.replace(/</g,'&lt;') +'</h1>' + html;
  window.__qdbReaderToggleHandled = true;
  return {ok:true, mode:'on', title: title};
})()
"""


class ReaderModePlugin(CommandProvider):
    name = "reader_mode"
    description = "Toggle a readability-style reading view."
    capabilities = ["reader_mode", "command_provider"]

    def __init__(self):
        super().__init__()
        self._window = None

    def activate(self, window):
        self._window = window

    def toggle(self, webview):
        if webview is None:
            return
        webview.view.page().runJavaScript(READER_JS)

    def get_commands(self, window):
        return [("Toggle reader mode",
                 lambda: self.toggle(window._active_webview))]
