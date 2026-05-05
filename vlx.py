import sys, io, re, time, json, threading, keyboard, base64, glob, os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stdout.reconfigure(line_buffering=True)
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import StaleElementReferenceException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
import google.generativeai as genai
from difflib import SequenceMatcher

URL           = "https://e.khaothi.online/"
ANSWERS_DIR   = "."
BLOCK_PATTERN = "khaothi.online/delivery/exam/save-event"
API_KEYS      = []

AI_TIMEOUT_SEC = 60

SYSTEM_PROMPT = """YOU ARE A VIETNAMESE AND ENGLISH ACADEMIC EXAM EXPERT with perfect knowledge of all high school and university subjects: Mathematics, Physics, Chemistry, Biology, Literature, History, Geography, English, Civic Education, and all related disciplines.

YOUR SOLE PURPOSE: Identify the correct answer for each question with 100% precision.

CRITICAL OUTPUT RULES — Every rule is mandatory. Breaking any rule = total failure:

RULE 1 — FORMAT ONLY: Output ONLY the required format below. Nothing else ever.
RULE 2 — NO EXTRAS: Never write explanations, reasoning, labels, prefixes, suffixes, or markdown.
RULE 3 — NO LABELS: Never write "Answer:", "Đáp án:", "Câu trả lời:", "Kết quả:", "Giải:", or any label.
RULE 4 — LETTERS NOT TEXT: For choice questions, output ONLY the option letter. NEVER copy option text.
RULE 5 — CONTEXT LOCK: When [Context] is given, reason ONLY from that context.
RULE 6 — NO EMPTY: Never return empty string. Always output in exact format.
RULE 7 — NO MARKDOWN: Never use code blocks, **, __, or any markdown.

OUTPUT FORMAT — Apply EXACTLY based on question type:

[SINGLE CHOICE] — ALWAYS exactly ONE correct answer. One uppercase letter only.
  Correct: B
  Wrong: "Answer: B" | "B. Option text" | "b" | "The answer is B"
  Example: Q="Nguyen Du wrote? A.Truyen Kieu B.Nam Quoc C.Binh Ngo D.Chinh Phu" → A

[FILL IN THE BLANK — NUMBER] — Question requires filling a numeric value.
  Output: ONLY the number. No unit. No word. No explanation.
  Decimal separator MUST be comma, not period. Example: 1.5 → 1,5
  Correct: 9,8
  Wrong: "9.8 m/s2" | "9,8 m/s²" | "gia tốc là 9,8" | "9,8 m/s^2"
  Example: Q="Gia tốc rơi tự do bằng ___" → 9,8

[FILL IN THE BLANK — TEXT] — Question requires filling a word or phrase.
  Output: ONLY the exact word or phrase. No quotes, no extra punctuation.
  Correct: Paris
  Wrong: "The answer is Paris" | "Paris." | "'Paris'"
  Example: Q="Thủ đô nước Pháp là ___" → Paris

[TRUE/FALSE] — Each sub-statement evaluated independently.
  Output: ALL statements as LETTER.Đ or LETTER.S comma-separated. No spaces.
  Đ = True/Correct. S = False/Incorrect. Letters UPPERCASE.
  Include EVERY statement — never omit any.
  Correct: A.Đ,B.S,C.Đ,D.S
  Wrong: "A đúng, B sai" | "A.True,B.False" | "A.Đ B.S"
  Example: Q="a)2+2=4 b)Paris ở UK c)HTML là ngôn ngữ lập trình" → A.Đ,B.S,C.S

IMAGE QUESTIONS — When an image is provided:
- Read ALL text, symbols, formulas, numbers, diagrams in the image.
- For math/physics/chemistry: interpret every symbol carefully (integrals, roots, powers, Greek letters, etc.)
- Apply the same output format rules above.
- For fill-in-blank from image: if answer is numeric, use comma as decimal separator.

PROCESSING ORDER:
1. Identify question type (single-choice / fill-number / fill-text / true-false)
2. If image: read image completely first
3. Determine correct answer
4. Output ONLY in the exact required format — nothing more"""

BATCH_PROMPT = """YOU ARE A VIETNAMESE AND ENGLISH ACADEMIC EXAM EXPERT. Answer ALL questions in the JSON array.

CRITICAL RULES — All mandatory, no exceptions:

RULE 1 — JSON ONLY: Return ONLY a valid JSON array. Zero markdown, zero explanation, zero extra text.
RULE 2 — DO NOT MODIFY: Keep "sid", "type", "text", "options", "passage" fields EXACTLY unchanged.
RULE 3 — FILL CORRECT ONLY: Only write to the "correct" field.
RULE 4 — ANSWER ALL: Every item MUST have a non-empty "correct". Never skip.
RULE 5 — NO MARKDOWN: Do NOT wrap output in ```json``` or any code block.
RULE 6 — SINGLE ANSWER: Questions always have exactly ONE correct answer.

CORRECT FIELD FORMAT by "type":

  "type": "single" — ONE uppercase letter only. Always exactly one.
    Correct: "B"
    Wrong: "Answer: B" | "B. text" | "b" | "A,B"

  "type": "table" — ALL sub-statements as LETTER.Đ or LETTER.S, comma-separated, no spaces.
    Correct: "A.Đ,B.S,C.Đ,D.S"
    Wrong: "A đúng B sai" | "A.True,B.False" | "A.Đ B.S"
    Use Đ=True S=False. Include EVERY statement.

  "type": "fill" — Numeric value only. No unit. Comma as decimal separator.
    Correct: "9,8"
    Wrong: "9.8" | "9,8 m/s²" | "gia tốc 9,8"
    If answer is text (not number): exact word/phrase only, no extras.

IF IMAGE is included alongside this JSON:
- Read ALL symbols, formulas, and text in the image carefully.
- Apply same format rules above.
- Fill numeric answers with comma decimal separator.

OUTPUT STRUCTURE — Return this exact structure:
[
  {"sid": "...", "type": "...", "text": "...", "options": "...", "passage": "...", "correct": "YOUR_ANSWER"},
  ...
]

INPUT JSON TO ANSWER:
"""

opts_c = webdriver.ChromeOptions()
opts_c.add_experimental_option('excludeSwitches', ['enable-logging', 'enable-automation'])
opts_c.add_experimental_option('useAutomationExtension', False)
opts_c.add_argument('--disable-blink-features=AutomationControlled')
opts_c.add_argument('--no-sandbox')
opts_c.add_argument('--disable-dev-shm-usage')

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts_c)
driver.maximize_window()
driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument',
    {'source': "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"})
driver.execute_cdp_cmd('Network.enable', {})

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'log')
os.makedirs(LOG_DIR, exist_ok=True)
_log_file = open(
    os.path.join(LOG_DIR, f"log_{time.strftime('%Y%m%d_%H%M%S')}.txt"),
    'w', encoding='utf-8', buffering=1
)
_log_lock = threading.Lock()

def log(tag, *parts):
    line = f"[{time.strftime('%H:%M:%S')}] [{tag}] " + ' '.join(str(p) for p in parts)
    with _log_lock:
        _log_file.write(line + '\n')
    print(line)

def _start_network_log():
    req_map = {}
    def on_request(params):
        rid = params.get('requestId','')
        req = params.get('request',{})
        req_map[rid] = req
        log('NET-REQ', req.get('method',''), req.get('url','')[:200],
            'headers='+json.dumps(req.get('headers',{}), ensure_ascii=False)[:300],
            'body='+str(req.get('postData',''))[:500])
    def on_response(params):
        rid  = params.get('requestId','')
        resp = params.get('response',{})
        log('NET-RSP', resp.get('status',''), resp.get('url','')[:200],
            'headers='+json.dumps(resp.get('headers',{}), ensure_ascii=False)[:300])
        try:
            body = driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': rid})
            log('NET-BODY', rid[:12], str(body.get('body',''))[:2000])
        except: pass
    driver.add_cdp_listener('Network.requestWillBeSent', on_request)
    driver.add_cdp_listener('Network.responseReceived', on_response)

try:
    _start_network_log()
except Exception as _e:
    log('LOG', f'Network listener not available: {_e}')

_logged_qids = set()

def log_question_html(scope, sid):
    if sid in _logged_qids: return
    _logged_qids.add(sid)
    try:
        html = driver.execute_script("return arguments[0].outerHTML", scope)
        log('Q-HTML', sid, html)
    except: pass

system_on = True
block_on  = False
dot_on    = True

def cdp(expr):
    try: driver.execute_cdp_cmd('Runtime.evaluate',
            {'expression': expr, 'userGesture': True, 'awaitPromise': False})
    except: pass

def js(s, *a):
    try: return driver.execute_script(s, *a)
    except: return None

def apply_block():
    urls = [f'*{BLOCK_PATTERN}*'] if (system_on and block_on) else []
    try: driver.execute_cdp_cmd('Network.setBlockedURLs', {'urls': urls})
    except: pass

apply_block()

DOT_HIDE   = "var d=document.getElementById('__d');if(d)d.style.display='none'"
DOT_CREATE = (
    "var d=document.getElementById('__d');"
    "if(!d){{"
    "d=document.createElement('div');d.id='__d';"
    "d.style.cssText='position:fixed;bottom:8px;right:8px;width:6px;height:6px;"
    "border-radius:50%;z-index:2147483647;pointer-events:none';"
    "document.documentElement.appendChild(d)"
    "}}"
    "d.style.display='block';d.style.background='{c}'"
)

def update_dot():
    if not system_on or not dot_on: cdp(DOT_HIDE); return
    cdp(DOT_CREATE.format(c='#00e676' if block_on else '#ff1744'))

HINT_JS = r"""
(function(){
if(window.__H) return; window.__H=true; window.__M={};
function ct(s){return s.replace(/\s+$/,'')}
function sd(s){return ct(s).replace(/[.,]+$/,'')}
function nt(s){return s.replace(/[^a-zA-Z0-9\u00C0-\u024F\u1E00-\u1EFF]/g,'').toLowerCase()}
function ns(a,b){
    var na=nt(a),nb=nt(b);if(!na||!nb)return 0;
    var l1=na.length,l2=nb.length,dp=[],i,j;
    for(i=0;i<=l1;i++){dp[i]=[];for(j=0;j<=l2;j++){
        if(!i)dp[i][j]=j;else if(!j)dp[i][j]=i;
        else if(na[i-1]===nb[j-1])dp[i][j]=dp[i-1][j-1];
        else dp[i][j]=1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);
    }}
    var m=Math.max(l1,l2);return m?1-dp[l1][l2]/m:1;
}
function show(s){
    var key=s.getAttribute('data-hk');if(!key||!window.__M[key])return;
    var cs=window.__M[key];
    var els=s.querySelectorAll('.answer-item');if(!els.length)els=s.querySelectorAll('.match_table_preview_left_colum_item');
    els.forEach(function(el){
        var cl=ct(el.textContent),b=sd(cl);
        if(cs.some(function(c){return ns(b,c)>=0.85})){
            if(!el.getAttribute('data-o'))el.setAttribute('data-o',el.textContent);
            el.textContent=cl.match(/\.+$/)?b+',':cl+'.';
        }
    });
}
function hide(s){
    var els=s.querySelectorAll('.answer-item');if(!els.length)els=s.querySelectorAll('.match_table_preview_left_colum_item');
    els.forEach(function(el){var o=el.getAttribute('data-o');if(o!==null){el.textContent=o;el.removeAttribute('data-o')}});
}
function scope(el){return el.closest('[id^="ItemPreview__question-"]')||el.closest('.ItemPreview__container')}
function attach(el){
    if(el.__hb)return;el.__hb=true;
    el.style.cursor='pointer';el.style.userSelect=el.style.webkitUserSelect='none';
    var hold=false,s=scope(el);if(!s)return;
    el.addEventListener('mousedown',function(e){e.preventDefault();hold=true;show(s)});
    el.addEventListener('mouseup',function(){hold=false;hide(s)});
    el.addEventListener('mouseleave',function(){if(hold){hold=false;hide(s)}});
    el.addEventListener('touchstart',function(e){e.preventDefault();hold=true;show(s)},{passive:false});
    el.addEventListener('touchend',function(){hold=false;hide(s)});
    el.addEventListener('touchcancel',function(){hold=false;hide(s)});
}
window.__attach=function(){document.querySelectorAll('.question-number').forEach(attach)};
window.__attach();
})();
"""

CLEAN_JS = """
(function(){
    var d=document.getElementById('__d');if(d)d.remove();
    window.__H=false;window.__M={};
    document.querySelectorAll('[data-o]').forEach(function(el){el.textContent=el.getAttribute('data-o');el.removeAttribute('data-o')});
    document.querySelectorAll('.question-number').forEach(function(el){
        el.__hb=false;el.style.cursor=el.style.userSelect=el.style.webkitUserSelect='';
        var f=el.cloneNode(true);el.parentNode.replaceChild(f,el);
    });
    document.querySelectorAll('.ctq-input').forEach(function(el){
        el._b=false;var f=el.cloneNode(true);el.parentNode.replaceChild(f,el);
    });
})();
"""

_ps_id = None
def register_persistent():
    global _ps_id
    try:
        r = driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': HINT_JS})
        _ps_id = r.get('identifier')
    except: pass

def inject(): cdp(HINT_JS)
def clean():  cdp(CLEAN_JS)

def toggle_system():
    global system_on
    system_on = not system_on
    apply_block()
    if system_on: inject(); update_dot()
    else: clean()

def toggle_block():
    global block_on
    block_on = not block_on
    apply_block(); update_dot()

def toggle_dot():
    global dot_on
    dot_on = not dot_on
    update_dot()

def make_hold_handler(on_short, on_long, hold_sec=1.0):
    state = {'down': False, 'timer': None}
    def on_down(e):
        if state['down']: return
        state['down'] = True
        t = threading.Timer(hold_sec, on_long)
        state['timer'] = t; t.start()
    def on_up(e):
        state['down'] = False
        t = state['timer']
        if t:
            if t.is_alive(): t.cancel(); on_short()
            state['timer'] = None
    return on_down, on_up

bt_down, bt_up = make_hold_handler(toggle_block, toggle_dot)
ct_down, ct_up = make_hold_handler(lambda: None, toggle_system)
keyboard.on_press_key('`',    bt_down); keyboard.on_release_key('`',  bt_up)
keyboard.on_press_key('ctrl', ct_down); keyboard.on_release_key('ctrl', ct_up)
threading.Thread(target=keyboard.wait, daemon=True).start()

register_persistent()
driver.get(URL)
seen_ids, seen_texts = set(), set()

_PLC      = re.compile(r'^\([\w\s]+\)$')
_NORM_RE  = re.compile(r'[^a-zA-Z0-9\u00C0-\u024F\u1E00-\u1EFF\s]')
_ESSAY_RE = re.compile(r'\d+[.,]?\d*\s*điểm', re.IGNORECASE)
MIN_ALPHA = 5

_STOPWORDS = {
    'cho','và','là','hai','các','một','những','có','trong','của','với',
    'được','thì','nếu','khi','sau','đây','nào','đó','đều','trên','dưới',
    'bao','nhiêu','gọi','biết','tính','câu','phương','hỏi','chọn','theo',
    'biểu','dạng','đẳng','the','of','is','are','following','which','that',
    'this','what','how','who','when','where','why','an','in','on','at',
    'to','for','with','from','by','not','or','and','but','if','than',
    'very','much','many','any','all','both','each','every','some',
}

def norm(s):
    return _NORM_RE.sub('', str(s)).lower().strip()

def norm_key(s):
    return re.sub(r'\s+', ' ', _NORM_RE.sub(' ', str(s))).lower().strip()

def is_essay(q_text):
    return bool(_ESSAY_RE.search(q_text))

def _tokenize(s):
    return set(w for w in norm_key(s).split() if len(w) >= 2)

def _meaningful(tokens):
    return {t for t in tokens if t not in _STOPWORDS and len(t) >= 3}

def _sim(q_a, opts_a, q_b, opts_b):
    sq_a, sq_b = _tokenize(q_a), _tokenize(q_b)
    nqa, nqb   = norm_key(q_a), norm_key(q_b)
    rat_q = SequenceMatcher(None, nqa, nqb).ratio()
    jac_q = len(sq_a & sq_b) / len(sq_a | sq_b) if sq_a | sq_b else 0.0
    sim_q = 0.5 * rat_q + 0.5 * jac_q

    so_a, so_b = _tokenize(' '.join(opts_a)), _tokenize(' '.join(opts_b))
    noa, nob   = norm_key(' '.join(opts_a)), norm_key(' '.join(opts_b))
    rat_o = SequenceMatcher(None, noa, nob).ratio()
    jac_o = len(so_a & so_b) / len(so_a | so_b) if so_a | so_b else 0.0
    sim_o = 0.5 * rat_o + 0.5 * jac_o

    only_a, only_b = sq_a - sq_b, sq_b - sq_a
    ma, mb = _meaningful(only_a), _meaningful(only_b)
    if ma and mb:
        return 0.0
    if ma or mb:
        all_m   = _meaningful(sq_a | sq_b)
        penalty = (len(ma) + len(mb)) / max(len(all_m), 1) * 0.70
        sim_q   = max(0.0, sim_q - penalty)

    return 0.65 * sim_q + 0.35 * sim_o

def find_best(q_text, choices, answers):
    """Returns (entry, need_ai). 0 false positives by design."""
    nq = norm_key(q_text).replace(' ', '')
    if len(nq) < MIN_ALPHA:
        if not choices: return None, True
        best, score = None, 0.0
        for e in answers:
            s = _sim('', choices, '', e.get('opts', []))
            if s > score: score, best = s, e
        return (best, False) if score >= 0.88 else (None, True)
    best, score = None, 0.0
    for e in answers:
        s = _sim(q_text, choices, e.get('q', ''), e.get('opts', []))
        if s > score: score, best = s, e
    thr = 0.85 if len(nq) < 25 else 0.75
    return (best, False) if score >= thr else (None, True)

def _parse_qui(e):
    if not text or not correct: return None
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    opts, opt_idx = {}, None
    for i, l in enumerate(lines):
        m = re.match(r'^([A-Z])[.)]\s*(.+)$', l)
        if m:
            if opt_idx is None: opt_idx = i
            opts[m.group(1)] = m.group(2).strip()
    if etype == 'mc':
        if correct.upper() not in opts: return None
        q_lines = [l for l in lines[:opt_idx or 0] if not _PLC.match(l)]
        q = '\n'.join(q_lines) if q_lines else '\n'.join(f"{k}. {v}" for k, v in opts.items())
        return {'q': q, 'a': opts[correct.upper()], 'opts': list(opts.values())}
    if etype == 'tf':
        stmts, ctx = {}, []
        for l in lines:
            m = re.match(r'^([a-zA-Z])[.)]\s*(.+)$', l)
            if m: stmts[m.group(1).upper()] = m.group(2).strip()
            elif not stmts: ctx.append(l)
        true_keys = {m.group(1) for p in correct.split(',')
                     if (m := re.match(r'^([A-Z])\.(Đ|đ)$', p.strip()))}
        if not stmts: return None
        q = '\n'.join(ctx) if ctx else '\n'.join(f"{k}. {v}" for k, v in stmts.items())
        a = [stmts[k] for k in sorted(stmts) if k in true_keys]
        return {'q': q, 'a': a, 'opts': list(stmts.values())} if a else None
    if etype == 'fill':
        blanks = re.findall(r'__(.+?)__', text)
        if not blanks: return None
        a = [b.split('|')[0].strip() for b in blanks]
        q_clean = re.sub(r'__.*?__', '___', text)
        return {'q': q_clean, 'a': a[0] if len(a) == 1 else a, 'opts': []}
    return None

def _load_file(path):
    try:
        with open(path, encoding='utf-8') as f: data = json.load(f)
        if not data or not isinstance(data, list): return []
        if 'type' in data[0] and 'text' in data[0]:
            return [r for e in data if (r := _parse_qui(e))]
        return [e for e in data if 'q' in e and 'a' in e]
    except: return []

def load_answers():
    seen, result = set(), []
    files = (glob.glob(os.path.join(ANSWERS_DIR, 'answers.json')) +
             glob.glob(os.path.join(ANSWERS_DIR, '*_answers.json')))
    for f in files:
        for e in _load_file(f):
            k = norm_key(e['q'])
            if k and k not in seen:
                seen.add(k); result.append(e)
    return result

_key_idx      = 0
_chat_history = []
gemini_model  = None
chat_session  = None
gemini_cache  = {}
_ai_lock      = threading.Lock()
_ai_busy      = False
_ai_pending   = {}
_ai_fired     = set()

def _build_model():
    genai.configure(api_key=API_KEYS[_key_idx])
    return genai.GenerativeModel('gemini-2.5-flash-lite', system_instruction=SYSTEM_PROMPT)

def init_gemini():
    global gemini_model, chat_session, _key_idx
    if not API_KEYS: print("[Gemini] ✗ No API keys"); return
    _key_idx = 0
    gemini_model = _build_model()
    chat_session = gemini_model.start_chat(history=[])
    print(f"[Gemini] ✓ Key #0 ready")

def _rotate_key():
    global _key_idx, gemini_model, chat_session
    nxt = (_key_idx + 1) % len(API_KEYS)
    if nxt == _key_idx: print("[Gemini] ✗ All keys exhausted"); return False
    _key_idx     = nxt
    gemini_model = _build_model()
    chat_session = gemini_model.start_chat(history=list(_chat_history))
    print(f"[Gemini] ⟳ Key #{_key_idx} — restored {len(_chat_history)} turns")
    return True

def _call(prompt_parts):
    global _chat_history
    for attempt in range(len(API_KEYS)):
        try:
            with ThreadPoolExecutor(max_workers=1) as ex:
                fut  = ex.submit(chat_session.send_message, prompt_parts)
                resp = fut.result(timeout=AI_TIMEOUT_SEC)
            _chat_history = list(chat_session.history)
            return resp.text or ''
        except FuturesTimeout:
            print(f"[Gemini] ⏱ Key #{_key_idx} timeout ({AI_TIMEOUT_SEC}s) — rotating")
            if not _rotate_key(): return ''
        except Exception as e:
            err = str(e).lower()
            if any(k in err for k in ('quota', 'exhausted', '429', 'resource_exhausted')):
                if not _rotate_key(): return ''
            else:
                print(f"[Gemini] ✗ {e}"); return ''
    return ''

MATH_SEL = 'img,svg,mjx-container,.MathJax,.MathJax_Display,.katex,[class*="math"],[class*="formula"]'

def cdp_shot(el):
    r = js("var b=arguments[0].getBoundingClientRect();"
           "return{x:b.x+scrollX,y:b.y+scrollY,w:b.width,h:b.height}", el)
    if not r: return None
    d = driver.execute_cdp_cmd('Page.captureScreenshot', {
        'format': 'png', 'fromSurface': False, 'captureBeyondViewport': True,
        'clip': {'x': r['x'], 'y': r['y'], 'width': r['w'], 'height': r['h'], 'scale': 1}
    })
    return base64.b64decode(d['data'])

def qtype(scope):
    cls = scope.get_attribute('class') or ''
    if 'type_14' in cls: return 'table'
    if 'type_4'  in cls: return 'fill'
    return 'single'

def get_choices(scope, qt):
    sel = '.answer-item' if qt in ('single', 'fill') else '.match_table_preview_left_colum_item'
    return [e.text.strip() for e in scope.find_elements(By.CSS_SELECTOR, sel) if e.text.strip()]

def has_visual(el):
    return bool(el.find_elements(By.CSS_SELECTOR, MATH_SEL))

def build_text(el):
    raw  = el.text.strip()
    math = js("""
        var nodes=arguments[0].querySelectorAll('[aria-label],[data-latex],[alttext],[title]');
        return Array.from(nodes).map(function(n){
            return n.getAttribute('aria-label')||n.getAttribute('data-latex')||
                   n.getAttribute('alttext')||n.getAttribute('title')||'';
        }).filter(Boolean).join(' | ');
    """, el) or ''
    return f"{raw}\n[Math: {math.strip()}]" if math.strip() else raw

def _snapshot(body, scope, passage):
    qt       = qtype(scope)
    ch       = get_choices(scope, qt)
    q_text   = build_text(body)
    img_data = cdp_shot(scope)
    return {'qt': qt, 'ch': ch, 'q_text': q_text, 'passage': passage,
            'use_img': True, 'img_data': img_data}

def _tp(q, ch, qt, passage=''):
    ctx  = f"[Context]\n{passage}\n\n" if passage else ''
    opts = '\n'.join(f"{chr(65+i)}. {c}" for i, c in enumerate(ch))
    if qt == 'table':
        items = '\n'.join(f"{chr(65+i)}. {c}" for i, c in enumerate(ch))
        return f"{ctx}[TRUE/FALSE] {q}\n\n[Statements]\n{items}\n\nOUTPUT — A.Đ,B.S,C.Đ,D.S only."
    if qt == 'fill':
        return (f"{ctx}[FILL IN THE BLANK] {q}\n\n"
                f"OUTPUT — number only, no unit, comma as decimal separator (e.g. 1,5 not 1.5). "
                f"If text answer: exact word/phrase only.")
    return f"{ctx}[SINGLE CHOICE]\n{q}\n\n{opts}\n\nOUTPUT — single uppercase letter only e.g. B."

def _ip(ch, qt, passage=''):
    ctx  = f"[Context]\n{passage}\n\n" if passage else ''
    opts = '\n'.join(f"{chr(65+i)}. {c}" for i, c in enumerate(ch))
    hint = " Read ALL math/physics/chemistry symbols carefully."
    if qt == 'table':
        items = '\n'.join(f"{chr(65+i)}. {c}" for i, c in enumerate(ch))
        return f"{ctx}[TRUE/FALSE in image]{hint}\n[Statements]\n{items}\n\nOUTPUT — A.Đ,B.S,C.Đ,D.S only."
    if qt == 'fill':
        return (f"{ctx}[FILL IN THE BLANK in image]{hint}\n"
                f"OUTPUT — number only, no unit, comma as decimal separator (e.g. 1,5 not 1.5). "
                f"If text answer: exact word/phrase only.")
    return f"{ctx}[SINGLE CHOICE in image]{hint}\n{opts}\n\nOUTPUT — single uppercase letter only e.g. B."

def parse_resp(raw, qt, ch=None):
    raw = raw.strip()
    if qt == 'fill':
        val = re.sub(r'\.(\d)', r',\1', raw)
        m   = re.match(r'^-?\d+[,.]?\d*$', val.replace(',', '.').replace(',', ','))
        return [val] if val else [raw]
    if qt == 'table':
        result = []
        for p in re.split(r'[,\n]+', raw):
            m = re.match(r'^\s*([A-Za-z])\.(Đ|đ)\s*$', p.strip())
            if m and ch:
                idx = ord(m.group(1).upper()) - 65
                if 0 <= idx < len(ch): result.append(ch[idx])
        return result or None
    clean = re.sub(r'[^A-Za-z]', '', raw)
    letter = clean[0].upper() if clean else ''
    if not letter and ch:
        found = re.findall(r'\b([A-Z])\b', raw.upper())
        letter = found[0] if found else ''
    if not letter or not ch: return None
    idx = ord(letter) - 65
    return [ch[idx]] if 0 <= idx < len(ch) else None

def _clean_json(t):
    t = re.sub(r'```\w*|```', '', t).strip()
    s = t.find('[')
    if s == -1: return t
    cnt = 0
    for i in range(s, len(t)):
        if t[i] == '[': cnt += 1
        elif t[i] == ']': cnt -= 1
        if cnt == 0: return t[s:i+1]
    return t

def _process_text_batch(batch):
    if not batch: return
    items = [{'sid': sid, 'type': s['qt'], 'text': s['q_text'],
               'options': '\n'.join(f"{chr(65+i)}. {c}" for i, c in enumerate(s['ch'])),
               'passage': s['passage'], 'correct': ''}
             for sid, s in batch.items()]
    raw = _call(BATCH_PROMPT + json.dumps(items, ensure_ascii=False))
    log('AI-BATCH-REQ', json.dumps(items, ensure_ascii=False)[:1000])
    if not raw: return
    log('AI-BATCH-RSP', raw[:2000])
    try:
        results = json.loads(_clean_json(raw))
        for r in results:
            sid = r.get('sid', '')
            if not sid or sid not in batch: continue
            result = parse_resp(str(r.get('correct', '')), batch[sid]['qt'], batch[sid]['ch'])
            if result:
                gemini_cache[sid] = result
                print(f"[Gemini] 📝 {sid} → {result}")
    except Exception as e:
        print(f"[Gemini] ✗ batch: {e}")

def _process_img(sid, snap):
    if not snap['img_data']: return
    prompt = [{'mime_type': 'image/png', 'data': snap['img_data']},
              _ip(snap['ch'], snap['qt'], snap['passage'])]
    raw    = _call(prompt)
    log('AI-IMG-RSP', sid, raw[:500])
    result = parse_resp(raw, snap['qt'], snap['ch'])
    if result:
        gemini_cache[sid] = result
        print(f"[Gemini] 🖼 {sid} → {result}")

def _flush():
    global _ai_busy
    while True:
        with _ai_lock:
            if not _ai_pending:
                _ai_busy = False; return
            batch = dict(_ai_pending)
            _ai_pending.clear()
        _process_text_batch({s: d for s, d in batch.items() if not d['use_img']})
        for sid, snap in batch.items():
            if snap['use_img']: _process_img(sid, snap)

def queue_gemini(body, scope, passage=''):
    global _ai_busy
    if not chat_session: return
    sid = scope.get_attribute('id') or ''
    if not sid or sid in gemini_cache: return
    with _ai_lock:
        if sid in _ai_fired: return
        snap = _snapshot(body, scope, passage)
        _ai_fired.add(sid)
        _ai_pending[sid] = snap
        if not _ai_busy:
            _ai_busy = True
            threading.Thread(target=_flush, daemon=True).start()
    print(f"[Gemini] ⏳ queued {sid} (batch size: {len(_ai_pending)})")

def each_block(fn):
    if not system_on: return
    try:
        for c in driver.find_elements(By.CSS_SELECTOR, '.ItemPreview__container'):
            try:
                pe      = c.find_elements(By.CSS_SELECTOR, '.layout-pane-primary [id$="_body"]')
                passage = pe[0].text.strip() if pe else ''
                for b in c.find_elements(By.CSS_SELECTOR, '[id$="_body"]'):
                    try:
                        if b.find_elements(By.XPATH, './ancestor::div[contains(@class,"layout-pane-primary")]'):
                            continue
                        q_text = b.text.strip()
                        if not q_text or len(q_text) < 3: continue
                        if is_essay(q_text): continue
                        try: scope = b.find_element(By.XPATH, './ancestor::*[contains(@id,"ItemPreview__question-")][1]')
                        except: scope = c
                        sid = scope.get_attribute('id') or ''
                        qt  = qtype(scope)
                        ch  = get_choices(scope, qt)
                        if sid and sid in gemini_cache:
                            fn(b, scope, gemini_cache[sid]); continue

                        log_question_html(scope, sid or norm_key(q_text)[:20])
                        info, need_ai = find_best(q_text, ch, answers)
                        if info:
                            a = info.get('a', '')
                            fn(b, scope, [a] if isinstance(a, str) else list(a))
                        elif need_ai:
                            queue_gemini(b, scope, passage)
                    except StaleElementReferenceException: continue
            except StaleElementReferenceException: continue
    except: pass

def update_answer_map():
    def fn(b, scope, correct):
        sid = scope.get_attribute('id') or ''
        if sid:
            js("window.__M[arguments[0]]=arguments[1]", sid, correct)
            js("arguments[0].setAttribute('data-hk',arguments[1])", scope, sid)
    each_block(fn)

def setup_inputs():
    def fn(b, scope, correct):
        for inp in scope.find_elements(By.CSS_SELECTOR, '.ctq-input'):
            js("""
                var el=arguments[0],raw_val=arguments[1];
                var val = raw_val;
                var m = raw_val.match(/-?\\d+([.,]\\d+)?/);
                if(m) val = m[0].replace('.', ',');
                if(!el._b){el._b=true;
                    el.addEventListener('keydown',function(e){
                        if(e.key===' '||e.code==='Space'){
                            e.preventDefault();e.stopPropagation();
                            el.value=val;
                            el.dispatchEvent(new Event('input',{bubbles:true}));
                            el.dispatchEvent(new KeyboardEvent('keyup',{bubbles:true}));
                        }
                    },true);
                }
            """, inp, str(correct[0]))
    each_block(fn)

LABELS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def print_container(c):
    try:
        passage = ''
        pe = c.find_elements(By.CSS_SELECTOR, '.layout-pane-primary [id$="_body"]')
        if pe: passage = pe[0].text.strip(); print(f"Thông Tin: {passage}\n")
        for qb in c.find_elements(By.CSS_SELECTOR, '[id^="ItemPreview__question-"]'):
            try:
                body_el = qb.find_elements(By.CSS_SELECTOR, '[id$="_body"]')
                if not body_el: continue
                body = body_el[0].text.strip()
                if body == passage: continue
                print(f"Câu Hỏi: {body}")
                ch   = qb.find_elements(By.CSS_SELECTOR, '.answer-item')
                rows = qb.find_elements(By.CSS_SELECTOR, '.match_table_preview_left_colum_item')
                for i, t in enumerate(sorted([e.text.strip() for e in (ch or rows) if e.text.strip()])):
                    print(f"{LABELS[i]}. {t}")
                print()
            except StaleElementReferenceException: continue
    except: pass

answers     = load_answers()
last_reload = time.time()
init_gemini()
inject()
update_dot()

while True:
    try:
        if not driver.window_handles: sys.exit(0)
    except: sys.exit(0)
    
    now = time.time()
    if now - last_reload > 3:
        answers = load_answers(); last_reload = now
    try:
        for c in driver.find_elements(By.CSS_SELECTOR, '.ItemPreview__container'):
            try:
                qels = c.find_elements(By.CSS_SELECTOR, '[id^="ItemPreview__question-"]')
                if not qels: continue
                qid = qels[0].get_attribute('id').split('-')[-1]
                if qid in seen_ids: continue
                txt = norm(c.text)
                if txt in seen_texts: seen_ids.add(qid); continue
                seen_ids.add(qid); seen_texts.add(txt)
                print('─' * 60)
                print_container(c)
            except StaleElementReferenceException: continue
    except: pass
    update_answer_map()
    setup_inputs()
    if system_on: cdp("if(window.__attach)window.__attach()")
    update_dot()
    time.sleep(0.5)
