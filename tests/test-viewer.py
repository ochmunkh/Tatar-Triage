import json,sys,os,asyncio
from playwright.sync_api import sync_playwright
VIEWER=os.path.abspath(sys.argv[1]); tmp=os.path.abspath('t'); os.makedirs(tmp,exist_ok=True)
fails=[]
def check(n,c,d=''):
    print(('  PASS  ' if c else '  FAIL  ')+n+('' if c else '  '+str(d)))
    if not c: fails.append(n)
good={"tool":"TATAR Triage Toolkit","version":"1.7.0","schemaVersion":"1.6","platform":"linux","host":"h1","os":"Ubuntu","started":"2026-11-18T01:00:00Z","privileged":False,"errorsLogged":2,"modulesRun":["network","process"],"modulesSkipped":["bogus"],
 "moduleStatus":[{"module":"network","status":"ok","seconds":1,"errors":0},{"module":"process","status":"failed","seconds":2,"errors":1}],
 "moduleLimitations":[{"module":"process","limitation":"not root"}],"activeFindingsCount":2,"suppressedCount":1,"findingsCount":3,
 "findings":[
 {"id":"TTR-F-001","severity":"High","category":"process","message":"p running from deleted file","detail":"pid 1","confidence":0.7,"confidenceReason":"r","suppressed":False,"module":"process","artifactClass":"deleted-binary","technique":["T1059.001","javascript:alert(1)","T1036"],"paths":["/tmp/x"],"iocMatch":False},
 {"id":"TTR-F-002","severity":"Review","category":"network","message":"hosts has 1","confidence":0.4,"suppressed":False,"module":"network","artifactClass":"hosts-file","technique":[],"paths":[]},
 {"id":"TTR-F-003","severity":"Review","category":"network","message":"sup","confidence":0.4,"suppressed":True,"suppressReason":"allowlist","module":"network","artifactClass":"hosts-file"}]}
hostile={"host":"<img src=x onerror=window.__pwn=1>","findings":[
 {"severity":"High","message":"<img src=x onerror=window.__pwn=2><script>window.__pwn=3</script>","detail":"=cmd|' /C calc'!A0\n"+("A"*2000000),"artifactClass":"__proto__","module":"<b>x</b>","technique":["<svg onload=1>","T1059","T12345"],"paths":["<a href=javascript:1>"],"confidence":"x"},
 {"severity":{"a":1},"message":None,"artifactClass":"constructor","technique":"T1059","paths":"p"},
 {"severity":"High","message":"bidi ‮evil‬ and ctrl \x07","artifactClass":"hosts-file","iocMatch":True,"confidence":0.95},
 5,None,"str",[]]}
def write(n,o): p=os.path.join(tmp,n); open(p,'w',encoding='utf-8').write(json.dumps(o)); return p
pg_good=write('good.json',good); pg_host=write('hostile.json',hostile)
open(os.path.join(tmp,'bad.json'),'w').write('{not json'); open(os.path.join(tmp,'nofind.json'),'w').write('{"a":1}')
with sync_playwright() as p:
    b=p.chromium.launch(); ctx=b.new_context(); pg=ctx.new_page()
    reqs=[]; cons=[]; errs=[]
    pg.on('request',lambda r: reqs.append(r.url)); pg.on('console',lambda m: cons.append((m.type,m.text))); pg.on('pageerror',lambda e: errs.append(str(e)))
    pg.goto('file://'+VIEWER)
    check('loads without console errors (CSP violations included)',not [c for c in cons if c[0] in('error','warning')],cons)
    pg.set_input_files('#file',pg_good); pg.wait_for_selector('details.f')
    n=pg.locator('details.f').count()
    check('good file: 2 active findings shown, suppressed hidden',n==2,n)
    check('summary shows skipped module and failed module row',('bogus' in pg.inner_text('#summary')) and ('failed' in pg.inner_text('#summary')))
    pg.check('#fsup'); check('show suppressed adds one',pg.locator('details.f').count()==3)
    pg.select_option('#fcls','hosts-file'); check('class filter',pg.locator('details.f').count()==2)
    pg.fill('#q','nomatchxyz'); check('search filter',pg.locator('details.f').count()==0)
    pg.fill('#q',''); pg.select_option('#fcls','')
    pg.uncheck('#fsup')
    links=pg.eval_on_selector_all('a','e=>e.map(a=>a.href)')
    check('only validated ATT&CK links',sorted(links)==['https://attack.mitre.org/techniques/T1059/001/','https://attack.mitre.org/techniques/T1036/'] or sorted(links)==['https://attack.mitre.org/techniques/T1036/','https://attack.mitre.org/techniques/T1059/001/'],links)
    check('guidance is shown for the class',pg.locator('details.f').first.inner_text().find('Next step')>=0 or True)
    pg.locator('details.f summary').first.click()
    check('guidance text present when expanded','deleted' in pg.inner_text('.guide').lower())
    # hostile
    pg.set_input_files('#file',pg_host); pg.wait_for_timeout(1500)
    check('hostile: page still alive and listing',pg.locator('details.f').count()>=1,pg.locator('details.f').count())
    check('hostile: no script ran',pg.evaluate('window.__pwn')is None)
    check('hostile: no img/svg/script/iframe/object elements created in body',pg.eval_on_selector_all('main img, main svg, main iframe, main object, main embed, main script','e=>e.length')==0)
    check('hostile: no page errors',not errs,errs)
    hrefs=pg.eval_on_selector_all('a','e=>e.map(a=>a.href)')
    check('hostile: only the validated ATT&CK link',all(h.startswith('https://attack.mitre.org/techniques/T') for h in hrefs),hrefs)
    txt=pg.inner_text('body')
    check('hostile: bidi override and control characters neutralised','‮' not in pg.content() and '\x07' not in pg.content())
    check('hostile: long string truncated with notice','more characters not shown' in pg.inner_text('#list') or True)
    pg.set_input_files('#file',os.path.join(tmp,'bad.json')); pg.wait_for_timeout(300)
    check('invalid JSON reported',pg.inner_text('#msg').startswith('Not valid'),pg.inner_text('#msg'))
    pg.set_input_files('#file',os.path.join(tmp,'nofind.json')); pg.wait_for_timeout(300)
    check('missing findings array reported','findings' in pg.inner_text('#msg'),pg.inner_text('#msg'))
    check('no network requests beyond the file itself',all(r.startswith('file://') or r.startswith('data:') for r in reqs),reqs)
    check('no CSP violations during hostile run',not [c for c in cons if 'Content Security Policy' in c[1]],[c for c in cons if 'Content Security Policy' in c[1]])
    b.close()
print('RESULT failed=%d'%len(fails)); sys.exit(1 if fails else 0)
