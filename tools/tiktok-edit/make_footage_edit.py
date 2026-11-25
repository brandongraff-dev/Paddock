#!/usr/bin/env python3
"""Build a footage-montage plan for a variant: extracts one exact run of frames per beat from stock clips
(inputs/clips/<id>.mp4, e.g. Mixkit free-license clips) into build/plate-<variant>/fNNNN.jpg and writes
build/screens-<variant>.js (SCREENS for edit.html). usage: make_footage_edit.py w1|w2 [beat] [frames]"""
import sys, json, subprocess, pathlib, math
here = pathlib.Path(__file__).parent
V = sys.argv[1]; B = float(sys.argv[2]) if len(sys.argv) > 2 else 0.4796; FR = int(sys.argv[3]) if len(sys.argv) > 3 else 518
LOGOS16 = "[{logo:'kalilinux'},{logo:'metasploit'},{logo:'burpsuite'},{logo:'wireshark'},{logo:'linux'},{logo:'PADDOCK'},{logo:'python'},{logo:'owasp'},{logo:'openssl'},{logo:'github'},{logo:'docker'},{logo:'gnubash'},{logo:'virustotal'},{logo:'hashcat'},{logo:'git'},{logo:'debian'}]"
LOGOS9 = "[{logo:'kalilinux'},{logo:'metasploit'},{logo:'burpsuite'},{logo:'wireshark'},{logo:'PADDOCK'},{logo:'owasp'},{logo:'python'},{logo:'linux'},{logo:'github'}]"
def P(clip, t0, fx=.5, tone='red', **kw): return ('P', clip, t0, fx, tone, kw)
def J(js): return ('J', js)
W1 = [P(46627,2.0,.3,ret=1,rec=1,rid=1), J("{logoSlam:'kalilinux'}"), P(50745,1.5,.55,ret=1,rid=2), P(34837,.5,.5,'none'),
 J("{words:1,lines:['ROOT'],fs:300,col:'#ff4a3a'}"), P(46578,2.5,.4,rec=1), P(49126,2.0,.15,'none',ret=1,rid=3), J("{rainF:1}"),
 P(24036,1.5,.5), P(23703,1.5,.5), P(31378,2.0,.75,ret=1,rid=4), J("{logoSlam:'metasploit'}"),
 P(23159,2.0,.5,rec=1), J("{tex:{img:'wireshark',crop:[.2,.1,.8]}}"), P(46574,3.0,.4,ret=1,rid=5), J("{specF:1}"),
 P(50737,2.0,.5), P(49125,2.0,.5,rec=1), J("{words:1,lines:['0DAY'],fs:280,col:'#ffffff'}"), P(46575,3.0,.1),
 P(29904,2.0,.45,ret=1,rid=6), J("{logoSlam:'burpsuite'}"), P(46632,2.0,.35,rec=1), J("{hexF:1}"),
 P(22970,2.0,.3,ret=1,rid=7), J("{logoSlam:'python'}"), P(50743,2.0,.5,ret=1,rid=8), J("{words:1,lines:['SUDO'],fs:300,col:'#ff4a3a'}"),
 P(50744,2.0,.5,ret=1,rid=9), J("{wall:1,title:'',cols:4,cell:240,hl:5,items:%s}" % LOGOS16), P(31372,2.0,.5,'none',rec=1),
 J("{wall:1,title:'',cols:3,cell:300,hl:4,strobe:1,invert:1,items:%s}" % LOGOS9)]
W2 = [P(50737,1.0,.5,'blue',ret=1,rec=1,rid=11), J("{logoSlam:'kalilinux'}"), P(11747,1.0,.5,'blue'), P(23219,1.0,.5,'blue'),
 J("{words:1,lines:['ICE'],fs:340,col:'#8fdcff'}"), P(22760,1.0,.5,'blue'), P(46634,2.0,.5,'blue',rec=1), J("{radarF:1}"),
 P(7863,1.0,.5,'blue'), P(23215,1.0,.5,'blue'), P(14158,1.0,.5,'blue'), J("{logoSlam:'docker'}"),
 P(34838,1.0,.5,'blue'), J("{tex:{img:'nmap',crop:[.1,.1,.7]}}"), P(50748,2.0,.5,'blue',rec=1), J("{specF:1}"),
 P(23282,1.0,.5,'blue'), P(24033,1.0,.5,'blue'), J("{words:1,lines:['SYN'],fs:320,col:'#ffffff'}"), P(49247,2.0,.85,'blue',ret=1,rid=12),
 P(46639,2.0,.6,'blue',ret=1,rid=13), J("{logoSlam:'openssl'}"), P(47050,1.0,.5,'blue'), J("{hexF:1}"),
 P(14159,1.0,.5,'blue'), J("{logoSlam:'git'}"), P(12262,1.0,.5,'blue'), J("{words:1,lines:['ACK'],fs:340,col:'#8fdcff'}"),
 P(41658,1.0,.5,'blue'), J("{wall:1,title:'',cols:4,cell:240,hl:5,items:%s}" % LOGOS16), P(31536,1.0,.5,'blue'),
 J("{wall:1,title:'',cols:3,cell:300,hl:4,strobe:1,invert:1,items:%s}" % LOGOS9)]
plan = {'w1': W1, 'w2': W2}[V]
out = here / 'build' / f'plate-{V}'; out.mkdir(parents=True, exist_ok=True)
for f in out.glob('*.jpg'): f.unlink()
frames = {}
for f in range(FR):
    k = min(31, int(f / 30 / B)) if f / 30 / B < 32 else 99
    frames.setdefault(k, []).append(f)
screens = []
for k in range(32):
    it = plan[k]
    if it[0] == 'J': screens.append(it[1]); continue
    _, clip, t0, fx, tone, kw = it
    path = here / 'inputs' / 'clips' / f'{clip}.mp4'
    dur = float(subprocess.run(['ffprobe','-v','error','-show_entries','format=duration','-of','csv=p=0',str(path)],capture_output=True,text=True).stdout)
    t0 = max(0, min(t0, dur - 0.8)); fs = frames.get(k, [])
    if fs:
        subprocess.run(['ffmpeg','-y','-loglevel','error','-ss',f'{t0:.3f}','-i',str(path),'-vf',f"fps=30,scale=-2:1920,crop=1080:1920:'(iw-1080)*{fx}':0",'-frames:v',str(len(fs)),'-q:v','3','-start_number',str(fs[0]),str(out/'f%04d.jpg')],check=True)
    extra = ''.join(f",{a}:{b}" for a, b in kw.items())
    screens.append("{plate:1,tone:'%s'%s}" % (tone, extra))
# frames after the 32 beats belong to the finale (no plate)
js = "window.SCREENS_EXT=window.SCREENS_EXT||{};window.SCREENS_EXT['%s']=[\n%s\n];" % (V, ",\n".join(f"/*{i}*/{s}" for i, s in enumerate(screens)))
(here / 'build' / f'screens-{V}.js').write_text(js)
cp = here / 'build'
for n in ('config', 'onsets'):
    src = cp / f'{n}-g1.json'
    if src.exists(): (cp / f'{n}-{V}.json').write_text(src.read_text())
print(V, 'plate frames:', len(list(out.glob('*.jpg'))))
