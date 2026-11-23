"""Original (rights-free) phonk tracks, 36 beats, drop on beat 8, denser on 16, silence + final hit on beat 32.
usage: python3 phonk.py drift|funk|hard out.wav   (drift 142 BPM, funk 130 BPM, hard 155 BPM aggressive)"""
import numpy as np, wave, sys
style=sys.argv[1];out=sys.argv[2]
BPM={'drift':142,'funk':130,'hard':155}[style];B=60/BPM;SR=44100;NB=36;D=NB*B+.3;n=int(SR*D);t=np.arange(n)/SR
rng=np.random.default_rng({'drift':7,'funk':13,'hard':21}[style])
L=np.zeros(n);R=np.zeros(n);PADL=np.zeros(n);PADR=np.zeros(n);BAS=np.zeros(n)
hz=lambda m:440*2**((m-69)/12)
def put(arr,t0,x,g=1.0):
    i=int(t0*SR)
    if i<0 or i>=n:return
    x=x[:n-i];arr[i:i+len(x)]+=x*g
def pan(t0,x,p=.5,g=1.0):put(L,t0,x,g*(1-p)*1.4);put(R,t0,x,g*p*1.4)
def xs(d):return np.arange(int(d*SR))/SR
lp=lambda x,k:np.convolve(x,np.ones(k)/k,'same')
dist=lambda x,d:np.tanh(x*d)/np.tanh(d)
# ---------- instruments
def cowbell(note,vel=1.0,dur=.45):
    r=2**(note/12);x=xs(dur);f1,f2=562*r,845*r
    sq=lambda f:sum(np.sin(2*np.pi*f*k*x)/k for k in (1,3,5,7))
    e=(np.exp(-x*16)*.8+np.exp(-x*5)*.3)*np.clip(x/.001,0,1)
    return dist((sq(f1)+sq(f2))*.5,2.2)*e*vel*.5
DRV=6.5 if style=='hard' else 3.2
def k808(note,dur,slide=0.0,drive=None):
    drive=DRV if drive is None else drive
    x=xs(dur);f=hz(note)*(2**(slide/12*np.exp(-x*9)))
    ph=2*np.pi*np.cumsum(f)/SR;v=np.sin(ph)*np.exp(-x*1.4)*np.clip(x/.004,0,1)*np.clip((dur-x)/.04,0,1)
    return dist(v,drive)*.8
def kick(vel=1.0):
    x=xs(.4);v=np.sin(2*np.pi*np.cumsum(48+150*np.exp(-x*30))/SR)*np.exp(-x*8)
    c=rng.standard_normal(len(x))*np.exp(-x*400)*.25
    return dist(v+c,2.0)*vel*.8
def snare(vel=1.0):
    x=xs(.35);nz=rng.standard_normal(len(x));nz=nz-lp(nz,3)
    b=np.sin(2*np.pi*185*x)*np.exp(-x*24)*.6
    return dist(nz*np.exp(-x*17)*.9+b,1.6)*vel*.55
def clap(vel=1.0):
    x=xs(.4);nz=rng.standard_normal(len(x));nz=nz-lp(nz,4);e=np.zeros(len(x))
    for o in (0,.011,.022):e+=np.exp(-np.clip(x-o,0,None)*55)*(x>=o)
    return nz*e*.4*vel
def hat(vel=1.0,o=False):
    x=xs(.22 if o else .05);nz=rng.standard_normal(len(x));nz=nz-lp(nz,3);return nz*np.exp(-x*(16 if o else 90))*.28*vel
FORM={'a':[(800,110),(1200,140)],'o':[(500,90),(900,120)],'e':[(420,80),(2000,200)],'u':[(330,70),(800,100)]}
def vox(note,vowel='a',dur=.22,vel=1.0):
    f0=hz(note);x=xs(dur);v=np.zeros(len(x))
    for h in range(1,26):
        fh=f0*h
        a=sum(np.exp(-((fh-F)/bw)**2) for F,bw in FORM[vowel])
        if a>.02:v+=np.sin(2*np.pi*fh*x+h)*a/h**.35
    v*=np.clip(x/.01,0,1)*np.clip((dur-x)/.03,0,1)*np.exp(-x*3)
    v=dist(v*.5,2.5)+rng.standard_normal(len(x))*.02*np.exp(-x*20)
    return v*vel*.35
def padchord(notes,d):
    x=xs(d);v=np.zeros(len(x))
    for m in notes:
        for det in (-.005,.0,.005):
            f=hz(m)*(1+det)
            v+=sum(np.sin(2*np.pi*f*k*x)/k for k in range(1,6))*.03
    return v*np.clip(x/.4,0,1)*np.clip((d-x)/.5,0,1)
def noise_riser(d,up=True):
    x=xs(d);nz=lp(rng.standard_normal(len(x)),6)*5;r=(x/d)**2.2 if up else (1-x/d)**2.2
    f=200+np.cumsum(r*2800)/SR*2;tone=np.sin(2*np.pi*np.cumsum(f)/SR)
    return (nz*.55+tone*.4)*r*(np.clip((d-x)/.01,0,1))
def impact(d=2.6):
    x=xs(d);v=np.sin(2*np.pi*np.cumsum(40+130*np.exp(-x*9))/SR)*np.exp(-x*1.6)
    c=rng.standard_normal(len(x));c=c-lp(c,5)
    return dist(v*1.2,2)+c*np.exp(-x*3)*.12
# ---------- arrangement (beat index = bar math; drop at beat 8)
ROOT={'drift':[33,29,31,28],'funk':[31,31,29,26],'hard':[31,31,29,27]}[style]   # A,F,G,E  /  G,G,F,D
SC=[0,3,5,7,10]
HARD=style=='hard'
def barnote(bar):return ROOT[bar%4]

# intro 0-8: pad, teaser, hats
for b in range(0,8,4):
    put(PADL,b*B,padchord([ROOT[(b//4)%4]+24,ROOT[(b//4)%4]+31,ROOT[(b//4)%4]+36],4*B+.3),1.0);put(PADR,b*B,padchord([ROOT[(b//4)%4]+24,ROOT[(b//4)%4]+31,ROOT[(b//4)%4]+36],4*B+.3),1.0)
for s,(bt,nt,vw) in enumerate([(2,12,'a'),(3,15,'o'),(5,12,'e'),(6.5,10,'a'),(7,15,'o')]):pan(bt*B,vox(57+nt,vw,.28),.3+.4*(s%2),.9)
for i in range(0,32):pan((4+i*.25)*B,hat(.5+.4*(i%4==0)),.5+.2*rng.standard_normal()*.3,.7)
for bt in (6,7):pan(bt*B,cowbell(0,.6),.5)
put(L,6*B,noise_riser(2*B),.18);put(R,6*B,noise_riser(2*B),.18)
# cowbell riff (2-beat motif), vox hooks, 808/kick groove from beat 8
MOT=[(0,0),(.5,0),(1.0,3),(1.5,0),(2,5),(2.5,3),(3,0),(3.5,-2)] if style=='drift' else [(0,5),(.75,5),(1.5,3),(2,5),(2.75,3),(3.5,0)]
KICK=[0,1.5,2.5] if style=='drift' else [0,.75,1.5,2.5,3.25]
SNR=[1,3] if style=='drift' else [1.5,3.5]
BASSP=[(0,1.2,0),(1.5,.8,2),(2.5,1.4,-2)] if style=='drift' else [(0,.7,0),(.75,.7,0),(1.5,1.2,3),(3,.9,0)]
if HARD:
    MOT=[(0,0),(.5,0),(1,3),(1.5,0),(2,5),(2.5,3),(3,0),(3.5,5)];KICK=[0,.75,1.5,2.5,3,3.5];SNR=[1,3]
    BASSP=[(0,.7,0),(.75,.7,0),(1.5,.9,3),(2.5,1,-2),(3.5,.5,0)]
for bar in range(2,9):   # bars start at beat 4*bar: bar2=8 ... bar8=32
    b0=bar*4
    if b0>=32:break
    root=barnote(bar-2);dense=b0>=16
    # pad
    if bar%2==0:
        ch=[root+24,root+27+24,root+31];put(PADL,b0*B,padchord(ch,8*B),1.0);put(PADR,b0*B,padchord(ch,8*B),1.0)
    for kp in KICK:pan((b0+kp)*B,kick(1.0 if kp==0 else .85),.5)
    for sp in SNR:
        pan((b0+sp)*B,snare(1.0),.5)
        if style in('drift','hard'):pan((b0+sp)*B,clap(.8 if not HARD else 1.0),.5)
    for dur_b,(p,ln,sl) in enumerate(BASSP):put(BAS,(b0+p)*B,k808(root+(12 if p==1.5 and style=='drift' and dense else 0)+(sl if sl==0 else 0),ln*B,slide=sl),1.0)
    # cowbell motif every 2 beats
    for half in (0,2):
        for off,nt in MOT:
            if off<2 and half==0 or off>=2 and half==2:
                bt=b0+off if style=='drift' else b0+off
                if style=='drift' and off>=2:bt=b0+off
                pan(bt*B,cowbell(nt+(12 if dense and nt==5 else 0),.75+.2*(off==0)),.62,1.0)
    if style=='funk':
        for bt in (0.5,2.0):pan((b0+bt)*B,cowbell(12,.5),.35)
    # vox hook on bar 2 of 2
    if bar%2==1:
        for j,(off,nt,vw) in enumerate([(0,12,'a'),(.5,15,'o'),(1.5,12,'e'),(2,10,'a'),(3,15,'o')]):pan((b0+off)*B,vox(57+nt,vw,.2),.35+.3*(j%2),1.0)
    # hats
    steps=4 if not dense else 8
    for i in range(int(4*steps)):
        v=.55+.3*(i%steps==0)
        if dense and (i%16)>=12:v*=1.2
        pan((b0+i/steps)*B,hat(v,o=(i%steps==steps//2 and dense)),.5+.2*rng.standard_normal()*.3,.8)
    if HARD:
        # reese bass: detuned saws, filter-pumped, sits under the 808
        xr=xs(4*B+.1);fl=(0.5+0.5*np.sin(2*np.pi*xr*(1/(B*.5))))
        rv=np.zeros(len(xr))
        for det in (-.006,.0,.006):
            f=hz(root+12)*(1+det);rv+=sum(np.sin(2*np.pi*f*k*xr)/k for k in range(1,12))
        rv=dist(rv*(.25+.5*fl),2.2)*.30*np.clip((4*B+.1-xr)/.05,0,1)
        put(BAS,b0*B,rv,1.0)
        # siren stab on bar 2 of each pair + rim ticks
        if bar%2==1:
            xsn=xs(2*B);sw=np.sin(2*np.pi*np.cumsum(hz(79)*(1+.045*np.sin(2*np.pi*3.2*xsn)+.5*np.exp(-xsn*3)))/SR)*np.exp(-xsn*1.4)
            pan((b0+2)*B,dist(sw*.5,3.0)*.45,.5,1.0)
        for rp in (.5,2.5):pan((b0+rp)*B,snare(.45),.35,.8)
        for i in range(8):pan((b0+i*.5+.25)*B,hat(.5,o=False),.6,.8)
    if dense:                                    # 32nd roll on last beat of every 2nd bar
        if bar%2==1:
            for i in range(16):pan((b0+3+i/16)*B,hat(.5+.5*i/16),.5,.8)
# build bar 28-32: snare roll + riser, then drop silence + final impact at beat 32
for i,bt in enumerate(np.arange(28,31.75,.25)):pan(bt*B,snare(.4+.7*(bt-28)/4),.5,.9)
if HARD:
    for bt in np.arange(30,31.9,.25):pan(bt*B,kick(.7+.4*(bt-30)/2),.5,.9)
put(L,29*B,noise_riser(3*B-.15),.28);put(R,29*B,noise_riser(3*B-.15),.28)
cut=int(31.9*B*SR);hush=int(32*B*SR)
# final hit
pan(32*B,impact(),.5,1.0);pan(32*B,kick(1.2),.5)
put(BAS,32*B,k808(ROOT[0]-12+12,2.2,slide=-5,drive=3.5),1.0)
for j,(off,nt,vw) in enumerate([(.25,12,'a'),(.75,15,'o'),(1.5,12,'e'),(2.25,10,'a'),(3,12,'o')]):pan((32+off)*B,vox(57+nt,vw,.22),.3+.4*(j%2),.9)
for bt in np.arange(34,36,.5):pan(bt*B,cowbell(0,.45),.62,.8)
put(PADL,32*B,padchord([ROOT[0]+24,ROOT[0]+27+24,ROOT[0]+31],4*B),1.0);put(PADR,32*B,padchord([ROOT[0]+24,ROOT[0]+27+24,ROOT[0]+31],4*B),1.0)
# pre-drop vacuum: duck everything just before beats 8, 16, 32
mask=np.ones(n)
for db in (8,16):
    a=int((db*B-.12)*SR);b=int(db*B*SR);mask[a:b]=.12
a=int((32*B-.12)*SR);b=int(32*B*SR);mask[a:b]=0.04
# sidechain duck for pad + 808 against kicks
duck=np.ones(n)
for bar in range(2,8):
    for kp in KICK:
        i=int((bar*4+kp)*B*SR);xx=np.arange(int(.22*SR))/SR;seg=min(len(xx),n-i);duck[i:i+seg]*=(.25+.75*(1-np.exp(-xx[:seg]*14)))
bus_l=L+PADL*duck*.9+BAS*duck*.75;bus_r=R+PADR*duck*.9+BAS*duck*.75
def verb(sig,seed,secs=1.6):
    r=np.random.default_rng(seed);m=int(secs*SR);ir=lp(r.standard_normal(m),5)*np.exp(-np.arange(m)/SR*3.3);N=1<<int(np.ceil(np.log2(n+m)))
    return np.fft.irfft(np.fft.rfft(sig,N)*np.fft.rfft(ir,N),N)[:n]*.01
wl=verb(L*1.0+PADL,1);wr=verb(R*1.0+PADR,2)
Lf=(bus_l+wl)*mask;Rf=(bus_r+wr)*mask
fade=np.clip((D-t)/.35,0,1);Lf*=fade;Rf*=fade
pk=max(abs(Lf).max(),abs(Rf).max());Lf/=pk;Rf/=pk
st=np.stack([Lf,Rf],1)*1.0;st=np.tanh(st*(3.0 if HARD else 2.0))/np.tanh(3.0 if HARD else 2.0)*.72
w=wave.open(out,'wb');w.setnchannels(2);w.setsampwidth(2);w.setframerate(SR);w.writeframes((np.clip(st,-1,1)*32767).astype('<i2').tobytes());w.close()
print(style,'bpm',BPM,'beat',round(B,4),'dur',round(D,2))
