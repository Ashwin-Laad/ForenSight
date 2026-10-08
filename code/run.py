"""ForenSIGHT experiments: signature IDS + ML IDS + anomaly detector + hybrid fusion
+ tamper-evident (hash-chained) forensic alert log, evaluated on NSL-KDD."""
import json, time, hashlib, hmac, copy, os, sys
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, roc_curve, confusion_matrix)
from xgboost import XGBClassifier
import shap

SEED = 42
np.random.seed(SEED)
D = sys.argv[1]; OUT = sys.argv[2]; os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"font.family": "serif", "font.serif": ["Liberation Serif"], "mathtext.fontset": "stix", "font.size": 10})
BLUE, DBLUE, LBLUE, BLACK = "#1f4e9c", "#0b2559", "#8fb3e8", "#000000"

cols = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
"num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
"serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]
tr = pd.read_csv(f"{D}/KDDTrain+.txt", names=cols); te = pd.read_csv(f"{D}/KDDTest+.txt", names=cols)

cat = {}
for a in "back land neptune pod smurf teardrop apache2 udpstorm processtable mailbomb worm".split(): cat[a]="DoS"
for a in "satan ipsweep nmap portsweep mscan saint".split(): cat[a]="Probe"
for a in ("guess_passwd ftp_write imap phf multihop warezmaster warezclient spy xlock xsnoop snmpguess "
          "snmpgetattack httptunnel sendmail named").split(): cat[a]="R2L"
for a in "buffer_overflow loadmodule rootkit perl sqlattack xterm ps".split(): cat[a]="U2R"
cat["normal"]="Normal"
for df in (tr, te):
    df["cat"] = df.label.map(cat); df["y"] = (df.label != "normal").astype(int)
assert te.cat.isna().sum()==0 and tr.cat.isna().sum()==0
known = set(tr.label.unique()); te["novel"] = (~te.label.isin(known)) & (te.y==1)
R = {}
R["dataset"] = {"train": len(tr), "test": len(te), "test21": int((te.difficulty<21).sum()),
  "train_cat": tr.cat.value_counts().to_dict(), "test_cat": te.cat.value_counts().to_dict(),
  "novel_types": sorted(set(te.label)-known), "n_novel_types": len(set(te.label)-known),
  "n_novel_records": int(te.novel.sum()), "train_types": len(known)-1, "test_types": te.label.nunique()-1}

# ---------------- preprocessing ----------------
catf = ["protocol_type","service","flag"]; numf = [c for c in cols[:41] if c not in catf]
def prep_num(df):
    X = df[numf].astype(float).copy()
    for c in ["duration","src_bytes","dst_bytes","count","srv_count","dst_host_count","dst_host_srv_count",
              "hot","num_compromised","num_root","num_file_creations","num_access_files"]:
        X[c] = np.log1p(X[c])
    return pd.concat([X, df[catf]], axis=1)
ct = ColumnTransformer([("oh", OneHotEncoder(handle_unknown="ignore", sparse_output=False), catf),
                        ("sc", MinMaxScaler(), numf)])
trn, val = train_test_split(tr, test_size=0.2, stratify=tr.label.where(tr.label.map(tr.label.value_counts())>1,"rare"), random_state=SEED)
Xtr = ct.fit_transform(prep_num(trn)); Xval = ct.transform(prep_num(val)); Xte = ct.transform(prep_num(te))
fnames = [n.split("__")[1] for n in ct.get_feature_names_out()]
ytr, yval, yte = trn.y.values, val.y.values, te.y.values
m21 = (te.difficulty < 21).values
R["n_features_after_encoding"] = Xtr.shape[1]

def metrics(y, p, s=None):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0,1]).ravel()
    d = {"acc": accuracy_score(y,p), "prec": precision_score(y,p,zero_division=0), "rec": recall_score(y,p),
         "f1": f1_score(y,p), "fpr": fp/(fp+tn), "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}
    if s is not None: d["auc"] = roc_auc_score(y, s)
    return {k: (round(float(v),4) if isinstance(v,float) else v) for k,v in d.items()}

def catrec(pred, df=te):
    out = {}
    for c in ["DoS","Probe","R2L","U2R"]:
        m = (df.cat==c).values; out[c] = round(float(pred[m].mean()),4)
    out["Normal_FPR"] = round(float(pred[(df.cat=="Normal").values].mean()),4)
    nv = df.novel.values; kn = (df.y==1).values & ~nv
    out["known_attacks"] = round(float(pred[kn].mean()),4); out["novel_attacks"] = round(float(pred[nv].mean()),4)
    return out

# ---------------- 1. signature engine (Snort-style rules on flow features) ----------------
RULES = [
 ("SIG-01","SYN flood (half-open connections)","T1498/T1499", lambda d: (d.flag.isin(["S0","S1","S2","S3"])) & (d.serror_rate>=0.8) & (d["count"]>=50)),
 ("SIG-02","ICMP echo-reply flood (Smurf)","T1498", lambda d: (d.protocol_type=="icmp") & (d.service=="ecr_i") & (d.src_bytes>=1000)),
 ("SIG-03","Malformed / overlapping fragments (Teardrop, Pod)","T1499", lambda d: d.wrong_fragment>0),
 ("SIG-04","LAND attack (src == dst)","T1499", lambda d: d.land==1),
 ("SIG-05","Port scan / sweep (REJ/RSTO burst)","T1046", lambda d: (d.rerror_rate>=0.8) & ((d.diff_srv_rate>=0.5) | (d.dst_host_diff_srv_rate>=0.5))),
 ("SIG-06","Host sweep (ICMP to many hosts)","T1018", lambda d: (d.protocol_type=="icmp") & (d.service.isin(["eco_i","ecr_i"])) & (d.dst_host_srv_diff_host_rate>=0.5)),
 ("SIG-07","Brute-force login (failed logins)","T1110", lambda d: d.num_failed_logins>=1),
 ("SIG-08","Root shell obtained (privilege escalation)","T1068", lambda d: d.root_shell>=1),
 ("SIG-09","Unexpected su / root activity in session","T1548", lambda d: (d.su_attempted>=1) | ((d.num_root>=1) & (d.logged_in==1) & (d.num_file_creations>=1))),
 ("SIG-10","Oversized HTTP request (Back / web exploit)","T1190", lambda d: (d.service=="http") & (d.src_bytes>=20000)),
 ("SIG-11","Guest FTP write (warez upload)","T1105", lambda d: (d.service.isin(["ftp","ftp_data"])) & (d.is_guest_login==1)),
 ("SIG-12","High 'hot' indicator count in session","T1059", lambda d: d.hot>=5),
]
def sig_engine(df):
    hits = np.zeros((len(df), len(RULES)), bool)
    for j,(rid,_,_,f) in enumerate(RULES): hits[:,j] = f(df).values
    return hits
t0 = time.perf_counter(); Hte = sig_engine(te); t_sig = time.perf_counter()-t0
sig_pred = Hte.any(1).astype(int)
R["signature"] = {"test": metrics(yte, sig_pred), "test21": metrics(yte[m21], sig_pred[m21]), "cat": catrec(sig_pred),
  "rules": [{"id":r[0],"name":r[1],"attck":r[2],"hits":int(Hte[:,j].sum()),
             "precision": round(float(yte[Hte[:,j]].mean()),4) if Hte[:,j].sum() else None} for j,r in enumerate(RULES)],
  "latency_us": round(t_sig/len(te)*1e6,3)}
Hval = sig_engine(val); R["signature"]["val"] = metrics(yval, Hval.any(1).astype(int))

# ---------------- 2. supervised ML ----------------
spw = (ytr==0).sum()/(ytr==1).sum()
models = {
 "Logistic Regression": LogisticRegression(max_iter=2000, C=1.0, random_state=SEED),
 "Decision Tree": DecisionTreeClassifier(max_depth=20, min_samples_leaf=2, random_state=SEED),
 "Random Forest": RandomForestClassifier(n_estimators=200, min_samples_leaf=1, n_jobs=-1, random_state=SEED),
 "MLP (64-32)": MLPClassifier(hidden_layer_sizes=(64,32), max_iter=60, early_stopping=True, random_state=SEED),
 "XGBoost": XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.9, colsample_bytree=0.8,
                          tree_method="hist", n_jobs=2, random_state=SEED, eval_metric="logloss"),
}
R["ml"] = {}; scores = {}
for name, m in models.items():
    t0=time.perf_counter(); m.fit(Xtr, ytr); tfit=time.perf_counter()-t0
    t0=time.perf_counter(); s = m.predict_proba(Xte)[:,1]; tinf=time.perf_counter()-t0
    p = (s>=0.5).astype(int); scores[name]=s
    sv = m.predict_proba(Xval)[:,1]
    R["ml"][name] = {"val": metrics(yval,(sv>=.5).astype(int),sv), "test": metrics(yte,p,s),
                     "test21": metrics(yte[m21],p[m21],s[m21]), "cat": catrec(p),
                     "fit_s": round(tfit,2), "latency_us": round(tinf/len(te)*1e6,3)}
    print(name, R["ml"][name]["test"])
xgb = models["XGBoost"]

# ---------------- 3. unsupervised anomaly detector (trained on normal traffic only) ----------------
iso = IsolationForest(n_estimators=300, max_samples=4096, contamination="auto", random_state=SEED, n_jobs=-1)
iso.fit(Xtr[ytr==0])
a_val = -iso.score_samples(Xval); a_te = -iso.score_samples(Xte)
thr_iso = float(np.quantile(a_val[yval==0], 0.97))   # calibrated: 3% FPR budget on validation normals
iso_pred = (a_te>=thr_iso).astype(int)
R["iforest"] = {"thr": round(thr_iso,4), "test": metrics(yte, iso_pred, a_te), "test21": metrics(yte[m21],iso_pred[m21],a_te[m21]), "cat": catrec(iso_pred)}

# ---------------- 4. hybrid fusion ----------------
# Tier-1 signatures (high-confidence known), Tier-2 XGBoost, Tier-3 anomaly. Thresholds tuned on validation only.
s_val = xgb.predict_proba(Xval)[:,1]; s_te = scores["XGBoost"]
sig_val = Hval.any(1)
best=None
for t in np.round(np.arange(0.05,0.96,0.05),2):
    for q in [0.90,0.93,0.95,0.97,0.98,0.99]:
        ti = np.quantile(a_val[yval==0], q)
        pv = (sig_val | (s_val>=t) | (a_val>=ti)).astype(int)
        mv = metrics(yval,pv)
        if mv["fpr"]<=0.03:
            key = (mv["f1"], -mv["fpr"])
            if best is None or key>best[0]: best=(key,t,q,ti)
_,t_x,q_i,thr_h = best
print("hybrid thresholds", t_x, q_i)
src_sig = Hte.any(1); src_ml = s_te>=t_x; src_an = a_te>=thr_h
hyb = (src_sig|src_ml|src_an).astype(int)
# continuous fused score for ROC: max of calibrated components
fused = np.maximum.reduce([src_sig.astype(float), s_te, np.clip((a_te-a_val[yval==0].min())/(np.quantile(a_val,0.999)-a_val[yval==0].min()),0,1)])
R["hybrid"] = {"xgb_thr": float(t_x), "iso_quantile": q_i, "iso_thr": round(float(thr_h),4),
  "test": metrics(yte,hyb,fused), "test21": metrics(yte[m21],hyb[m21],fused[m21]), "cat": catrec(hyb),
  "val": metrics(yval,(sig_val|(s_val>=t_x)|(a_val>=thr_h)).astype(int))}
# ablation
abl = {"Signature only": src_sig, "XGBoost only (t=0.5)": s_te>=0.5, "XGBoost (tuned t)": src_ml, "Isolation Forest only": src_an,
       "Signature + XGBoost": src_sig|src_ml, "XGBoost + IForest": src_ml|src_an, "Full hybrid (Sig + XGB + IF)": src_sig|src_ml|src_an}
R["ablation"] = {k: {**metrics(yte,v.astype(int)), **{"novel": catrec(v.astype(int))["novel_attacks"]}} for k,v in abl.items()}
# which tier first caught each true attack
att = yte==1
R["tier_attribution"] = {"sig": int((src_sig&att).sum()), "ml_only": int((~src_sig&src_ml&att).sum()),
                         "anom_only": int((~src_sig&~src_ml&src_an&att).sum()), "missed": int((att&(hyb==0)).sum())}

# ---------------- 5. multi-class (attack category) ----------------
cmap = {"Normal":0,"DoS":1,"Probe":2,"R2L":3,"U2R":4}; inv = {v:k for k,v in cmap.items()}
ytr5 = trn.cat.map(cmap).values; yte5 = te.cat.map(cmap).values
from sklearn.utils.class_weight import compute_sample_weight
xgb5 = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.9, colsample_bytree=0.8,
                     tree_method="hist", n_jobs=2, random_state=SEED, objective="multi:softprob")
xgb5.fit(Xtr, ytr5, sample_weight=compute_sample_weight("balanced", ytr5))
p5 = xgb5.predict(Xte)
cm5 = confusion_matrix(yte5, p5, labels=[0,1,2,3,4])
R["multiclass"] = {"acc": round(accuracy_score(yte5,p5),4), "macro_f1": round(f1_score(yte5,p5,average="macro"),4),
  "weighted_f1": round(f1_score(yte5,p5,average="weighted"),4),
  "per_class_f1": {inv[i]: round(v,4) for i,v in enumerate(f1_score(yte5,p5,average=None,labels=[0,1,2,3,4]))},
  "cm": cm5.tolist()}

# ---------------- 6. explainability (SHAP on XGBoost) ----------------
expl = shap.TreeExplainer(xgb)
idx = np.random.RandomState(SEED).choice(len(Xte), 3000, replace=False)
sv = expl.shap_values(Xte[idx])
imp = np.abs(sv).mean(0); order = np.argsort(imp)[::-1][:15]
R["shap_top"] = [(fnames[i], round(float(imp[i]),4)) for i in order]

# ---------------- 7. forensic-ready, tamper-evident alert log ----------------
KEY = b"forensight-demo-anchor-key"  # demo HMAC key for periodic signed anchors (would live in an HSM)
alerts_idx = np.where(hyb==1)[0]
sv_all = None
def build_log(ids, with_shap=True):
    prev = "0"*64; log=[]; anchors=[]
    base_ts = 1791436800.0  # fixed epoch for reproducibility (2026-10-08 UTC)
    if with_shap: S = expl.shap_values(Xte[ids])
    for k,i in enumerate(ids):
        r = te.iloc[i]
        src = "SIG" if src_sig[i] else ("ML" if src_ml[i] else "ANOMALY")
        rule = [RULES[j][0] for j in np.where(Hte[i])[0]]
        rec = {"seq": k, "ts": round(base_ts + k*0.01,2), "flow_id": int(i), "proto": r.protocol_type, "service": r.service,
               "flag": r.flag, "src_bytes": int(r.src_bytes), "dst_bytes": int(r.dst_bytes),
               "detector": src, "rules": rule, "ml_score": round(float(s_te[i]),4), "anomaly": round(float(a_te[i]),4),
               "severity": "HIGH" if (src_sig[i] or s_te[i]>=0.9) else ("MEDIUM" if s_te[i]>=t_x else "LOW"),
               "evidence": [fnames[j] for j in np.argsort(-np.abs(S[k]))[:3]] if with_shap else [],
               "prev_hash": prev}
        payload = json.dumps(rec, sort_keys=True, separators=(",",":")).encode()
        h = hashlib.sha256(payload).hexdigest(); rec["hash"]=h; prev=h; log.append(rec)
        if (k+1)%1000==0: anchors.append({"upto": k, "hash": h, "hmac": hmac.new(KEY, h.encode(), hashlib.sha256).hexdigest()})
    return log, anchors
def verify(log, anchors):
    prev="0"*64
    for k,rec in enumerate(log):
        r = {kk:vv for kk,vv in rec.items() if kk!="hash"}
        if r["prev_hash"]!=prev or r["seq"]!=k: return ("broken-link", k)
        h = hashlib.sha256(json.dumps(r, sort_keys=True, separators=(",",":")).encode()).hexdigest()
        if h!=rec["hash"]: return ("hash-mismatch", k)
        prev=h
    for a in anchors:
        if a["upto"]>=len(log) or log[a["upto"]]["hash"]!=a["hash"] or not hmac.compare_digest(a["hmac"], hmac.new(KEY,a["hash"].encode(),hashlib.sha256).hexdigest()):
            return ("anchor-mismatch", a["upto"])
    return ("ok", None)
t0=time.perf_counter(); log, anchors = build_log(alerts_idx, with_shap=False); t_build=time.perf_counter()-t0
t0=time.perf_counter(); v=verify(log, anchors); t_ver=time.perf_counter()-t0
log_s, anch_s = build_log(alerts_idx[:2000], with_shap=True)
with open(f"{OUT}/alert_log_sample.jsonl","w") as f:
    for rec in log_s[:5]: f.write(json.dumps(rec)+"\n")
size = sum(len(json.dumps(r)) for r in log)
# tamper experiments
rng = np.random.RandomState(SEED); T={}
def trial(fn, n=200):
    det=0; locs=[]
    for _ in range(n):
        L = copy.deepcopy(log_s); A = copy.deepcopy(anch_s); pos = fn(L, A, rng)
        res = verify(L, A); det += res[0]!="ok"; locs.append(res[1]==pos if res[0]!="ok" else False)
    return {"detected": det, "trials": n, "localised": int(sum(locs))}
def t_modify(L,A,rng):
    k=rng.randint(len(L)); L[k]["detector"]="NONE"; L[k]["severity"]="LOW"; return k
def t_delete(L,A,rng):
    k=rng.randint(1,len(L)-1); del L[k]
    for j in range(k,len(L)): L[j]["seq"]=j  # attacker renumbers
    return k
def t_reorder(L,A,rng):
    k=rng.randint(len(L)-1); L[k],L[k+1]=L[k+1],L[k]; return k
def t_rechain(L,A,rng):  # attacker modifies and recomputes ALL hashes after it (no key for anchors)
    k=rng.randint(len(L)-1); L[k]["ml_score"]=0.01; prev=L[k]["prev_hash"]
    for j in range(k,len(L)):
        L[j]["prev_hash"]=prev; r={kk:vv for kk,vv in L[j].items() if kk!="hash"}
        L[j]["hash"]=hashlib.sha256(json.dumps(r,sort_keys=True,separators=(",",":")).encode()).hexdigest(); prev=L[j]["hash"]
    return (k//1000)*1000+999 if k < 1999 else None
def t_truncate(L,A,rng):
    k=rng.randint(1000,len(L)); del L[k:]; return None
T["Field modification"]=trial(t_modify); T["Record deletion"]=trial(t_delete); T["Record reordering"]=trial(t_reorder)
T["Modify + full re-hash"]=trial(t_rechain); T["Tail truncation"]=trial(t_truncate)
R["forensic_log"] = {"alerts": len(log), "build_s": round(t_build,3), "build_us_per_alert": round(t_build/len(log)*1e6,2),
  "verify_s": round(t_ver,3), "verify_us_per_alert": round(t_ver/len(log)*1e6,2), "verify_result": v[0],
  "bytes": size, "bytes_per_alert": round(size/len(log),1), "anchors": len(anchors), "tamper": T,
  "sample": log_s[0]}
print(json.dumps(R["forensic_log"]["tamper"]))

# ---------------- figures ----------------
def save(fig, n): fig.tight_layout(); fig.savefig(f"{OUT}/{n}.pdf"); plt.close(fig)
# ROC
fig, ax = plt.subplots(figsize=(5.2,4.2)); styles=[("-",DBLUE),("--",BLUE),("-.",LBLUE),(":",BLACK),("-",BLUE)]
for (name,s),(ls,c) in zip(scores.items(), styles):
    fpr,tpr,_=roc_curve(yte,s); ax.plot(fpr,tpr,ls,color=c,lw=1.4,label=f"{name} (AUC={R['ml'][name]['test']['auc']:.3f})")
fpr,tpr,_=roc_curve(yte,a_te); ax.plot(fpr,tpr,"--",color=BLACK,lw=1,label=f"Isolation Forest (AUC={R['iforest']['test']['auc']:.3f})")
ax.plot([0,1],[0,1],color="#9db5d9",lw=.8); ax.set_xlabel("False positive rate"); ax.set_ylabel("True positive rate")
ax.set_title("ROC on KDDTest+ (binary)"); ax.legend(fontsize=7.5, loc="lower right"); save(fig,"roc")
# per-category recall
fig, ax = plt.subplots(figsize=(6.4,3.4)); cats=["DoS","Probe","R2L","U2R","known_attacks","novel_attacks"]
lbl=["DoS","Probe","R2L","U2R","Known\ntypes","Novel\ntypes"]
series=[("Signature",R["signature"]["cat"],LBLUE),("XGBoost",R["ml"]["XGBoost"]["cat"],BLUE),("Hybrid",R["hybrid"]["cat"],DBLUE)]
x=np.arange(len(cats)); w=.26
for k,(n,d,c) in enumerate(series):
    b=ax.bar(x+(k-1)*w,[d[cc]*100 for cc in cats],w,color=c,edgecolor=BLACK,lw=.4,label=n)
    for xi,v in zip(x+(k-1)*w,[d[cc]*100 for cc in cats]): ax.text(xi,v+1,f"{v:.0f}",ha="center",fontsize=6.5)
ax.set_xticks(x); ax.set_xticklabels(lbl); ax.set_ylabel("Detection rate / recall (%)"); ax.set_ylim(0,110)
ax.legend(fontsize=8, ncol=3, loc="upper right"); ax.spines[["top","right"]].set_visible(False); save(fig,"cat_recall")
# confusion matrix
fig, ax = plt.subplots(figsize=(4.4,3.8)); cmn = cm5/cm5.sum(1,keepdims=True)
ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1); names=["Normal","DoS","Probe","R2L","U2R"]
for i in range(5):
    for j in range(5): ax.text(j,i,f"{cm5[i,j]}\n({cmn[i,j]*100:.0f}%)",ha="center",va="center",fontsize=7,color="white" if cmn[i,j]>.5 else BLACK)
ax.set_xticks(range(5)); ax.set_yticks(range(5)); ax.set_xticklabels(names); ax.set_yticklabels(names)
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title("5-class XGBoost on KDDTest+"); save(fig,"cm5")
# SHAP bar
fig, ax = plt.subplots(figsize=(5.6,4)); tops=R["shap_top"][::-1]
ax.barh([t[0] for t in tops],[t[1] for t in tops],color=BLUE,edgecolor=BLACK,lw=.4)
ax.set_xlabel("Mean |SHAP value| (impact on attack log-odds)"); ax.set_title("Top-15 features driving XGBoost alerts")
ax.spines[["top","right"]].set_visible(False); ax.tick_params(axis="y",labelsize=8); save(fig,"shap")
# ablation bars
fig, ax = plt.subplots(figsize=(6.4,3.4)); ks=list(R["ablation"].keys())
rec=[R["ablation"][k]["rec"]*100 for k in ks]; nov=[R["ablation"][k]["novel"]*100 for k in ks]; fp=[R["ablation"][k]["fpr"]*100 for k in ks]
x=np.arange(len(ks)); w=.27
ax.bar(x-w,rec,w,color=BLUE,edgecolor=BLACK,lw=.4,label="Overall recall")
ax.bar(x,nov,w,color=LBLUE,edgecolor=BLACK,lw=.4,label="Novel-attack recall")
ax.bar(x+w,fp,w,color=BLACK,label="False positive rate")
ax.set_xticks(x); ax.set_xticklabels([k.replace(" (","\n(").replace(" + ","+\n",1) if len(k)>14 else k for k in ks],fontsize=6.6)
ax.set_ylabel("%"); ax.legend(fontsize=7.5,ncol=3,loc="upper left"); ax.set_ylim(0,105); ax.spines[["top","right"]].set_visible(False); save(fig,"ablation")

json.dump(R, open(f"{OUT}/results.json","w"), indent=1, default=str)
print(json.dumps({k:R[k] for k in ["signature","hybrid","multiclass","iforest"]}, indent=1, default=str)[:6000])
