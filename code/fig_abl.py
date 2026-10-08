import json,sys,numpy as np,matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
plt.rcParams.update({"font.family":"serif","font.serif":["Liberation Serif"],"font.size":10})
R=json.load(open(sys.argv[1])); A=R["ablation"]
ks=list(A); lab=["Signature\nonly","XGBoost\n(t=0.5)","XGBoost\n(tuned t)","IForest\nonly","Sig +\nXGB","XGB +\nIForest","Full\nhybrid"]
x=np.arange(len(ks)); w=.27; fig,ax=plt.subplots(figsize=(6.6,3.4))
for off,key,c,n in [(-w,"rec","#1f4e9c","Overall recall"),(0,"novel","#8fb3e8","Novel-attack recall"),(w,"fpr","#000000","False positive rate")]:
    v=[A[k][key]*100 for k in ks]; ax.bar(x+off,v,w,color=c,edgecolor="black",lw=.4,label=n)
    for xi,vi in zip(x+off,v): ax.text(xi,vi+1,f"{vi:.0f}",ha="center",fontsize=6.3)
ax.set_xticks(x); ax.set_xticklabels(lab,fontsize=8); ax.set_ylabel("%"); ax.set_ylim(0,100)
ax.legend(fontsize=7.5,ncol=3,loc="upper left",frameon=False); ax.spines[["top","right"]].set_visible(False)
fig.tight_layout(); fig.savefig(sys.argv[2])
