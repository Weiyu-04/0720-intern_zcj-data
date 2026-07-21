#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
目录结构生成器 —— 本地快速版
用法:
    python3 _目录结构生成器.py <要解析的文件夹路径> [输出目录]

例:
    python3 _目录结构生成器.py /Volumes/语料库项目
    python3 _目录结构生成器.py /Volumes/知识库项目 ~/Desktop/nas服务器数据结构

功能:
  - 递归扫描（原生, 快）；保留隐藏/临时文件（.DS_Store、~$、.ghost 等）
  - 自适应折叠：小分支完整展开(目录内文件>8只列3个示例+汇总)；
    含大量重复子目录的大分支钻到第2层后改用 📦 汇总卡片(模态/文件数/大小/主要类型)
  - 生成 <文件夹名>.md
  - 末尾附「疑似未下载完整」清单(.downloading/.aria2/.part/.ghost 等)
无需第三方库，纯标准库。
"""
import os, sys, collections, datetime, time

sys.setrecursionlimit(100000)  # 防极深目录触发递归上限

# ---- 可调参数 ----
SMALL_FILES = 40      # 子树文件数<=此 且 目录数<=SMALL_DIRS => 视为“小”，完整展开
SMALL_DIRS  = 15
DRILL_MAX   = 2       # 大分支最多向下钻几层，之后出卡片
COLLAPSE    = 8       # 目录内文件数 > 此 则折叠为示例
SAMPLE      = 3       # 折叠时展示的示例文件数

MARKERS = [".downloading",".aria2",".part",".crdownload",".partial",
           ".opdownload",".ghost",".!qb",".bt.td",".xltd",".td",".dltmp"]

CAT = {
    "图像": {".jpg",".jpeg",".png",".bmp",".gif",".tif",".tiff",".webp"},
    "视频": {".mp4",".avi",".mov",".mkv",".flv",".wmv",".m4v"},
    "音频": {".wav",".mp3",".flac",".aac",".m4a",".ogg"},
    "点云/3D": {".pcd",".ply",".bin",".las",".obj",".npy",".npz"},
    "文本/标注": {".txt",".json",".xml",".csv",".yaml",".yml",".md",".jsonl",".tsv"},
    "文档": {".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".wps",".caj",".ofd"},
    "压缩包": {".zip",".tar",".gz",".7z",".rar",".bz2"},
    "代码/脚本": {".py",".ipynb",".sh",".c",".cpp",".h",".java",".m",".mat"},
}
E2C = {e:c for c,es in CAT.items() for e in es}

def human(n):
    n=float(n)
    for u in ["B","KB","MB","GB","TB"]:
        if n<1024 or u=="TB": return (f"{int(n)} B" if u=="B" else f"{n:.1f} {u}")
        n/=1024

def ext_of(nm):
    if nm.startswith("~$"): return "~$临时"
    d=nm.rfind(".")
    return nm[d:].lower() if d>0 else "(无扩展名)"

def is_marker(nm):
    low=nm.lower()
    for m in MARKERS:
        if low.endswith(m): return m
    return None

class Node:
    __slots__=("name","dirs","files","agg_size","agg_files","agg_dirs","ext","cat")
    def __init__(self,name):
        self.name=name; self.dirs={}; self.files=[]

markers_hit=[]   # (相对路径, 大小, 标记)
_SPIN="|/-\\"    # 旋转转轮(ASCII, 保证任何终端都能显示、明显在转)
_prog={"dirs":0,"files":0,"size":0,"errs":0,"last":0.0,"frame":0,"start":0.0}

def _tick(force=False):
    # 一行实时刷新的进度：转轮 + 已用时间 + 目录/文件/大小（原地更新，不刷屏）
    now=time.time()
    if not _prog["start"]: _prog["start"]=now
    if force or now-_prog["last"]>=0.12:
        _prog["last"]=now
        _prog["frame"]=(_prog["frame"]+1)%len(_SPIN)
        el=int(now-_prog["start"]); mm,ss=divmod(el,60)
        sys.stderr.write(f"\r  [{_SPIN[_prog['frame']]}] 扫描中 {mm:02d}:{ss:02d}  目录 {_prog['dirs']:,} · 文件 {_prog['files']:,} · 已统计 {human(_prog['size'])}        ")
        sys.stderr.flush()

def scan(path, node, relbase):
    try:
        with os.scandir(path) as it:
            entries=list(it)
    except (PermissionError,OSError):
        _prog["errs"]+=1
        return
    _prog["dirs"]+=1
    _tick()
    for e in sorted(entries, key=lambda x:x.name):
        try:
            if e.is_symlink():
                # 记为文件(不追链)，大小0
                node.files.append((e.name,0)); _prog["files"]+=1; continue
            if e.is_dir(follow_symlinks=False):
                child=Node(e.name); node.dirs[e.name]=child
                scan(e.path, child, relbase+"/"+e.name)
            else:
                try: sz=e.stat(follow_symlinks=False).st_size
                except OSError: sz=0
                node.files.append((e.name,sz)); _prog["files"]+=1; _prog["size"]+=sz
                if _prog["files"] % 2000 == 0: _tick()
                m=is_marker(e.name)
                if m: markers_hit.append((relbase+"/"+e.name, sz, m))
        except OSError:
            _prog["errs"]+=1
            continue

def aggregate(n):
    size=0;fc=0;dc=0;ext=collections.Counter();cat=collections.Counter()
    for nm,sz in n.files:
        size+=sz;fc+=1; e=ext_of(nm);ext[e]+=1;cat[E2C.get(e,"其他")]+=1
    for d in n.dirs.values():
        s,f,dd,ee,cc=aggregate(d);size+=s;fc+=f;dc+=1+dd;ext+=ee;cat+=cc
    n.agg_size=size;n.agg_files=fc;n.agg_dirs=dc;n.ext=ext;n.cat=cat
    return size,fc,dc,ext,cat

def modality(n):
    if n.agg_files==0: return "空"
    its=n.cat.most_common();tot=sum(n.cat.values()) or 1
    if len(its)==1 or its[0][1]/tot>=0.7: return f"{its[0][0]}为主"
    return f"{its[0][0]}+{its[1][0]}"

def top_exts(n,k=4):
    its=n.ext.most_common(k);s=" ".join(f"{e}×{c}" for e,c in its)
    if len(n.ext)>k: s+=" 等"
    return s

def card_text(n):
    seg=[modality(n), f"{n.agg_files:,} 文件", human(n.agg_size)]
    if n.agg_files>0: seg.append("主要类型 "+top_exts(n))
    if n.agg_dirs>0: seg.append(f"含 {n.agg_dirs} 子目录")
    return " · ".join(seg)

def decide(child, depth):
    if not child.dirs: return "fold"
    if child.agg_files<=SMALL_FILES and child.agg_dirs<=SMALL_DIRS: return "fold"
    if depth<DRILL_MAX: return "drill"
    return "card"

def render(n, prefix, depth, lines):
    dir_items=sorted(n.dirs.items())
    file_items=sorted(n.files)
    entries=[("D",nm,ch) for nm,ch in dir_items]
    if len(file_items)>COLLAPSE:
        entries+=[("F",nm,sz) for nm,sz in file_items[:SAMPLE]]
        entries+=[("C",None,file_items)]
    else:
        entries+=[("F",nm,sz) for nm,sz in file_items]
    m=len(entries)
    for i,(typ,name,obj) in enumerate(entries):
        last=i==m-1;conn="└── " if last else "├── ";ext="    " if last else "│   "
        if typ=="D":
            mode=decide(obj,depth+1)
            head=f"({obj.agg_dirs} 子目录, {obj.agg_files} 文件, {human(obj.agg_size)})"
            if mode=="card":
                lines.append(prefix+conn+f"📦 {name}/  —— {card_text(obj)}")
            else:
                lines.append(prefix+conn+f"📁 {name}/  {head}")
                render(obj, prefix+ext, depth+1, lines)
        elif typ=="F":
            lines.append(prefix+conn+f"📄 {name}  ({human(obj)})")
        else:
            allf=obj;c=collections.Counter(ext_of(nm) for nm,_ in allf)
            summ="、".join(f"{e}×{n2}" for e,n2 in c.most_common(5))+("等" if len(c)>5 else "")
            tot=sum(s for _,s in allf);rest=len(allf)-SAMPLE
            lines.append(prefix+conn+f"📄 …（本目录共 {len(allf)} 文件：{summ}；合计 {human(tot)}；上列 {SAMPLE} 个为示例，其余 {rest} 个已省略）")

def main():
    if len(sys.argv)<2:
        print("用法: python3 _目录结构生成器.py <文件夹路径> [输出目录]");sys.exit(1)
    target=os.path.abspath(sys.argv[1].rstrip("/"))
    outdir=os.path.abspath(sys.argv[2]) if len(sys.argv)>2 else os.path.dirname(os.path.abspath(__file__))
    name=os.path.basename(target)
    if not os.path.isdir(target):
        print(f"❌ 不是文件夹或无法访问: {target}")
        print("   若报权限问题：系统设置→隐私与安全性→完全磁盘访问权限→给终端授权后重开终端再试。")
        sys.exit(1)
    os.makedirs(outdir, exist_ok=True)
    print(f"扫描 {target} ...（大目录可能需要几分钟）")
    root=Node(name)
    scan(target, root, "")
    _tick(force=True); sys.stderr.write("\n"); sys.stderr.flush()
    if _prog["errs"]:
        print(f"⚠️ 有 {_prog['errs']} 处因权限/IO 无法读取，已跳过。")
    aggregate(root)
    lines=[]
    render(root,"",0,lines)
    tree="\n".join(lines)
    top=[(nm,ch.agg_dirs,ch.agg_files,ch.agg_size) for nm,ch in sorted(root.dirs.items())]
    rootf=sorted(root.files)
    today=datetime.date.today().isoformat()
    md=[]
    md.append(f"# {name}");md.append("")
    md.append(f"> 目录结构解析报告　·　生成日期：{today}　·　本地生成");md.append("")
    md.append("## 📊 总体统计");md.append("")
    md.append("| 指标 | 数值 |");md.append("| --- | --- |")
    md.append(f"| 目录总数 | {root.agg_dirs:,} 个 |")
    md.append(f"| 文件总数 | {root.agg_files:,} 个 |")
    md.append(f"| 内容总大小 | {human(root.agg_size)} |");md.append("")
    md.append("### 顶层分支概览");md.append("")
    md.append("| 分支 | 子目录数 | 文件数 | 大小 |");md.append("| --- | ---: | ---: | ---: |")
    for nm,dc,fc,sz in top: md.append(f"| 📁 {nm} | {dc:,} | {fc:,} | {human(sz)} |")
    for nm,sz in rootf: md.append(f"| 📄 {nm} | - | 1 | {human(sz)} |")
    md.append("")
    md.append("## 🗂 目录树（自适应折叠）");md.append("")
    md.append("```text");md.append(f"{name}/");md.append(tree);md.append("```");md.append("")
    if markers_hit:
        md.append("## ⚠️ 疑似未下载完整 / 临时下载文件");md.append("")
        md.append(f"共 **{len(markers_hit)}** 个（后缀为下载器未完成标记，可能数据没下全）：");md.append("")
        md.append("| 标记 | 大小 | 路径 |");md.append("| --- | ---: | --- |")
        for rel,sz,m in sorted(markers_hit):
            md.append(f"| `{m}` | {human(sz)} | {rel.lstrip('/')} |")
        md.append("")
    outpath=os.path.join(outdir, name+".md")
    # errors="replace": 遇到坏编码/乱码的文件名(常见于从 Windows/GBK 拷来的数据)也不会崩，
    # 无法表示的字符写成 “�”，保证 2 小时扫描后一定能出文件。
    with open(outpath,"w",encoding="utf-8",errors="replace") as f: f.write("\n".join(md))
    print(f"✅ 已生成: {outpath}")
    print(f"   目录 {root.agg_dirs:,} | 文件 {root.agg_files:,} | 大小 {human(root.agg_size)} | 未完成标记 {len(markers_hit)}")

if __name__=="__main__":
    main()
