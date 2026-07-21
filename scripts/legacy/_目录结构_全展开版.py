#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
目录结构 · 全展开版（快）
—— 枚举所有文件夹到最深一层；末端文件夹只给几个文件“例子”，不逐个列文件、不算大小。
   因为不 stat 文件大小，只 readdir 目录，所以即使几百万文件也只需几分钟。

用法:
    python3 _目录结构_全展开版.py <文件夹路径> [输出目录]
例:
    python3 ~/Desktop/nas服务器数据结构/_目录结构_全展开版.py /Volumes/语料库项目
"""
import os, sys, datetime, time
sys.setrecursionlimit(200000)

SAMPLE = 3   # 末端文件夹展示几个文件名做例子

_SPIN = "|/-\\"
_p = {"dirs": 0, "files": 0, "last": 0.0, "start": 0.0, "frame": 0, "errs": 0}

def tick(force=False):
    now = time.time()
    if not _p["start"]: _p["start"] = now
    if force or now - _p["last"] >= 0.12:
        _p["last"] = now
        _p["frame"] = (_p["frame"] + 1) % len(_SPIN)
        el = int(now - _p["start"]); mm, ss = divmod(el, 60)
        sys.stderr.write(f"\r  [{_SPIN[_p['frame']]}] 枚举目录中 {mm:02d}:{ss:02d}  已扫文件夹 {_p['dirs']:,} · 见到文件 {_p['files']:,}        ")
        sys.stderr.flush()

class Node:
    __slots__ = ("name", "dirs", "fcount", "samples")
    def __init__(self, name):
        self.name = name; self.dirs = {}; self.fcount = 0; self.samples = []

def scan(path, node):
    try:
        with os.scandir(path) as it:
            entries = list(it)
    except OSError:
        _p["errs"] += 1
        return
    _p["dirs"] += 1
    tick()   # 每进入一个目录就尝试刷新(内部 0.12s 节流, 不会刷屏)
    subdirs = []; files = []
    for e in entries:
        try:
            if e.is_symlink():
                files.append(e.name)          # 软链接当“文件”，不追进去
            elif e.is_dir(follow_symlinks=False):
                subdirs.append(e.name)
            else:
                files.append(e.name)
        except OSError:
            files.append(e.name)
    files.sort()
    _p["files"] += len(files)
    node.fcount = len(files)
    node.samples = files[:SAMPLE]
    for d in sorted(subdirs):
        child = Node(d); node.dirs[d] = child
        scan(os.path.join(path, d), child)

def count_dirs(n):
    return 1 + sum(count_dirs(k) for k in n.dirs.values())

lines = []
def file_note(n, leaf=True):
    if n.fcount == 0: return ""
    ex = "、".join(n.samples)
    more = " …" if n.fcount > SAMPLE else ""
    head = "" if leaf else "另含 "
    return f"   〔{head}{n.fcount} 个文件，例: {ex}{more}〕"

def render(n, prefix):
    items = sorted(n.dirs.items())
    m = len(items)
    for i, (name, ch) in enumerate(items):
        last = (i == m - 1); conn = "└── " if last else "├── "; ext = "    " if last else "│   "
        leaf = (len(ch.dirs) == 0)
        lines.append(prefix + conn + f"📁 {name}/{file_note(ch, leaf)}")
        render(ch, prefix + ext)

def main():
    if len(sys.argv) < 2:
        print("用法: python3 _目录结构_全展开版.py <文件夹路径> [输出目录]"); sys.exit(1)
    target = os.path.abspath(sys.argv[1].rstrip("/"))
    outdir = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(__file__))
    name = os.path.basename(target)
    if not os.path.isdir(target):
        print(f"❌ 不是文件夹或无法访问: {target}")
        print("   若权限问题：系统设置→隐私与安全性→完全磁盘访问权限→给终端授权后重开终端。")
        sys.exit(1)
    os.makedirs(outdir, exist_ok=True)
    print(f"枚举 {target} 的目录结构（不算大小，只列文件夹+文件例子）...")
    root = Node(name)
    scan(target, root)
    tick(force=True); sys.stderr.write("\n"); sys.stderr.flush()

    render(root, "")
    tree = "\n".join(lines)
    total_dirs = count_dirs(root) - 1
    today = datetime.date.today().isoformat()

    md = []
    md.append(f"# {name}");  md.append("")
    md.append(f"> 目录结构解析报告（**全展开·仅结构版**）　·　生成日期：{today}　·　本地生成");  md.append("")
    md.append("## 📌 说明");  md.append("")
    md.append(f"- 枚举**全部文件夹**到最深一层；末端文件夹只给 {SAMPLE} 个**文件例子** + 文件数量，**不逐个列文件、不统计大小**。")
    md.append("- 名称中的 `?`/`�` 表示该文件夹/文件名在磁盘上是**损坏/非 UTF-8 编码**（多为从 Windows/GBK 环境拷入），非本工具问题。")
    md.append("");  md.append("## 📊 概览");  md.append("")
    md.append("| 指标 | 数值 |");  md.append("| --- | --- |")
    md.append(f"| 文件夹总数 | {total_dirs:,} 个 |")
    md.append(f"| 文件总数(仅计数, 未列出) | {_p['files']:,} 个 |")
    md.append("");  md.append("## 🗂 目录结构树（全展开）");  md.append("")
    md.append("```text");  md.append(f"{name}/{file_note(root, len(root.dirs)==0)}");  md.append(tree);  md.append("```");  md.append("")

    outpath = os.path.join(outdir, name + "_目录结构.md")
    with open(outpath, "w", encoding="utf-8", errors="replace") as f:
        f.write("\n".join(md))
    print(f"✅ 已生成: {outpath}")
    print(f"   文件夹 {total_dirs:,} 个 · 文件 {_p['files']:,} 个" + (f" · 跳过{_p['errs']}处不可读" if _p['errs'] else ""))

if __name__ == "__main__":
    main()
