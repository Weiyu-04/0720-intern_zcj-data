#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
目录结构 · 快速版【v3 · 抗掉线 + 防覆盖 + 断点续扫】
================================================================
为什么有 v3：SMB 网络盘(//hmy@192.168.0.102/ 挂在 /Volumes/<项目>)在长时间扫描中会
反复掉线。掉线瞬间, 对“确实存在的目录”执行 os.scandir 会返回 errno 2(ENOENT)。旧版把这类
ENOENT 当成“该目录持久不可读”并提前 return, 于是每个顶层目录一失败就整棵子树被砍
——2026-07-13 一次扫描 268 万文件塌成 43 万(20,809→677 文件夹), 且用固定文件名把上次
2.5 小时的好结果静默覆盖、不可恢复。

v3 三大硬化(均来自事故复盘):
  1) 抗掉线 + 抗僵死: scandir 失败时先探“卷根还健不健康”, 用它给 ENOENT 消歧。判为掉线就
     【阻塞等重连、重连后重读同一目录】, 永不因掉线丢子树; 只有“卷健康但此目录仍读不了”
     (真删/坏名/权限)才记入不可读清单。
     另: 一个目录的【全部网络 I/O】跑在受监视的子线程里 —— SMB 僵死(syscall 发出去再不返回,
     进程进 U 态、连 Ctrl-C 都杀不掉)时主流程能靠轮询脱身。卡住后先问卷根: 卷健康说明只是
     目录大/慢 → 继续等并打印心跳(绝不误杀慢目录); 卷也不响应 → 判僵死 → 按掉线等重连。
  2) 防覆盖 + 灾难守卫: 写前无条件带时间戳备份 + 原子写(os.replace)。若本次比历史高水位
     骤降(<50%)、或有【顶层目录】不可读、或扫描目标已消失 → 判为疑似不完整, 大声告警并
     改写 <名字>_目录结构.SUSPECT-时间戳.md, 【绝不覆盖】既有好结果。
  3) 断点续扫: 以 JSON 树(<名字>_树状态.json)为持久状态, markdown 只是它的投影。续扫时
     只重扫标 unreadable 的子树并原地合并回树, 而非从头重扫整盘。

另含审计修复: is_dir() 抛错不再被静默当文件(抗掉线); “文件堆”启发式抽验防把成堆同名
子文件夹误判为文件; 概览总数从树现算; 深树用大栈线程跑防段错误; 清单解析容 CRLF。

用法:
  # 全量扫描(生成 md + 不可读清单 + 树状态 json):
  python3 _目录结构_快速版_v3.py <文件夹路径> [输出目录]

  # 彻底模式(任何命令都能加): 关掉"文件堆"抽样快捷方式, 逐个核实每一项。
  # 默认的抽样是概率性的 —— 大堆文件里混着极少数同后缀的【文件夹】时仍可能漏判,
  # 且漏掉的没有任何告警。--thorough 杜绝此漏判, 代价是网络盘上可能明显更慢。
  python3 _目录结构_快速版_v3.py <文件夹路径> --thorough

  # 断点续扫(只重扫失败子树, 合并回主结构):
  python3 _目录结构_快速版_v3.py --resume <名字>_树状态.json [输出目录]

  # 播种历史高水位基线(灾难守卫用; 事故后建议先跑一次把已知好数据写进去):
  python3 _目录结构_快速版_v3.py --seed-baseline <名字> <文件夹数> <文件数> [输出目录]
  # 例: python3 _目录结构_快速版_v3.py --seed-baseline 语料库项目 20809 2686040

  # 只读复查(快速看清单里的目录现在能不能读; 不重建子树, 恢复请用 --resume):
  python3 _目录结构_快速版_v3.py --recheck <不可读清单.txt> [输出目录]

  # 输出目录务必落本地磁盘(默认脚本所在的 Desktop 目录), 别写到 SMB 盘上。
"""
import os, sys, json, time, errno, shutil, datetime, threading

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_NAME = os.path.basename(__file__)

# ---------------- 可调参数 ----------------
SAMPLE = 3
PILE = 30              # 同一扩展名出现 > 此次数 → 视为“文件堆”, 抽样核实后略过逐个核实
PILE_SAMPLE_CAP = 32  # 每个文件堆【跨堆均匀抽样】核实的上限条目数(防成堆同名文件夹被当文件)
STAT_CAP = 120000     # 单目录核实上限(防陌生格式海量堆积)
FANOUT = 120000       # 子文件夹上限(防病态结构)
RECHECK = 3           # scandir/stat 短重试次数(抗真瞬时抖动)
RECHECK_SLEEP = 0.35
PROBE_TIMEOUT = 8.0   # 卷健康探测的超时(僵死挂载会卡死 syscall, 超时即判不健康)
SCANDIR_POLL = 2.0        # 轮询"读目录子线程"的间隔(也决定僵死时 Ctrl-C 多久能响应)
SCANDIR_SLOW_AFTER = 20.0 # 一个目录读超过这么久 → 开始判别"大目录慢" vs "挂载僵死"
WEDGE_PROBE_EVERY = 10.0  # 上述判别的探测间隔(卷健康就继续等, 不健康才判僵死)
WEDGE_CONFIRM = 3         # 连续这么多次探测都不健康才判僵死。单次失败很可能是【假阴性】——
                          # 巨量枚举把 SMB 连接占满, 健康探测被挤超时, 其实卷是好的。
                          # 只凭一次就判僵死会把已经读了几十分钟的大目录白白作废。
DIR_BUDGET = 900.0        # 单个目录的总耗时预算(秒, 含各次重试)。超了就放弃它并明确标注,
                          # 防止一个病态大目录(如百万级视频抽帧)把整盘扫描无限期卡住。
# ↓↓ 枚举上限: 本工具的目的是【目录结构】, 不是精确文件计数。一个目录里堆着几十万个视频帧
#    时, 把每一帧都枚举出来既耗尽时间又会拖垮 SMB 连接, 换来的却只是一个更精确的数字 ——
#    不划算。读到上限就截断, 记成"超大目录, ≥N 项", 结构照样有, 代价封顶。
ENUM_CAP = 50000          # 单目录最多枚举这么多项, 超了截断
ENUM_TIME_CAP = 120.0     # 单目录枚举最多花这么久(秒), 超了截断
ENUM_TIME_CHECK = 1024    # 每枚举这么多项检查一次耗时(免得每项都调 time)
REMOUNT_INTERVAL = 5.0
REMOUNT_MAX_WAIT = 1800   # 掉线最长等待(秒), 30 分钟; 设 0 = 无限等到 Ctrl-C
REMOUNT_STABLE = 2    # 连续几次探测健康才认定“已稳定重连”
MAX_REMOUNT_CYCLES = 4  # 同一目录“等到重连仍读不了”达此轮数 → 判该目录持久不可读(防死循环)
GUARD_RATIO = 0.5     # 本次 < 高水位 * 此比例 → 判疑似不完整
RECURSION_STACK = 256 * 1024 * 1024
sys.setrecursionlimit(120000)   # 与 256MB 大栈匹配(在大栈线程里跑递归)

KNOWN_FILE_EXTS = {
    "json","jsonl","txt","csv","tsv","md","xml","yaml","yml","log","ini","cfg","toml","conf","properties","srt","vtt","ass","sub",
    "pdf","doc","docx","xls","xlsx","ppt","pptx","wps","caj","ofd","rtf","pages","numbers","key","epub","mobi","tex","odt","ods",
    "jpg","jpeg","png","bmp","gif","tif","tiff","webp","svg","ico","heic","heif","raw","dng","cr2","nef","arw","exr","hdr","pgm","ppm","pnm","psd","ai",
    "mp4","avi","mov","mkv","flv","wmv","m4v","mpg","mpeg","ts","webm","3gp","m2ts","mts","vob","rmvb","asf",
    "mp3","wav","flac","aac","m4a","ogg","amr","opus","aiff","wma","ape","m4b","mid",
    "zip","tar","gz","7z","rar","bz2","xz","tgz","iso","dmg","cab","lz","lzma","zst","z","gzip",
    "pcd","ply","bin","las","laz","e57","obj","stl","off","xyz","pts","pcap","bag","rosbag","mcap","fbx","glb","gltf",
    "npy","npz","mat","pkl","pickle","h5","hdf5","pt","pth","ckpt","onnx","pb","safetensors","tfrecord","parquet","arrow","feather","model","weights","joblib",
    "shp","shx","dbf","geojson","kml","kmz","gpx","dcm","nii","nrrd","mha","vtk","tfw","prj",
    "py","ipynb","sh","c","cpp","cc","h","hpp","java","js","ts","tsx","jsx","html","htm","css","sql","bat","go","rs","rb","php","r","jl","scala","kt","swift","lua","pl","vue","m","asm","cs",
    "exe","dll","db","db3","sqlite","mdb","accdb","bak","old","dat","dwg","dxf",
    "ds_store","downloading","aria2","ghost","part","crdownload","tmp","lock","action","0000",
}

def ext_of(nm):
    if nm.startswith("~$"): return "~$"
    d = nm.rfind(".")
    return nm[d+1:].lower() if d > 0 else ""

def merge_warn(w, extra):
    return (w + "; " + extra) if w else extra

def _now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")

def _stamp():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

# ---------------- 进度显示 ----------------
_SPIN = "|/-\\"
_p = {"dirs": 0, "files": 0, "folders": 0, "last": 0.0, "start": 0.0, "frame": 0,
      "warn": 0, "unread": 0, "remounts": 0, "skipped": 0, "truncated": 0}
_ABORT = threading.Event()   # Ctrl-C 时置位; scan 见到即快速收敛并把未扫处标为可续扫
THOROUGH = False             # --thorough: 关掉"文件堆"抽样快捷方式, 逐个核实每一项(准, 但可能慢)
SKIP_PATHS = set()           # --skip <路径>: 不进去枚举的目录(病态大目录), 会在树里明确标注

def tick(force=False):
    now = time.time()
    if not _p["start"]: _p["start"] = now
    if force or now - _p["last"] >= 0.12:
        _p["last"] = now
        _p["frame"] = (_p["frame"] + 1) % len(_SPIN)
        el = int(now - _p["start"]); mm, ss = divmod(el, 60)
        sys.stderr.write(f"\r  [{_SPIN[_p['frame']]}] 枚举中 {mm:02d}:{ss:02d}  已读目录 {_p['dirs']:,} · "
                         f"找到文件夹 {_p['folders']:,} · 见到文件 {_p['files']:,} · "
                         f"不可读 {_p['unread']:,} · 掉线重连 {_p['remounts']}        ")
        sys.stderr.flush()

# ================= 抗掉线核心 (Task A) =================
def volume_root_of(path):
    """从任意扫描路径推出 SMB 卷根: /Volumes/<卷名>。"""
    parts = os.path.abspath(path).split(os.sep)      # ['', 'Volumes', '语料库项目', ...]
    if len(parts) >= 3 and parts[1] == "Volumes":
        return os.sep + os.path.join(parts[1], parts[2])
    return os.sep

def _run_with_timeout(fn, timeout):
    """在 daemon 子线程里跑 fn, 超时不把主流程一起挂死。返回 ('ok',值)/('err',异常)/('hang',None)。"""
    box = {}
    def worker():
        try: box["ok"] = fn()
        except BaseException as e: box["err"] = e
    t = threading.Thread(target=worker, daemon=True)
    try:
        t.start()
    except RuntimeError:
        return "hang", None          # 线程耗尽等极端情况 → 当探测失败, 别掀翻主流程
    t.join(timeout)
    if t.is_alive(): return "hang", None
    if "err" in box: return "err", box["err"]
    return "ok", box.get("ok")

class VolHealth:
    """卷健康探测: ismount + st_dev 指纹 + 能读到已知顶层子项, 全部带超时。"""
    def __init__(self, vol_root, probe_timeout=PROBE_TIMEOUT):
        self.root = vol_root; self.timeout = probe_timeout
        self.dev = None; self.known_top = set()

    def snapshot(self):
        try:
            self.dev = os.stat(self.root).st_dev
            self.known_top = {e.name for e in os.scandir(self.root)}
        except OSError:
            self.dev = None; self.known_top = set()

    def _probe(self):
        if not os.path.ismount(self.root):
            return False
        if self.dev is not None and os.stat(self.root).st_dev != self.dev:
            return False                                   # 防残留同名本地空壳冒充
        names = {e.name for e in os.scandir(self.root)}
        if not names:
            return False
        if self.known_top and not (names & self.known_top):
            return False
        return True

    def healthy(self):
        state, val = _run_with_timeout(self._probe, self.timeout)
        return bool(val) if state == "ok" else False       # hang/err 一律判不健康

# errno 分类
PERSISTENT = {errno.EACCES, errno.EPERM, errno.ENAMETOOLONG, errno.ELOOP, errno.ENOTDIR}
HARD_DOWN  = {errno.ENOTCONN, errno.ECONNRESET, errno.EPIPE,
              errno.EHOSTDOWN, errno.EHOSTUNREACH, errno.ENETDOWN, errno.ENETUNREACH}
# EIO/ESTALE/ETIMEDOUT/EAGAIN 与 ENOENT/未知: 既可能是“该目录自身坏”也可能是“整卷掉线”,
# 一律靠卷根健康探测裁决 —— 卷健康则判该目录持久坏(不空等, 防死循环); 卷不健康才判掉线。

def classify(ex, vol):
    """persistent = 该目录自身问题(短重试/空等都无意义); dropout = 挂载掉线(应等重连)。"""
    e = getattr(ex, "errno", None)
    if e in PERSISTENT: return "persistent"
    if e in HARD_DOWN:  return "dropout"     # 连接级错误: 无疑是掉线, 等重连
    return "persistent" if vol.healthy() else "dropout"

def wait_for_remount(vol):
    """阻塞等挂载恢复。参数在调用时读全局(便于运行时调/测试), 不用默认参数固化。
       等待期间会响应中断标志 —— 否则僵死时 Ctrl-C 卡在这里, 收尾会脏。"""
    interval = REMOUNT_INTERVAL; max_wait = REMOUNT_MAX_WAIT; stable = REMOUNT_STABLE
    start = time.time(); good = 0
    sys.stderr.write("\n  ⚠ 检测到挂载掉线/僵死, 开始等待重连...(Ctrl-C 可中断并存可续扫快照)\n"); sys.stderr.flush()
    while True:
        if _ABORT.is_set():
            sys.stderr.write("\r  ⚠ 等待中收到中断, 停止等待。                         \n")
            sys.stderr.flush(); return False
        if vol.healthy():
            good += 1
            if good >= stable:
                el = int(time.time() - start)
                sys.stderr.write(f"\r  ✓ 已重连(等待 {el//60:02d}:{el%60:02d}), 继续扫描                 \n")
                sys.stderr.flush(); vol.snapshot(); _p["remounts"] += 1; return True
        else:
            good = 0
        el = int(time.time() - start)
        if max_wait and el >= max_wait:
            sys.stderr.write(f"\r  ✗ 等待 {max_wait}s 仍未重连, 暂放弃此目录(可稍后 --resume 续扫)。\n")
            sys.stderr.flush(); return False
        sys.stderr.write(f"\r  ...等待重连 {el//60:02d}:{el%60:02d} (每 {interval:.0f}s 探一次, Ctrl-C 可停)   ")
        sys.stderr.flush()
        # 分片 sleep, 让中断最多 0.5s 就能被察觉
        slept = 0.0
        while slept < interval:
            if _ABORT.is_set(): break
            time.sleep(min(0.5, interval - slept)); slept += 0.5

def _entry_is_dir_raw(e, full):
    """原始类型判定, 不含任何等待/重试(它跑在受监视子线程里)。
       返回 True/False/None(仅此项判不了)。传输类错误直接抛出, 交外层按掉线/僵死处理整个目录。"""
    try:
        if e.is_symlink():
            return False                       # 符号链接不跟进(防环), 按文件计
        return e.is_dir(follow_symlinks=False)
    except OSError as ex:
        if getattr(ex, "errno", None) in PERSISTENT:
            return None                        # 只是这一项有毛病, 不牵连整个目录
        raise                                  # 其它 → 抛给外层判掉线/僵死

def _read_dir_raw(path):
    """一个目录的【全部网络 I/O】集中在此: scandir + 文件堆抽样 + 逐项类型判定。
       不含等待/重试 —— 它整体跑在受监视的子线程里, 挂载僵死时外层靠轮询脱身。
       返回 payload dict; 失败抛 OSError。"""
    # 增量枚举 + 上限截断。不用 list(it) 一次性物化 —— 那对百万级目录等于自杀:
    # 要么耗尽时间, 要么把 SMB 连接拖垮, 而我们要的只是结构, 不是精确到个位的文件数。
    ents = []; truncated = None
    t0 = time.time()
    with os.scandir(path) as it:
        for e in it:
            ents.append(e)
            if len(ents) >= ENUM_CAP:
                truncated = f"项数达上限 {ENUM_CAP:,}"; break
            if len(ents) % ENUM_TIME_CHECK == 0 and (time.time() - t0) > ENUM_TIME_CAP:
                truncated = f"枚举耗时超过 {ENUM_TIME_CAP:.0f}s"; break
    warns = []
    if truncated:
        warns.append(f"超大目录: {truncated}, 已截断枚举 —— 实际项数更多(此处只统计到已枚举的部分), "
                     f"且上限之后若还有子文件夹则未被列出")
    freq = {}
    for e in ents:
        k = ext_of(e.name); freq[k] = freq.get(k, 0) + 1

    # 文件堆: 跨整堆均匀抽样核实(目录可能扎堆在枚举尾部, 只抽头几个会漏)。
    # ⚠ 抽样是【概率性】的: 大堆里若混着极少数同后缀的文件夹, 抽样仍可能漏掉,
    #    漏掉的文件夹会被当成文件、其子树不展开且【无任何告警】。
    #    要杜绝这种漏判就用 --thorough(逐个核实, 不走抽样快捷方式)。
    pile_exts = set() if THOROUGH else {
        k for k, c in freq.items()
        if c > PILE and k not in ("", "~$") and k in KNOWN_FILE_EXTS}
    trusted = set()
    for k in pile_exts:
        group = [e for e in ents if ext_of(e.name) == k]
        n = len(group)
        picks = min(n, PILE_SAMPLE_CAP)        # 小堆(≤32)全验; 大堆抽 32 个散布样本
        step = max(1, n // picks)
        sample_idx = set(range(0, n, step)); sample_idx.add(n - 1)
        found_dir = False
        for j in sorted(sample_idx):
            if _entry_is_dir_raw(group[j], os.path.join(path, group[j].name)) is not False:
                found_dir = True; break        # 抽到目录(或判不了) → 不信任此堆, 逐个核实
        if found_dir:
            warns.append(f"“{k}”堆疑含同名文件夹, 已逐个核实")
        else:
            trusted.add(k)

    subdirs = []; nfiles = 0; samples = []; stat_count = 0; capped = False
    def as_file(nm):
        nonlocal nfiles
        nfiles += 1
        if len(samples) < SAMPLE: samples.append(nm)
    for e in ents:
        nm = e.name; k = ext_of(nm)
        if k in trusted or k == "~$":
            as_file(nm); continue
        if stat_count >= STAT_CAP:
            if not capped:
                capped = True
                warns.append(f"项过多(核实{STAT_CAP:,}后其余按文件计, 个别文件夹可能未识别)")
            as_file(nm); continue
        stat_count += 1
        full = os.path.join(path, nm)
        r = _entry_is_dir_raw(e, full)
        if r is True:
            subdirs.append(nm); continue
        if r is None:                          # 此项判不了 → 兜底复核一次类型
            try:
                if os.path.isdir(full):
                    subdirs.append(nm); warns.append("个别条目类型判定失败, 已按目录展开")
                else:
                    as_file(nm)                # 确认非目录 → 按文件计, 不污染不可读清单
            except OSError:
                subdirs.append(nm)             # 仍判不了 → 保守当目录, 绝不静默丢子树
                warns.append("个别条目类型判定失败, 已按目录尝试展开")
            continue
        as_file(nm)
    subdirs.sort()
    return {"subdirs": subdirs, "nfiles": nfiles, "samples": samples,
            "warns": list(dict.fromkeys(warns)), "capped": capped,
            "truncated": bool(truncated)}

def _read_dir_watched(path, vol):
    """把一个目录的全部 I/O 丢进 daemon 子线程并轮询 —— 挂载僵死时子线程永不返回,
       但本函数能脱身(线程留给内核, 挂载恢复/强制卸载后它自会退出)。
       返回 ('ok', payload) / ('err', OSError) / ('wedged', None) / ('abort', None)。
       要点: 【超时 ≠ 失败】。卡住后先问卷根 ——
         卷健康  → 只是这个目录大/慢, 继续等并打印心跳(绝不把慢目录误判成坏目录);
         卷不健康/探测也卡住 → 判定僵死, 按掉线处理去等重连。"""
    box = {}
    def worker():
        try: box["v"] = _read_dir_raw(path)
        except BaseException as e: box["e"] = e
    t = threading.Thread(target=worker, daemon=True)
    try:
        t.start()
    except RuntimeError:
        return "wedged", None                  # 线程耗尽等极端情况
    waited = 0.0; last_probe = 0.0; bad_streak = 0
    while True:
        t.join(SCANDIR_POLL)
        if not t.is_alive():
            if "e" in box:
                e = box["e"]
                if isinstance(e, OSError): return "err", e
                raise e                        # 非 OSError = 真 bug, 别吞
            return "ok", box.get("v")
        waited += SCANDIR_POLL
        if _ABORT.is_set():
            return "abort", None               # 僵死时也能 Ctrl-C 脱身
        if waited >= SCANDIR_SLOW_AFTER and (waited - last_probe) >= WEDGE_PROBE_EVERY:
            last_probe = waited
            if vol.healthy():
                bad_streak = 0
                sys.stderr.write(f"\r  ⏳ 大目录读取中 {int(waited)}s (卷正常, 继续等): "
                                 f"{os.path.basename(path)[:34]}          ")
                sys.stderr.flush()
            else:
                bad_streak += 1
                # 单次探测失败很可能是假阴性(巨量枚举占满连接把探测挤超时), 别急着作废长读取
                if bad_streak < WEDGE_CONFIRM:
                    sys.stderr.write(f"\r  ⏳ 大目录读取中 {int(waited)}s (探测失败 {bad_streak}/{WEDGE_CONFIRM}, "
                                     f"暂按连接繁忙处理, 继续等): {os.path.basename(path)[:24]}      ")
                    sys.stderr.flush()
                    continue
                sys.stderr.write(f"\n  ⚠ 读取无响应 {int(waited)}s 且卷根连续 {bad_streak} 次不健康 → 判定挂载僵死: {path}\n")
                sys.stderr.flush()
                return "wedged", None

# ---------------- 节点 ----------------
class Node:
    __slots__ = ("name", "dirs", "subcount", "fcount", "samples", "warn", "unreadable")
    def __init__(self, name):
        self.name = name; self.dirs = {}; self.subcount = 0
        self.fcount = 0; self.samples = []; self.warn = ""; self.unreadable = False

def _mark_unreadable(node, why):
    node.unreadable = True; node.warn = why
    _p["dirs"] += 1; _p["unread"] += 1; tick()

def scan(path, node, depth, vol):
    if _ABORT.is_set():
        node.unreadable = True
        node.warn = "扫描被中断(未展开, 可 --resume 续扫)"
        _p["unread"] += 1; return
    if os.path.abspath(path) in SKIP_PATHS:
        sys.stderr.write(f"\n  ⏭  已按 --skip 跳过(未枚举): {path}\n"); sys.stderr.flush()
        _mark_unreadable(node, "已按 --skip 要求跳过, 未枚举其下内容"); _p["skipped"] += 1; return

    # 读这个目录: 掉线/僵死 → 等重连后整目录重读; 只有“卷健康却仍读不了”才判真不可读
    cycles = 0; tries = 0; payload = None; t_start = time.time()
    while True:
        st, val = _read_dir_watched(path, vol)
        if st == "ok":
            payload = val; break
        if st == "abort":
            node.unreadable = True
            node.warn = "扫描被中断(未展开, 可 --resume 续扫)"
            _p["unread"] += 1; return
        if st == "wedged":
            last = OSError(errno.ETIMEDOUT, "挂载僵死: 读取无响应且卷根不健康")
            decided = "dropout"
        else:                                  # st == "err"
            last = val; decided = classify(val, vol)
        if decided == "persistent":
            tries += 1
            if tries < RECHECK:                # 短重试, 抗真瞬时抖动
                time.sleep(RECHECK_SLEEP * tries); continue
            eno = getattr(last, "errno", "?")
            emsg = (last.strerror or str(last)) if last else "未知错误"
            _mark_unreadable(node, f"不可读(errno {eno}: {emsg}) —— 卷健康但此目录仍读不了"
                                   f"(疑真删/坏名/权限)，其下未纳入"); return
        if not wait_for_remount(vol):
            _mark_unreadable(node, "不可读: 等待重连超时(挂载未恢复, 可稍后 --resume 续扫)"); return
        cycles += 1
        spent = time.time() - t_start
        if spent > DIR_BUDGET:                 # 单目录耗时预算: 防一个病态大目录卡住整盘
            sys.stderr.write(f"\n  ⏭  此目录已耗时 {spent/60:.0f} 分钟仍读不完, 放弃并继续扫其余部分: {path}\n")
            sys.stderr.flush()
            _mark_unreadable(node, f"放弃: 耗时超过 {DIR_BUDGET/60:.0f} 分钟仍枚举不完"
                                   f"(疑目录过大/连接扛不住), 其下未纳入; 可用 --skip 明确排除或单独处理")
            _p["skipped"] += 1; return
        if cycles >= MAX_REMOUNT_CYCLES:       # 反复“重连后仍读不了” → 判持久坏, 防死循环
            sys.stderr.write(f"\n  ⚠ 目录反复读不了(已等重连 {cycles} 轮), 记为不可读: {path}\n")
            _mark_unreadable(node, f"不可读: 重连后仍反复读不了(已试 {cycles} 轮, 可 --resume 再试)"); return
        # 回到 while 顶部: 重连后整个目录重读, 子树完整保留

    _p["dirs"] += 1; tick()
    for w in payload["warns"]:
        node.warn = merge_warn(node.warn, w)
    if payload["capped"]: _p["warn"] += 1
    if payload["truncated"]:
        _p["truncated"] += 1
        sys.stderr.write(f"\n  ⏭  超大目录已截断枚举, 继续扫其余部分: {path}\n"); sys.stderr.flush()
    subdirs = payload["subdirs"]; nfiles = payload["nfiles"]
    node.subcount = len(subdirs); node.fcount = nfiles; node.samples = payload["samples"]
    _p["folders"] += len(subdirs); _p["files"] += nfiles
    if len(subdirs) > FANOUT:
        node.warn = merge_warn(node.warn, "子文件夹过多, 仅列名未深入")
        _p["warn"] += 1
        for d in subdirs: node.dirs[d] = Node(d)
        return
    for d in subdirs:
        child = Node(d); node.dirs[d] = child
        if _ABORT.is_set():        # 中断: 剩余子目录标为未展开(可 --resume 续), 不留“空且看似完整”的洞
            child.unreadable = True
            child.warn = "扫描被中断(未展开, 可 --resume 续扫)"
            _p["unread"] += 1; continue
        scan(os.path.join(path, d), child, depth + 1, vol)

# ---------------- 统计 / 渲染 ----------------
def tree_stats(n):
    """概览总数一律从树现算(resume 时全局 _p 不完整, 不能依赖它)。"""
    folders = 0; files = n.fcount; unread = 1 if n.unreadable else 0
    for ch in n.dirs.values():
        f, fi, u = tree_stats(ch)
        folders += 1 + f; files += fi; unread += u
    return folders, files, unread

def node_tail(n):
    parts = []
    if n.subcount: parts.append(f"{n.subcount} 子目录")
    if n.fcount:
        ex = "、".join(n.samples); more = " …" if n.fcount > SAMPLE else ""
        parts.append(f"{n.fcount:,} 文件(例: {ex}{more})")
    s = ("  〔" + "，".join(parts) + "〕") if parts else ""
    if n.warn: s += f"  〔⚠ {n.warn}〕"
    return s

def build_md(name, root):
    out = []
    def render(n, prefix):
        items = sorted(n.dirs.items())
        m = len(items)
        for i, (nm, ch) in enumerate(items):
            last = (i == m - 1); conn = "└── " if last else "├── "; ext = "    " if last else "│   "
            out.append(prefix + conn + f"📁 {nm}/{node_tail(ch)}")
            render(ch, prefix + ext)
    render(root, "")
    tree = "\n".join(out)
    folders, files, unread = tree_stats(root)
    today = datetime.date.today().isoformat()
    md = [f"# {name}", "",
          f"> 目录结构解析报告（**完整文件夹结构版 · v3 抗掉线**）　·　生成日期：{today}　·　本地生成", "",
          "## 📌 说明", "",
          f"- **列出全部文件夹, 深度到底**；每个文件夹标注「N 子目录 / M 文件」并附 {SAMPLE} 个文件名例子。不算文件大小。",
          f"- 判定逻辑：某常见扩展名在一个目录里出现 >{PILE} 次(成堆文件)先跨堆抽样(至多 {PILE_SAMPLE_CAP} 个)确认无子文件夹混入才略过核实；其余一律核实。",
          f"- 网络盘掉线会自动等待重连后重读，**不因掉线丢子树**；树里标 `⚠ 不可读` 的是“卷健康但仍读不了”的真不可读目录(见 `{name}_不可读清单.txt`)。",
          f"- 本报告目标是**目录结构**，不是精确文件计数：单个目录枚举超过 {ENUM_CAP:,} 项或 {ENUM_TIME_CAP:.0f} 秒即**截断**并标 `⚠ 超大目录`"
          f"（常见于视频抽帧/图片集这类底层堆文件的目录）。此类目录的文件数是**下限**，其下若还有子文件夹也可能未列出。",
          "- 名称里的 `?`/`�` 是磁盘上文件名**编码损坏**(多为 Windows/GBK 拷入)。",
          "", "## 📊 概览", "",
          "| 指标 | 数值 |", "| --- | --- |",
          f"| 文件夹总数 | {folders:,} 个 |",
          f"| 文件总数(计数) | {files:,} 个 |",
          f"| 触发安全上限的目录 | {_p['warn']} 个 |",
          f"| 超大目录(已截断枚举) | {_p['truncated']} 个 |",
          f"| 不可读目录(其下未纳入) | {unread} 个 |",
          "", "## 🗂 文件夹结构树（完整）", "",
          "```text", f"{name}/{node_tail(root)}", tree, "```", ""]
    return "\n".join(md)

# ================= 持久状态 / 防覆盖 (Task B) =================
def _san(s):
    """清洗 GBK 损坏名里的孤立代理字符, 防 json.dump 崩。"""
    return s.encode("utf-8", "replace").decode("utf-8")

def node_to_dict(n):
    d = {"n": _san(n.name), "sc": n.subcount, "fc": n.fcount,
         "s": [_san(x) for x in n.samples], "w": _san(n.warn), "u": n.unreadable}
    if n.dirs:
        d["d"] = {k: node_to_dict(v) for k, v in n.dirs.items()}
    return d

def node_from_dict(d):
    n = Node(d["n"]); n.subcount = d["sc"]; n.fcount = d["fc"]
    n.samples = list(d.get("s", [])); n.warn = d.get("w", ""); n.unreadable = d.get("u", False)
    for k, v in d.get("d", {}).items():
        n.dirs[k] = node_from_dict(v)
    return n

def atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", errors="replace") as f:
        f.write(text); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def load_baseline(outdir, name):
    p = os.path.join(outdir, name + "_树状态.json")
    if os.path.isfile(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    md = os.path.join(outdir, name + "_目录结构.md")   # 回退: grep 旧 md(可能已是坏版)
    if os.path.isfile(md):
        import re
        b = {}
        for ln in open(md, encoding="utf-8", errors="replace"):
            m = re.search(r"文件夹总数\D+([\d,]+)", ln)
            if m: b["hw_folders"] = int(m.group(1).replace(",", ""))
            m = re.search(r"文件总数\D+([\d,]+)", ln)
            if m: b["hw_files"] = int(m.group(1).replace(",", ""))
        if b:
            sys.stderr.write("  ⚠ 基线来自旧 md(可能已是坏版), 建议先 --seed-baseline 播种已知好数据。\n")
            return b
    return None

def save_state(path, target, root, baseline, update_hw):
    folders, files, unread = tree_stats(root)
    prev_hwf = (baseline or {}).get("hw_folders", 0)
    prev_hwfi = (baseline or {}).get("hw_files", 0)
    data = {"target": target, "ts": _now_iso(),
            "folders": folders, "files": files, "unread": unread,
            "hw_folders": max(folders, prev_hwf) if update_hw else prev_hwf,
            "hw_files":   max(files,  prev_hwfi) if update_hw else prev_hwfi,
            "tree": node_to_dict(root)}
    atomic_write(path, json.dumps(data, ensure_ascii=True))

def _exists_safe(path):
    state, val = _run_with_timeout(lambda: os.path.exists(path), PROBE_TIMEOUT)
    return bool(val) if state == "ok" else False

def guard_reasons(root, target, baseline):
    r = []
    if _ABORT.is_set():
        r.append("扫描被用户中断(Ctrl-C), 结果不完整")
    if not _exists_safe(target):
        r.append(f"扫描目标已不存在(挂载疑似掉线): {target}")
    top_bad = [nm for nm, ch in root.dirs.items() if ch.unreadable]
    if top_bad:
        r.append(f"{len(top_bad)} 个【顶层目录】不可读→整棵子树被砍风险: "
                 + "、".join(top_bad[:8]) + ("…" if len(top_bad) > 8 else ""))
    folders, files, _ = tree_stats(root)
    if baseline:
        bf, bfi = baseline.get("hw_folders", 0), baseline.get("hw_files", 0)
        if bf and folders < GUARD_RATIO * bf:
            r.append(f"文件夹数骤降: 本次 {folders:,} < 历史高水位 {bf:,} 的 {GUARD_RATIO:.0%}")
        if bfi and files < GUARD_RATIO * bfi:
            r.append(f"文件数骤降: 本次 {files:,} < 历史高水位 {bfi:,} 的 {GUARD_RATIO:.0%}")
    return r

def safe_write_md(outdir, name, md_text, root, target, baseline):
    """守卫通过 → 备份旧版+原子覆盖+刷新基线; 守卫触发 → 改写 SUSPECT, 绝不覆盖。返回(路径, 是否为正式覆盖)。"""
    canon = os.path.join(outdir, name + "_目录结构.md")
    reasons = guard_reasons(root, target, baseline)
    if reasons:
        stamp = _stamp()
        suspect_md = os.path.join(outdir, f"{name}_目录结构.SUSPECT-{stamp}.md")
        atomic_write(suspect_md, md_text)
        save_state(os.path.join(outdir, f"{name}_树状态.SUSPECT-{stamp}.json"),
                   target, root, baseline, update_hw=False)
        sys.stderr.write("\n" + "=" * 64 + "\n⛔ 灾难性不完整守卫触发——拒绝覆盖既有好结果！\n")
        for x in reasons: sys.stderr.write("   · " + x + "\n")
        sys.stderr.write(f"   本次结果改写到: {suspect_md}\n"
                         f"   既有 {os.path.basename(canon)} 与基线均保持不变。\n"
                         f"   待挂载稳定后, 可用 --resume 上面那个 SUSPECT 的 json 续扫补全。\n"
                         + "=" * 64 + "\n")
        return suspect_md, False
    stamp = _stamp()
    if os.path.isfile(canon):
        os.replace(canon, os.path.join(outdir, f"{name}_目录结构.{stamp}.bak.md"))
    state_path = os.path.join(outdir, name + "_树状态.json")
    if os.path.isfile(state_path):        # 权威 json 也一并带戳备份(与 md 对称, 防守卫误放行时不可回滚)
        try:
            shutil.copy2(state_path, os.path.join(outdir, f"{name}_树状态.{stamp}.bak.json"))
        except OSError:
            pass
    atomic_write(canon, md_text)
    save_state(state_path, target, root, baseline, update_hw=True)
    return canon, True

# ---------------- 不可读清单 ----------------
def iter_unreadable(node, path):
    """yield (完整路径, 真实Node对象)。unreadable 节点必是叶子(scan 遇失败 early-return)。"""
    if node.unreadable:
        yield path, node
    for nm, ch in node.dirs.items():
        yield from iter_unreadable(ch, os.path.join(path, nm))

def write_failed_list(outdir, name, root, target):
    fails = list(iter_unreadable(root, target))
    listpath = os.path.join(outdir, name + "_不可读清单.txt")
    head = [f"# {name} · 不可读目录清单　生成 {_now_iso()}"]
    if not fails:
        head.append("# 本次全部可读 ✅")
        atomic_write(listpath, "\n".join(head) + "\n")
        return listpath, 0
    head += [f"# 共 {len(fails)} 个: “卷健康但仍读不了”的真不可读(疑真删/坏名/权限)。掉线目录不在此列(已等重连补回)。",
             f"# 续扫合并:  python3 {SCRIPT_NAME} --resume {name}_树状态.json",
             "# 格式:  完整路径 <TAB> 原因", "#" + "-" * 70]
    body = [f"{p}\t{nd.warn}" for p, nd in fails]
    atomic_write(listpath, "\n".join(head + body) + "\n")
    return listpath, len(fails)

# ---------------- 大栈线程(防深树段错误) ----------------
def run_deep(fn):
    box = {}
    def worker():
        try: box["v"] = fn()
        except BaseException as e: box["e"] = e
    old = threading.stack_size(RECURSION_STACK)
    try:
        t = threading.Thread(target=worker, daemon=True)
        t.start()
    finally:
        threading.stack_size(old or 0)   # 栈在 start() 时已分配; 立即复位, 后续探测线程用默认小栈
    try:
        while t.is_alive():      # 循环 join 让主线程能接住 Ctrl-C
            t.join(0.5)
    except KeyboardInterrupt:
        _ABORT.set()
        sys.stderr.write("\n⚠ 收到中断(Ctrl-C), 正在收尾已扫部分(标记为可续扫)...\n"); sys.stderr.flush()
        t.join(60)               # worker 见 _ABORT 会在每个 scan 入口快速返回, 很快收敛
    if "e" in box: raise box["e"]
    return box.get("v")

# ================= 各入口 =================
def do_scan(argv):
    target = os.path.abspath(argv[0].rstrip("/"))
    outdir = os.path.abspath(argv[1]) if len(argv) > 1 else SCRIPT_DIR
    name = os.path.basename(target)
    if not os.path.isdir(target):
        print(f"❌ 不是文件夹或无法访问: {target}"); sys.exit(1)
    os.makedirs(outdir, exist_ok=True)
    vol = VolHealth(volume_root_of(target)); vol.snapshot()
    print(f"枚举 {target} 的文件夹结构（v3 抗掉线·防覆盖）...")
    print(f"  卷根: {vol.root}   输出(本地): {outdir}")
    root = Node(name)
    run_deep(lambda: scan(target, root, 0, vol))
    tick(force=True); sys.stderr.write("\n"); sys.stderr.flush()

    baseline = load_baseline(outdir, name)
    md_text = build_md(name, root)
    outpath, ok = safe_write_md(outdir, name, md_text, root, target, baseline)
    listpath, nfail = write_failed_list(outdir, name, root, target)
    folders, files, unread = tree_stats(root)
    print(f"{'✅ 已生成' if ok else '⚠ 疑似不完整, 未覆盖, 另存'}: {outpath}")
    print(f"   文件夹 {folders:,} · 文件 {files:,} · 真不可读 {unread}"
          + (f" · 掉线重连 {_p['remounts']} 次" if _p['remounts'] else "")
          + (f" · 清单 {listpath}" if nfail else " · 全部可读 ✅"))

def do_resume(argv):
    if not argv:
        print("用法: python3 %s --resume <名字>_树状态.json [输出目录]" % SCRIPT_NAME); sys.exit(1)
    state_path = os.path.abspath(argv[0])
    outdir = os.path.abspath(argv[1]) if len(argv) > 1 else os.path.dirname(state_path)
    if not os.path.isfile(state_path):
        print(f"❌ 状态文件不存在: {state_path}"); sys.exit(1)
    st = json.load(open(state_path, encoding="utf-8"))
    target = st["target"]; root = node_from_dict(st["tree"]); name = os.path.basename(target)
    vol = VolHealth(volume_root_of(target)); vol.snapshot()
    todo = list(iter_unreadable(root, target))
    print(f"断点续扫: 目标 {target}\n  {len(todo)} 个不可读子树, 仅重扫这些…")
    if not todo:
        print("  没有不可读子树, 无需续扫。"); return
    counter = {"healed": 0}
    def heal():
        for path, nd in todo:
            nd.unreadable = False; nd.warn = ""; nd.dirs = {}
            nd.subcount = 0; nd.fcount = 0; nd.samples = []
            scan(path, nd, 1, vol)                 # 原地 mutate = 自动 splice 回主树
            if not nd.unreadable: counter["healed"] += 1
    run_deep(heal)
    tick(force=True); sys.stderr.write("\n"); sys.stderr.flush()
    print(f"续扫完成: {counter['healed']}/{len(todo)} 个子树已补回。")

    baseline = load_baseline(outdir, name)
    md_text = build_md(name, root)
    outpath, ok = safe_write_md(outdir, name, md_text, root, target, baseline)
    listpath, nfail = write_failed_list(outdir, name, root, target)
    folders, files, unread = tree_stats(root)
    print(f"{'✅ 已更新' if ok else '⚠ 仍疑不完整, 另存'}: {outpath}")
    print(f"   文件夹 {folders:,} · 文件 {files:,} · 仍不可读 {unread}"
          + (f" · 本轮掉线重连 {_p['remounts']} 次" if _p['remounts'] else ""))
    if nfail:
        print(f"   还剩 {nfail} 个不可读(可再跑一次 --resume, 幂等): {listpath}")

def do_seed_baseline(argv):
    if len(argv) < 3:
        print("用法: python3 %s --seed-baseline <名字> <文件夹数> <文件数> [输出目录]" % SCRIPT_NAME); sys.exit(1)
    name = argv[0]; hwf = int(argv[1]); hwfi = int(argv[2])
    outdir = os.path.abspath(argv[3]) if len(argv) > 3 else SCRIPT_DIR
    os.makedirs(outdir, exist_ok=True)
    p = os.path.join(outdir, name + "_树状态.json")
    prev = {}
    if os.path.isfile(p):
        try: prev = json.load(open(p, encoding="utf-8"))
        except Exception: prev = {}
    prev["hw_folders"] = max(hwf, prev.get("hw_folders", 0))
    prev["hw_files"]   = max(hwfi, prev.get("hw_files", 0))
    prev.setdefault("target", "")
    prev["seed_ts"] = _now_iso()
    atomic_write(p, json.dumps(prev, ensure_ascii=True))
    print(f"✅ 已播种历史高水位基线: {p}")
    print(f"   hw_folders={prev['hw_folders']:,}  hw_files={prev['hw_files']:,}")
    print("   之后任何扫描若显著低于此水位, 灾难守卫会拒绝覆盖。")

def read_list_paths(listpath):
    paths = []
    for ln in open(listpath, "r", encoding="utf-8", errors="replace"):
        ln = ln.rstrip("\r\n")
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        parts = ln.split("\t")
        p = next((x for x in parts if x.startswith("/")), parts[0])  # 容 errno\t原因\t路径 或 路径\t原因
        paths.append(p)
    return paths

def do_recheck(argv):
    if not argv:
        print("用法: python3 %s --recheck <不可读清单.txt> [输出目录]" % SCRIPT_NAME); sys.exit(1)
    listpath = os.path.abspath(argv[0])
    outdir = os.path.abspath(argv[1]) if len(argv) > 1 else os.path.dirname(listpath)
    if not os.path.isfile(listpath):
        print(f"❌ 清单文件不存在: {listpath}"); sys.exit(1)
    paths = read_list_paths(listpath)
    print(f"只读复查 {len(paths)} 个目录(每个短重试 {RECHECK} 次)...")
    ok, still = [], []
    for i, p in enumerate(paths, 1):
        sys.stderr.write(f"\r  复查中 {i}/{len(paths)} · 已读回 {len(ok)} · 仍失败 {len(still)}    "); sys.stderr.flush()
        ents = None; err = None
        for a in range(RECHECK):
            try:
                with os.scandir(p) as it: ents = list(it)
                break
            except OSError as ex:
                err = ex
                if a < RECHECK - 1: time.sleep(RECHECK_SLEEP * (a + 1))
        if ents is None:
            eno = err.errno if err else "?"; emsg = (err.strerror or str(err)) if err else "未知"
            still.append((p, eno, emsg))
        else:
            nsub = sum(1 for e in ents if _safe_isdir(e))
            ok.append((p, nsub, len(ents) - nsub))
    sys.stderr.write("\n"); sys.stderr.flush()

    today = datetime.date.today().isoformat()
    base = os.path.splitext(os.path.basename(listpath))[0]
    report = os.path.join(outdir, base + "_复查结果.md")
    md = ["# 不可读目录复查结果", "",
          f"> 复查日期：{today}　·　来源：`{os.path.basename(listpath)}`　·　共 {len(paths)} 个目录", "",
          "> ⚠ 本复查只验证顶层是否可读, **不重建子树**。要真正把内容补回主结构树请用 `--resume <名字>_树状态.json`。", "",
          "| 指标 | 数值 |", "| --- | --- |",
          f"| 本次已读回 | {len(ok)} 个 |", f"| 仍不可读 | {len(still)} 个 |", ""]
    if ok:
        md += ["## ✅ 已读回（顶层这次能读了）", "", "| 子目录 | 文件 | 路径 |", "| ---: | ---: | --- |"]
        for p, ns, nf in ok: md.append(f"| {ns} | {nf} | `{p}` |")
        md += ["", "> 恢复内容请用 `--resume`(会只重扫这些子树并原子合并、不覆盖好结果), 不要跑会覆盖的全量扫描。", ""]
    if still:
        md += ["## ⚠ 仍不可读（需人工排查或稍后再试）", "", "| errno | 原因 | 路径 |", "| ---: | --- | --- |"]
        for p, eno, emsg in still: md.append(f"| {eno} | {emsg} | `{p}` |")
        md += ["", "常见 errno：`2` 掉线/路径已不存在 · `13` 权限 · `5` I/O(网络或磁盘) · `63` 文件名过长或编码损坏。", ""]
    atomic_write(report, "\n".join(md))
    print(f"✅ 复查完成: 读回 {len(ok)} · 仍失败 {len(still)}\n   报告: {report}")

def _safe_isdir(e):
    try:
        return (not e.is_symlink()) and e.is_dir(follow_symlinks=False)
    except OSError:
        return False

def main():
    global THOROUGH
    args = sys.argv[1:]
    if "--thorough" in args:
        THOROUGH = True; args = [a for a in args if a != "--thorough"]
        print("【彻底模式】已关闭“文件堆”抽样快捷方式, 逐个核实每一项 —— 不会漏判取名像文件的文件夹, 但更慢。")
    while "--skip" in args:                       # 可重复: --skip A --skip B
        i = args.index("--skip")
        if i + 1 >= len(args):
            print("❌ --skip 后面要跟一个目录路径"); sys.exit(1)
        SKIP_PATHS.add(os.path.abspath(args[i + 1].rstrip("/")))
        del args[i:i + 2]
    if SKIP_PATHS:
        print(f"【跳过】以下 {len(SKIP_PATHS)} 个目录不会被枚举(树里会明确标注):")
        for p in sorted(SKIP_PATHS): print("   ⏭ ", p)
    if args and args[0] == "--resume":
        do_resume(args[1:])
    elif args and args[0] == "--recheck":
        do_recheck(args[1:])
    elif args and args[0] == "--seed-baseline":
        do_seed_baseline(args[1:])
    elif args and not args[0].startswith("--"):
        do_scan(args)
    else:
        print("用法:")
        print(f"  全量扫描:  python3 {SCRIPT_NAME} <文件夹路径> [输出目录]")
        print(f"  跳过大坑:  ... --skip <要跳过的目录>   (可重复; 病态大目录枚举不完时用)")
        print(f"  彻底模式:  ... --thorough              (不走文件堆抽样, 逐个核实, 准但慢)")
        print(f"  断点续扫:  python3 {SCRIPT_NAME} --resume <名字>_树状态.json [输出目录]")
        print(f"  播种基线:  python3 {SCRIPT_NAME} --seed-baseline <名字> <文件夹数> <文件数> [输出目录]")
        print(f"  只读复查:  python3 {SCRIPT_NAME} --recheck <不可读清单.txt> [输出目录]")
        sys.exit(1)

if __name__ == "__main__":
    main()
