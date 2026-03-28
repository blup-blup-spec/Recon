#!/usr/bin/env python3
# main.py — RECON OPERATOR v3  (Linux / nmap + intelligence edition)
# pip install PyQt6 python-nmap
# sudo apt install nmap whois dnsutils

import sys, os
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QSplitter, QGroupBox, QDoubleSpinBox, QComboBox,
    QProgressBar, QTabWidget, QFileDialog, QHeaderView, QFrame,
    QCheckBox, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont, QTextCursor

C = {
    "bg":"#07090c","surface":"#0c1118","panel":"#0f1520",
    "border":"#1c2d3d","border2":"#253545",
    "amber":"#e8a020","amber_dim":"#7a5010","amber_glow":"#f0b840",
    "green":"#3ddc84","green_dim":"#1a5c38",
    "red":"#e03030","red_dim":"#5c1010",
    "orange":"#e06020","yellow":"#d4c020",
    "blue":"#2080d0","blue_dim":"#0a2848",
    "text":"#b8c8d8","text_dim":"#3a5060","text_bright":"#d8ecf8",
    "cyan":"#20c0c0",
}
RISK_COL={"CRITICAL":"#e03030","HIGH":"#e06020","MEDIUM":"#d4c020","LOW":"#3ddc84"}
TRIAGE_COL={"PRIMARY":"#e03030","SECONDARY":"#e06020","TERTIARY":"#d4c020","SKIP":"#3a5060"}

SS=f"""
*{{font-family:'Courier Prime','Courier New','DejaVu Sans Mono',monospace;font-size:12px;color:{C['text']};}}
QMainWindow,QWidget{{background:{C['bg']};}}
QGroupBox{{border:1px solid {C['border']};border-top:2px solid {C['amber_dim']};border-radius:0px;margin-top:14px;padding:10px 8px 8px 8px;background:{C['surface']};}}
QGroupBox::title{{subcontrol-origin:margin;left:8px;padding:0 6px;color:{C['amber']};font-size:10px;letter-spacing:3px;background:{C['surface']};}}
QLineEdit,QDoubleSpinBox,QComboBox{{background:{C['bg']};border:1px solid {C['border']};border-radius:0;color:{C['amber_glow']};padding:5px 8px;}}
QLineEdit:focus,QComboBox:focus{{border:1px solid {C['amber']};}}
QComboBox::drop-down{{border:none;width:20px;}}
QComboBox QAbstractItemView{{background:{C['surface']};color:{C['amber_glow']};selection-background-color:{C['amber_dim']};}}
QDoubleSpinBox::up-button,QDoubleSpinBox::down-button{{background:{C['border']};border:none;width:16px;}}
QPushButton{{background:{C['surface']};color:{C['text']};border:1px solid {C['border2']};border-radius:0;padding:7px 16px;letter-spacing:1px;font-size:11px;}}
QPushButton:hover{{background:#16212e;border-color:{C['amber_dim']};color:{C['amber']};}}
QPushButton#execBtn{{background:#0a1a0a;color:{C['green']};border:1px solid {C['green_dim']};font-size:12px;letter-spacing:3px;padding:10px;font-weight:bold;}}
QPushButton#execBtn:hover{{background:#0f2a0f;border-color:{C['green']};}}
QPushButton#execBtn:disabled{{color:{C['green_dim']};border-color:#0d1e0d;background:#080e08;}}
QPushButton#deepBtn{{background:#1a0a00;color:{C['orange']};border:1px solid #7a3010;font-size:11px;letter-spacing:2px;padding:7px;}}
QPushButton#deepBtn:hover{{background:#2a1500;border-color:{C['orange']};}}
QPushButton#deepBtn:disabled{{color:#3a1800;border-color:#1a0800;background:#0e0800;}}
QPushButton#abortBtn{{background:{C['red_dim']};color:{C['red']};border:1px solid #7a1010;letter-spacing:3px;}}
QPushButton#abortBtn:hover{{background:#3c0808;}}
QPushButton#abortBtn:disabled{{background:#0e0808;color:#3a1010;border-color:#1a0808;}}
QTableWidget{{background:{C['bg']};border:1px solid {C['border']};gridline-color:#111d28;color:{C['text']};selection-background-color:#152030;alternate-background-color:#0a0f16;}}
QTableWidget::item{{padding:3px 8px;border:none;}}
QHeaderView::section{{background:{C['panel']};color:{C['amber']};border:none;border-right:1px solid {C['border']};border-bottom:1px solid {C['border']};padding:5px 10px;font-size:10px;letter-spacing:2px;}}
QTextEdit{{background:{C['bg']};border:1px solid {C['border']};color:#40c070;font-size:11px;}}
QProgressBar{{background:{C['bg']};border:1px solid {C['border']};border-radius:0;height:6px;color:transparent;}}
QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C['green_dim']},stop:1 {C['green']});}}
QTabWidget::pane{{border:1px solid {C['border']};background:{C['surface']};top:-1px;}}
QTabBar::tab{{background:{C['bg']};color:{C['text_dim']};border:1px solid {C['border']};border-bottom:none;padding:6px 20px;margin-right:2px;font-size:10px;letter-spacing:2px;}}
QTabBar::tab:selected{{background:{C['surface']};color:{C['amber']};border-top:2px solid {C['amber']};}}
QScrollBar:vertical{{background:{C['bg']};width:5px;border:none;}}
QScrollBar::handle:vertical{{background:{C['border2']};min-height:20px;}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
QScrollBar:horizontal{{background:{C['bg']};height:5px;border:none;}}
QScrollBar::handle:horizontal{{background:{C['border2']};}}
QCheckBox{{color:{C['text']};spacing:6px;}}
QCheckBox::indicator{{width:12px;height:12px;border:1px solid {C['border2']};background:{C['bg']};border-radius:0;}}
QCheckBox::indicator:checked{{background:{C['amber']};border-color:{C['amber']};}}
QSplitter::handle{{background:{C['border']};}}
"""

# ── Workers ────────────────────────────────────────────────────────────────────
class ScanWorker(QThread):
    log=pyqtSignal(str); port_found=pyqtSignal(str,dict); ping_result=pyqtSignal(str,bool)
    progress=pyqtSignal(int,int); status_msg=pyqtSignal(str); host_triage=pyqtSignal(str,dict)
    intel_result=pyqtSignal(str,str,object); ids_warning=pyqtSignal(str)
    suggest_pn=pyqtSignal(); finished=pyqtSignal(dict,dict)

    def __init__(self,cfg):
        super().__init__(); self.cfg=cfg; self._stop=False
    def stop(self): self._stop=True

    def run(self):
        from core.scanner import ping_sweep,scan_host,get_os_info,nmap_available
        from core.discovery import discover_host
        from core.intel import score_host,check_banner_cves,get_nonstandard_hint
        from core.dns_intel import full_dns_enum,grab_tls_cert,grab_http_intel
        from utils.cidr import expand_target
        from utils.reporter import generate_markdown,save_report

        cfg=self.cfg; start_time=datetime.now()
        if not nmap_available():
            self.log.emit("[ERR] nmap not found — sudo apt install nmap"); return

        self.log.emit(f"[SYS] TARGET   : {cfg['target']}")
        self.log.emit(f"[SYS] TIMING   : {cfg['timing']}")
        self.log.emit(f"[SYS] -Pn MODE : {'YES' if cfg['force_pn'] else 'NO (auto-fallback)'}")
        self.log.emit(f"[SYS] STEALTH  : {'YES (SYN)' if cfg['stealth'] else 'NO (TCP connect)'}")
        self.log.emit("[---] ─────────────────────────────────────")

        try: ip_list=expand_target(cfg["target"])
        except ValueError as e: self.log.emit(f"[ERR] {e}"); return

        self.log.emit(f"[SYS] RANGE SIZE : {len(ip_list)} addresses")
        self.status_msg.emit("PING SWEEP")
        self.log.emit("[>>>] PHASE 1 — PING SWEEP")

        def ping_cb(ip,is_up,done,total):
            self.log.emit(f"  {'UP  ' if is_up else 'DOWN'} {ip}")
            self.ping_result.emit(ip,is_up); self.progress.emit(done,total)

        try:
            sweep=ping_sweep(cfg["target"],timeout=int(cfg["timeout"]),
                             force_pn=cfg["force_pn"],progress_cb=ping_cb,
                             stop_flag=lambda:self._stop)
        except RuntimeError as e: self.log.emit(f"[ERR] {e}"); return

        alive=sweep["alive"]
        self.log.emit(f"[---] ALIVE : {len(alive)} / {len(ip_list)}")

        if not alive and sweep.get("suggested_pn") and not cfg["force_pn"]:
            self.log.emit("[!] 0 hosts responded to ping — target may filter ICMP")
            self.log.emit("[!] Suggest: enable -Pn and re-scan")
            self.suggest_pn.emit()
            self.finished.emit({},{"target":cfg["target"],"start_time":start_time,
                "end_time":datetime.now(),"total_hosts":len(ip_list),"alive_hosts":0})
            return

        if not alive:
            self.log.emit("[!] No alive hosts.")
            self.finished.emit({},{"target":cfg["target"],"start_time":start_time,
                "end_time":datetime.now(),"total_hosts":len(ip_list),"alive_hosts":0})
            return

        all_results={}; total_hosts=len(alive); prev_open=0; ids_ctr=0

        for idx,ip in enumerate(alive):
            if self._stop: break
            self.status_msg.emit(f"SCANNING {ip}  [{idx+1}/{total_hosts}]")
            self.log.emit(f"\n[>>>] HOST {idx+1}/{total_hosts} — {ip}")
            self.progress.emit(idx,total_hosts)

            disc=discover_host(ip)
            if disc["hostname"]: self.log.emit(f"      HOSTNAME : {disc['hostname']}")
            os_info=get_os_info(ip)
            self.log.emit(f"      OS       : {os_info}")
            self.log.emit(f"      SCANNING VULN PORTS...")

            try:
                open_ports=scan_host(ip=ip,stealth=cfg["stealth"],timing=cfg["timing"],
                                     delay=cfg["delay"],stop_flag=lambda:self._stop)
            except RuntimeError as e:
                self.log.emit(f"      [ERR] {e}"); open_ports=[]

            # IDS detection
            if idx>0 and prev_open>3 and len(open_ports)==0:
                ids_ctr+=1
                if ids_ctr>=2: self.ids_warning.emit(ip); self.log.emit(f"[!!!] IDS WARNING — responses dropped")
            else: ids_ctr=0
            prev_open=len(open_ports)

            self.log.emit(f"      OPEN PORTS : {len(open_ports)}")
            for p in sorted(open_ports,key=lambda x:x["port"]):
                ns=get_nonstandard_hint(p["port"])
                if ns["is_nonstandard"]:
                    p["nonstandard_hint"]=ns["hint"]; p["likely_service"]=ns["likely_service"]
                    self.log.emit(f"      [NS-PORT] {p['port']} → likely {ns['likely_service']} — {ns['hint']}")
                else:
                    self.log.emit(f"      [{p['risk']:<8}] {p['port']:<6} {p['service']:<16} {p.get('banner','')}")
                if p.get("tcpwrapped"):
                    self.log.emit(f"      [WRAPPED] {p['port']} — manual: nc -v {ip} {p['port']}")
                if cfg.get("run_cve",True):
                    cves=check_banner_cves(p.get("banner",""),p.get("service",""))
                    if cves:
                        p["cves"]=cves
                        for c in cves: self.log.emit(f"      [CVE] {c['cve']} — {c['desc']} [{c['severity']}]")
                self.port_found.emit(ip,p)

            triage=score_host(open_ports)
            self.log.emit(f"      TRIAGE : {triage['score']}/100 — {triage['label']}")
            for w in triage["warnings"]: self.log.emit(f"      [WARN] {w}")
            self.host_triage.emit(ip,triage)

            port_nums={p["port"] for p in open_ports}

            if cfg.get("run_dns",True):
                target_dns=disc.get("hostname") or ip
                if "." in target_dns:
                    self.log.emit(f"      [DNS] Enumerating {target_dns}...")
                    dns_data=full_dns_enum(target_dns)
                    for note in dns_data.get("interesting",[]): self.log.emit(f"      [DNS] {note}")
                    self.intel_result.emit(ip,"dns",dns_data)

            for tls_port in [443,8443,465,993,995]:
                if tls_port in port_nums:
                    self.log.emit(f"      [TLS] Cert on port {tls_port}...")
                    cert=grab_tls_cert(ip,tls_port)
                    for note in cert.get("interesting",[]): self.log.emit(f"      [TLS] {note}")
                    self.intel_result.emit(ip,f"tls_{tls_port}",cert)
                    break

            for http_port,use_ssl in [(80,False),(8080,False),(443,True),(8443,True),(8000,False),(8888,False)]:
                if http_port in port_nums:
                    self.log.emit(f"      [HTTP] Probing {http_port}...")
                    hd=grab_http_intel(ip,http_port,use_ssl)
                    if hd.get("title"): self.log.emit(f"      [HTTP] Title: {hd['title']}")
                    if hd.get("server"): self.log.emit(f"      [HTTP] Server: {hd['server']}")
                    for note in hd.get("interesting",[]): self.log.emit(f"      [HTTP] {note}")
                    self.intel_result.emit(ip,f"http_{http_port}",hd)
                    break

            all_results[ip]={"discovery":disc,"os":os_info,"open_ports":open_ports,"triage":triage}

        meta={"target":cfg["target"],"start_time":start_time,"end_time":datetime.now(),
              "total_hosts":len(ip_list),"alive_hosts":len(alive)}
        md_text=""
        from utils.reporter import generate_markdown,save_report
        md_text=generate_markdown(all_results,meta)
        if cfg.get("obsidian_dir"):
            path=save_report(md_text,cfg["obsidian_dir"],cfg["target"])
            self.log.emit(f"\n[OK] REPORT → {path}")

        self.progress.emit(total_hosts,total_hosts)
        self.status_msg.emit("COMPLETE")
        self.log.emit("[OK] SCAN COMPLETE")
        self.finished.emit(all_results,meta)


class DeepScanWorker(QThread):
    log=pyqtSignal(str); port_found=pyqtSignal(str,dict); finished=pyqtSignal(str,list)
    def __init__(self,ip,timing,stealth,delay):
        super().__init__(); self.ip=ip; self.timing=timing; self.stealth=stealth
        self.delay=delay; self._stop=False
    def stop(self): self._stop=True
    def run(self):
        from core.scanner import deep_scan_host
        from core.intel import check_banner_cves,get_nonstandard_hint
        self.log.emit(f"\n[>>>] DEEP SCAN — {self.ip} — full -p- (all 65535 ports)")
        self.log.emit(f"      Scanning all ports with --min-rate 5000, ~30-60s...")
        try:
            ports=deep_scan_host(self.ip,self.timing,self.stealth,self.delay,stop_flag=lambda:self._stop)
        except RuntimeError as e:
            self.log.emit(f"[ERR] {e}"); self.finished.emit(self.ip,[]); return
        self.log.emit(f"      COMPLETE — {len(ports)} open ports total")
        for p in sorted(ports,key=lambda x:x["port"]):
            ns=get_nonstandard_hint(p["port"])
            if ns["is_nonstandard"]:
                p["nonstandard_hint"]=ns["hint"]; p["likely_service"]=ns["likely_service"]
                self.log.emit(f"      [NS-PORT] {p['port']} → {ns['likely_service']} — {ns['hint']}")
            else:
                self.log.emit(f"      [{p['risk']:<8}] {p['port']:<6} {p['service']:<16} {p.get('banner','')}")
            cves=check_banner_cves(p.get("banner",""),p.get("service",""))
            if cves:
                p["cves"]=cves
                for c in cves: self.log.emit(f"      [CVE] {c['cve']} — {c['desc']}")
            self.port_found.emit(self.ip,p)
        self.finished.emit(self.ip,ports)


# ── Header ─────────────────────────────────────────────────────────────────────
class HeaderBar(QFrame):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(58)
        self.setStyleSheet(f"background:{C['panel']};border-bottom:1px solid {C['border']};")
        layout=QHBoxLayout(self); layout.setContentsMargins(20,0,20,0)
        left=QVBoxLayout(); left.setSpacing(1)
        title=QLabel("RECON OPERATOR")
        title.setStyleSheet(f"color:{C['amber']};font-size:17px;letter-spacing:5px;font-weight:bold;")
        sub=QLabel("NETWORK INTELLIGENCE SYSTEM  //  v3  //  LINUX")
        sub.setStyleSheet(f"color:{C['text_dim']};font-size:9px;letter-spacing:3px;")
        left.addWidget(title); left.addWidget(sub); layout.addLayout(left); layout.addStretch()
        right=QHBoxLayout(); right.setSpacing(24)
        self._sv=self._ind(right,"STATUS","STANDBY",C["text_dim"])
        self._hv=self._ind(right,"ALIVE","—",C["text_dim"])
        self._pv=self._ind(right,"OPEN PORTS","—",C["text_dim"])
        self._cv=self._ind(right,"CVE HITS","—",C["text_dim"])
        layout.addLayout(right)
        self.ids_lbl=QLabel("  ⚠ IDS DETECTED")
        self.ids_lbl.setStyleSheet(f"color:{C['red']};font-size:11px;letter-spacing:2px;font-weight:bold;")
        self.ids_lbl.hide(); layout.addWidget(self.ids_lbl)

    def _ind(self,p,label,val,col):
        c=QVBoxLayout(); c.setSpacing(1)
        l=QLabel(label); l.setStyleSheet(f"color:{C['text_dim']};font-size:8px;letter-spacing:2px;")
        v=QLabel(val); v.setStyleSheet(f"color:{col};font-size:13px;letter-spacing:1px;font-weight:bold;")
        c.addWidget(l); c.addWidget(v); p.addLayout(c); return v

    def set_status(self,t,col=None):
        self._sv.setText(t)
        self._sv.setStyleSheet(f"color:{col or C['amber']};font-size:13px;font-weight:bold;")
    def set_hosts(self,v):
        self._hv.setText(str(v))
        self._hv.setStyleSheet(f"color:{C['amber_glow']};font-size:13px;font-weight:bold;")
    def set_ports(self,v):
        self._pv.setText(str(v))
        self._pv.setStyleSheet(f"color:{C['red']};font-size:13px;font-weight:bold;")
    def set_cve(self,v):
        self._cv.setText(str(v))
        self._cv.setStyleSheet(f"color:{C['orange']};font-size:13px;font-weight:bold;")
    def show_ids(self): self.ids_lbl.show()
    def hide_ids(self): self.ids_lbl.hide()


# ── Config Panel ───────────────────────────────────────────────────────────────
class ConfigPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedWidth(295)
        self.setStyleSheet(f"background:{C['surface']};border-right:1px solid {C['border']};")
        lv=QVBoxLayout(self); lv.setContentsMargins(12,12,12,12); lv.setSpacing(10)

        tg=QGroupBox("TARGET"); tgl=QVBoxLayout(tg)
        self.target_input=QLineEdit()
        self.target_input.setPlaceholderText("IP / CIDR / domain / range")
        tgl.addWidget(self.target_input); lv.addWidget(tg)

        sc=QGroupBox("SCAN CONFIG"); scl=QVBoxLayout(sc); scl.setSpacing(6)
        r1=QHBoxLayout(); r1.addWidget(QLabel("TIMING "))
        self.timing_combo=QComboBox()
        self.timing_combo.addItems(["T0 — Paranoid","T1 — Sneaky","T2 — Polite","T3 — Normal","T4 — Aggressive"])
        self.timing_combo.setCurrentIndex(2); r1.addWidget(self.timing_combo); scl.addLayout(r1)
        r2=QHBoxLayout(); r2.addWidget(QLabel("DELAY  "))
        self.delay_spin=QDoubleSpinBox(); self.delay_spin.setRange(0,10)
        self.delay_spin.setSingleStep(0.1); self.delay_spin.setValue(0.2); self.delay_spin.setSuffix("s")
        r2.addWidget(self.delay_spin); scl.addLayout(r2)
        r3=QHBoxLayout(); r3.addWidget(QLabel("TIMEOUT"))
        self.timeout_spin=QDoubleSpinBox(); self.timeout_spin.setRange(1,10)
        self.timeout_spin.setValue(2.0); self.timeout_spin.setSuffix("s")
        r3.addWidget(self.timeout_spin); scl.addLayout(r3)
        self.stealth_cb=QCheckBox("SYN STEALTH  (root required)")
        self.stealth_cb.setStyleSheet(f"color:{C['amber']};font-size:10px;letter-spacing:1px;")
        scl.addWidget(self.stealth_cb)
        self.pn_cb=QCheckBox("-Pn  SKIP HOST DISCOVERY")
        self.pn_cb.setStyleSheet(f"color:{C['cyan']};font-size:10px;letter-spacing:1px;")
        scl.addWidget(self.pn_cb); lv.addWidget(sc)

        ig=QGroupBox("INTELLIGENCE"); igl=QVBoxLayout(ig); igl.setSpacing(4)
        self.dns_cb=QCheckBox("DNS enum + zone transfer")
        self.tls_cb=QCheckBox("TLS cert + SAN extraction")
        self.http_cb=QCheckBox("HTTP headers + robots.txt")
        self.cve_cb=QCheckBox("Banner CVE matching")
        for cb in [self.dns_cb,self.tls_cb,self.http_cb,self.cve_cb]:
            cb.setChecked(True); cb.setStyleSheet("font-size:11px;letter-spacing:1px;")
            igl.addWidget(cb)
        lv.addWidget(ig)

        ob=QGroupBox("OBSIDIAN VAULT"); obl=QVBoxLayout(ob)
        self.obs_input=QLineEdit(); self.obs_input.setPlaceholderText("/home/user/vault/Recon/")
        obl.addWidget(self.obs_input)
        browse=QPushButton("BROWSE..."); browse.clicked.connect(self._browse); obl.addWidget(browse)
        lv.addWidget(ob); lv.addStretch()

        div=QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"color:{C['border']};"); lv.addWidget(div)
        self.exec_btn=QPushButton("▶  EXECUTE SCAN"); self.exec_btn.setObjectName("execBtn"); lv.addWidget(self.exec_btn)
        self.deep_btn=QPushButton("⬛  DEEP SCAN  (selected host)"); self.deep_btn.setObjectName("deepBtn")
        self.deep_btn.setEnabled(False); lv.addWidget(self.deep_btn)
        self.abort_btn=QPushButton("■  ABORT"); self.abort_btn.setObjectName("abortBtn")
        self.abort_btn.setEnabled(False); lv.addWidget(self.abort_btn)

    def _browse(self):
        p=QFileDialog.getExistingDirectory(self,"Select Obsidian Folder")
        if p: self.obs_input.setText(p)

    def get_config(self):
        tm={"T0 — Paranoid":"T0","T1 — Sneaky":"T1","T2 — Polite":"T2","T3 — Normal":"T3","T4 — Aggressive":"T4"}
        return {"target":self.target_input.text().strip(),
                "timing":tm.get(self.timing_combo.currentText(),"T2"),
                "delay":self.delay_spin.value(),"timeout":self.timeout_spin.value(),
                "stealth":self.stealth_cb.isChecked(),"force_pn":self.pn_cb.isChecked(),
                "run_dns":self.dns_cb.isChecked(),"run_tls":self.tls_cb.isChecked(),
                "run_http":self.http_cb.isChecked(),"run_cve":self.cve_cb.isChecked(),
                "obsidian_dir":self.obs_input.text().strip() or None}


# ── Results Table ──────────────────────────────────────────────────────────────
class ResultsTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(8)
        self.setHorizontalHeaderLabels(["IP","PORT","SERVICE","VERSION","RISK","TRIAGE","CVE","NS-HINT"])
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(22)
        hdr=self.horizontalHeader()
        modes=[QHeaderView.ResizeMode.ResizeToContents,QHeaderView.ResizeMode.ResizeToContents,
               QHeaderView.ResizeMode.ResizeToContents,QHeaderView.ResizeMode.Stretch,
               QHeaderView.ResizeMode.ResizeToContents,QHeaderView.ResizeMode.ResizeToContents,
               QHeaderView.ResizeMode.ResizeToContents,QHeaderView.ResizeMode.Stretch]
        for i,m in enumerate(modes): hdr.setSectionResizeMode(i,m)

    def add_port(self,ip,p,triage=None):
        row=self.rowCount(); self.insertRow(row)
        risk=p.get("risk","LOW"); rc=QColor(RISK_COL.get(risk,C["text"])); dim=QColor(C["text"])
        tl=triage["label"] if triage else ""
        tc=QColor(TRIAGE_COL.get(triage["priority"] if triage else "TERTIARY",C["text_dim"]))
        cves=p.get("cves",[]); cve_str=cves[0]["cve"] if cves else ""
        ns=p.get("nonstandard_hint","")
        def cell(v,col=None,center=False):
            it=QTableWidgetItem(str(v)); it.setForeground(col or dim)
            if center: it.setTextAlignment(Qt.AlignmentFlag.AlignCenter|Qt.AlignmentFlag.AlignVCenter)
            return it
        self.setItem(row,0,cell(ip,QColor(C["amber_glow"])))
        self.setItem(row,1,cell(p["port"],center=True))
        self.setItem(row,2,cell(p["service"]))
        self.setItem(row,3,cell(p.get("banner","") or ""))
        ri=QTableWidgetItem(risk); ri.setForeground(rc)
        ri.setFont(QFont("Courier New",10,QFont.Weight.Bold))
        ri.setTextAlignment(Qt.AlignmentFlag.AlignCenter|Qt.AlignmentFlag.AlignVCenter)
        self.setItem(row,4,ri)
        ti=QTableWidgetItem(tl); ti.setForeground(tc)
        ti.setTextAlignment(Qt.AlignmentFlag.AlignCenter|Qt.AlignmentFlag.AlignVCenter)
        self.setItem(row,5,ti)
        ci=QTableWidgetItem(cve_str); ci.setForeground(QColor(C["orange"]) if cve_str else dim)
        ci.setTextAlignment(Qt.AlignmentFlag.AlignCenter|Qt.AlignmentFlag.AlignVCenter)
        self.setItem(row,6,ci)
        self.setItem(row,7,cell(ns,QColor(C["cyan"]) if ns else dim))
        self.scrollToBottom()

    def get_selected_ip(self):
        rows=self.selectedItems()
        if rows:
            item=self.item(rows[0].row(),0)
            return item.text() if item else ""
        return ""


# ── Briefing Panel ─────────────────────────────────────────────────────────────
class BriefingPanel(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setStyleSheet(f"background:{C['bg']};border:1px solid {C['border']};color:{C['text_bright']};font-size:12px;")
        self._hosts={}

    def update_host(self,ip,triage,open_ports):
        self._hosts[ip]={"triage":triage,"ports":open_ports}; self._rebuild()

    def _rebuild(self):
        lines=[]
        lines.append(f'<span style="color:{C["amber"]};font-size:14px;letter-spacing:4px;">RECON BRIEFING</span>')
        lines.append(f'<span style="color:{C["text_dim"]};">{"─"*60}</span>'); lines.append("")
        for ip,data in sorted(self._hosts.items(),key=lambda x:x[1]["triage"].get("score",0),reverse=True):
            t=data["triage"]; ports=data["ports"]
            col=TRIAGE_COL.get(t.get("priority","TERTIARY"),C["text_dim"])
            lines.append(f'<span style="color:{col};font-weight:bold;">{t.get("label","")}  {ip}  [{t.get("score",0)}/100]</span>')
            for r in t.get("reasons",[]): lines.append(f'<span style="color:{C["green_dim"]};">  ✓ {r}</span>')
            for w in t.get("warnings",[]): lines.append(f'<span style="color:{C["orange"]};">  ⚠ {w}</span>')
            groups={}
            for p in ports:
                s=p["service"].lower()
                if any(x in s for x in ["ftp","tftp"]): g="FILE TRANSFER"
                elif any(x in s for x in ["ssh","telnet","rdp","vnc"]): g="REMOTE ACCESS"
                elif any(x in s for x in ["http","https","tomcat","nginx","apache"]): g="WEB SURFACE"
                elif any(x in s for x in ["smb","netbios","rpc","ldap"]): g="WINDOWS/AD"
                elif any(x in s for x in ["mysql","postgres","mssql","oracle","mongo","redis","elastic","couch"]): g="DATABASES"
                elif any(x in s for x in ["docker","kubelet","etcd"]): g="CONTAINERS"
                else: g="OTHER"
                groups.setdefault(g,[]).append(p)
            for grp,gp in groups.items():
                lines.append(f'<span style="color:{C["text_dim"]};">  [{grp}]</span>')
                for p in gp:
                    rc=RISK_COL.get(p["risk"],C["text"])
                    ns="  ← NON-STD PORT" if p.get("nonstandard_hint") else ""
                    cv=f"  CVE:{p['cves'][0]['cve']}" if p.get("cves") else ""
                    lines.append(
                        f'<span style="color:{rc};">    {p["port"]:<6} {p["service"]:<14} {p.get("banner","")[:30]}</span>'
                        f'<span style="color:{C["cyan"]};">{ns}</span>'
                        f'<span style="color:{C["orange"]};">{cv}</span>')
            pn={p["port"] for p in ports}
            if 21 in pn: lines.append(f'<span style="color:{C["green"]};">  → ENTRY: ftp {ip}  (try anonymous)</span>')
            for sp in [4445,4446,4447]:
                if sp in pn: lines.append(f'<span style="color:{C["cyan"]};">  → NON-STD SMB: smbclient //{ip}/share -p {sp} -U user</span>'); break
            if 6379 in pn: lines.append(f'<span style="color:{C["red"]};">  → REDIS UNAUTH: redis-cli -h {ip} ping</span>')
            if 9200 in pn: lines.append(f'<span style="color:{C["red"]};">  → ELASTIC UNAUTH: curl http://{ip}:9200/_cat/indices</span>')
            if 2375 in pn: lines.append(f'<span style="color:{C["red"]};">  → DOCKER UNAUTH: docker -H tcp://{ip}:2375 ps</span>')
            lines.append("")
        self.setHtml("<br>".join(lines))


# ── Log Console ────────────────────────────────────────────────────────────────
class LogConsole(QTextEdit):
    def __init__(self):
        super().__init__(); self.setReadOnly(True); self.setFont(QFont("Courier New",11))
    def append_log(self,msg):
        if any(x in msg for x in ["[ERR]","[!!!]"]): col=C["red"]
        elif "[OK]" in msg: col=C["green"]
        elif "[>>>]" in msg: col=C["amber"]
        elif "[SYS]" in msg: col=C["blue"]
        elif "[CVE]" in msg: col=C["orange"]
        elif any(x in msg for x in ["[TLS]","[DNS]","[HTTP]","[NS-PORT]"]): col=C["cyan"]
        elif any(x in msg for x in ["[WARN]","[WRAPPED]"]): col=C["yellow"]
        elif "CRITICAL" in msg: col=C["red"]
        elif "HIGH" in msg: col=C["orange"]
        elif "MEDIUM" in msg: col=C["yellow"]
        elif "  UP  " in msg: col=C["green"]
        elif "  DOWN" in msg: col=C["text_dim"]
        else: col="#40b060"
        self.append(f'<span style="color:{col};white-space:pre;">{msg}</span>')
        self.moveCursor(QTextCursor.MoveOperation.End)


# ── Main Window ────────────────────────────────────────────────────────────────
class ReconOperator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RECON OPERATOR  //  v3  //  LINUX")
        self.setMinimumSize(1400,860)
        self.worker=None; self.deep_worker=None
        self._results={}; self._meta={}
        self._port_count=0; self._alive_count=0; self._cve_count=0
        self._host_triage={}; self._host_ports={}
        self._setup_ui()
        self._clock=QTimer(); self._clock.timeout.connect(self._tick); self._clock.start(1000)

    def _setup_ui(self):
        central=QWidget(); self.setCentralWidget(central)
        root=QVBoxLayout(central); root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        self.header=HeaderBar(); root.addWidget(self.header)
        ts=QFrame(); ts.setFixedHeight(22)
        ts.setStyleSheet(f"background:{C['bg']};border-bottom:1px solid {C['border']};")
        tsl=QHBoxLayout(ts); tsl.setContentsMargins(20,0,20,0)
        self.ts_lbl=QLabel()
        self.ts_lbl.setStyleSheet(f"color:{C['text_dim']};font-size:9px;letter-spacing:2px;")
        eng=QLabel("ENGINE: nmap + python-nmap  //  INTEL: CVE + DNS + TLS + HTTP")
        eng.setStyleSheet(f"color:{C['text_dim']};font-size:9px;letter-spacing:2px;")
        tsl.addWidget(self.ts_lbl); tsl.addStretch(); tsl.addWidget(eng); root.addWidget(ts)

        body=QHBoxLayout(); body.setContentsMargins(0,0,0,0); body.setSpacing(0)
        self.config=ConfigPanel()
        self.config.exec_btn.clicked.connect(self._start_scan)
        self.config.abort_btn.clicked.connect(self._stop_scan)
        self.config.deep_btn.clicked.connect(self._start_deep_scan)
        body.addWidget(self.config)

        right=QWidget(); rv=QVBoxLayout(right); rv.setContentsMargins(0,0,0,0); rv.setSpacing(0)
        tabs=QTabWidget()

        scan_tab=QWidget(); stl=QVBoxLayout(scan_tab); stl.setContentsMargins(0,0,0,0)
        splitter=QSplitter(Qt.Orientation.Vertical)
        self.results_table=ResultsTable()
        self.results_table.selectionModel().selectionChanged.connect(self._on_row_selected)
        splitter.addWidget(self.results_table)
        bot=QWidget(); bv=QVBoxLayout(bot); bv.setContentsMargins(8,4,8,8); bv.setSpacing(4)
        self.progress=QProgressBar(); self.progress.setValue(0); bv.addWidget(self.progress)
        self.log=LogConsole(); bv.addWidget(self.log)
        splitter.addWidget(bot); splitter.setSizes([520,240]); stl.addWidget(splitter)
        tabs.addTab(scan_tab,"LIVE SCAN")

        brief_tab=QWidget(); bl=QVBoxLayout(brief_tab); bl.setContentsMargins(0,0,0,0)
        self.briefing=BriefingPanel(); bl.addWidget(self.briefing)
        tabs.addTab(brief_tab,"BRIEFING")

        rep_tab=QWidget(); rl=QVBoxLayout(rep_tab); rl.setContentsMargins(8,8,8,8)
        self.report_view=QTextEdit(); self.report_view.setReadOnly(True)
        self.report_view.setPlaceholderText("// REPORT GENERATED POST-SCAN")
        rl.addWidget(self.report_view)
        brw=QHBoxLayout()
        sb=QPushButton("SAVE MARKDOWN"); sb.clicked.connect(self._save_report)
        brw.addWidget(sb); brw.addStretch(); rl.addLayout(brw)
        tabs.addTab(rep_tab,"REPORT")

        rv.addWidget(tabs); body.addWidget(right)
        bw=QWidget(); bw.setLayout(body); root.addWidget(bw)

    def _tick(self):
        self.ts_lbl.setText(f"SYS TIME  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")

    def _on_row_selected(self):
        ip=self.results_table.get_selected_ip()
        self.config.deep_btn.setEnabled(bool(ip) and not self.worker)

    def _start_scan(self):
        cfg=self.config.get_config()
        if not cfg["target"]: self.log.append_log("[ERR] No target."); return
        self.results_table.setRowCount(0); self.log.clear()
        self.progress.setValue(0); self._port_count=0; self._alive_count=0
        self._cve_count=0; self._host_triage={}; self._host_ports={}
        self.header.hide_ids()
        self.worker=ScanWorker(cfg)
        self.worker.log.connect(self.log.append_log)
        self.worker.port_found.connect(self._on_port)
        self.worker.ping_result.connect(self._on_ping)
        self.worker.progress.connect(self._on_progress)
        self.worker.status_msg.connect(lambda m:self.header.set_status(m))
        self.worker.host_triage.connect(self._on_triage)
        self.worker.intel_result.connect(lambda ip,t,d:None)
        self.worker.ids_warning.connect(self._on_ids)
        self.worker.suggest_pn.connect(self._on_suggest_pn)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()
        self.config.exec_btn.setEnabled(False); self.config.abort_btn.setEnabled(True)
        self.config.deep_btn.setEnabled(False); self.header.set_status("SCANNING",C["green"])

    def _start_deep_scan(self):
        ip=self.results_table.get_selected_ip()
        if not ip: return
        cfg=self.config.get_config()
        self.deep_worker=DeepScanWorker(ip,cfg["timing"],cfg["stealth"],cfg["delay"])
        self.deep_worker.log.connect(self.log.append_log)
        self.deep_worker.port_found.connect(lambda i,p:self._on_port(i,p))
        self.deep_worker.finished.connect(self._on_deep_finished)
        self.deep_worker.start()
        self.config.deep_btn.setEnabled(False)
        self.header.set_status(f"DEEP SCAN {ip}",C["orange"])

    def _stop_scan(self):
        if self.worker: self.worker.stop()
        if self.deep_worker: self.deep_worker.stop()
        self._set_idle()

    def _set_idle(self):
        self.config.exec_btn.setEnabled(True); self.config.abort_btn.setEnabled(False)
        self.header.set_status("STANDBY",C["text_dim"])

    def _on_port(self,ip,p):
        triage=self._host_triage.get(ip)
        self.results_table.add_port(ip,p,triage)
        self._port_count+=1; self.header.set_ports(self._port_count)
        if p.get("cves"):
            self._cve_count+=len(p["cves"]); self.header.set_cve(self._cve_count)
        self._host_ports.setdefault(ip,[]).append(p)

    def _on_triage(self,ip,triage):
        self._host_triage[ip]=triage
        self.briefing.update_host(ip,triage,self._host_ports.get(ip,[]))

    def _on_ids(self,ip):
        self.header.show_ids()
        self.log.append_log(f"[!!!] IDS/FIREWALL — responses dropped near {ip}")
        self.log.append_log(f"[!!!] Try: T0/T1 timing, increase delay, or scan manually")

    def _on_suggest_pn(self):
        self.log.append_log("[!] SUGGESTION: Enable -Pn — target filtering ICMP")
        self.config.pn_cb.setChecked(True)

    def _on_ping(self,ip,alive):
        if alive: self._alive_count+=1; self.header.set_hosts(self._alive_count)

    def _on_progress(self,done,total):
        if total>0: self.progress.setValue(int(done/total*100))

    def _on_finished(self,results,meta):
        self._results=results; self._meta=meta; self._set_idle()
        self.progress.setValue(100); self.header.set_status("COMPLETE",C["green"])
        from utils.reporter import generate_markdown
        self.report_view.setPlainText(generate_markdown(results,meta))

    def _on_deep_finished(self,ip,ports):
        self.log.append_log(f"[OK] Deep scan {ip} — {len(ports)} total ports")
        self.config.deep_btn.setEnabled(True); self.header.set_status("COMPLETE",C["green"])

    def _save_report(self):
        md=self.report_view.toPlainText()
        if not md: return
        path,_=QFileDialog.getSaveFileName(self,"Save Report","recon_report.md","Markdown (*.md)")
        if path:
            with open(path,"w") as f: f.write(md)
            self.log.append_log(f"[OK] Saved → {path}")


if __name__=="__main__":
    app=QApplication(sys.argv); app.setStyleSheet(SS)
    win=ReconOperator(); win.show(); sys.exit(app.exec())
