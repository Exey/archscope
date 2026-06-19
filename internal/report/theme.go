// Package report holds the shared HTML theme (CSS + JS) consumed by the html
// writer. Keeping the theme here, separate from the document assembly in
// report/html, lets the look evolve in one place. The aesthetic is a refined
// "analyzer console": dark-first, data-dense, one accent, monospace for codes
// and metrics, with a light toggle. The output is a single self-contained file
// (no external assets, no network), so the CSS and JS are inlined verbatim.
package report

// Version is the tool version surfaced in the report header and SARIF driver.
const Version = "26.6.18"

// CSS is the full stylesheet, including dark (default) and light themes and the
// class vocabulary emitted by report modules (.as-arch__*, .as-dp__*, etc.).
const CSS = `
:root{
  --bg:#0d1017; --bg-elev:#141925; --bg-elev-2:#1b2230; --bg-inset:#0a0d13;
  --border:#222b3a; --border-strong:#324056;
  --text:#e6edf6; --text-dim:#9aa7ba; --text-faint:#5d6b80;
  --accent:#4ea1ff; --accent-dim:#27466b; --accent-ink:#0a0d13;
  --good:#3fb950; --warn:#d29922; --bad:#f0883e; --crit:#f85149;
  --good-bg:rgba(63,185,80,.12); --warn-bg:rgba(210,153,34,.12);
  --bad-bg:rgba(240,136,62,.12); --crit-bg:rgba(248,81,73,.12);
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --radius:10px; --radius-sm:7px;
}
[data-theme="light"]{
  --bg:#f4f6fa; --bg-elev:#ffffff; --bg-elev-2:#f7f9fc; --bg-inset:#eef1f6;
  --border:#e0e5ee; --border-strong:#c7d0de;
  --text:#16202e; --text-dim:#56657c; --text-faint:#8a97ab;
  --accent:#1f6feb; --accent-dim:#cfe0ff; --accent-ink:#ffffff;
  --good:#1a7f37; --warn:#9a6700; --bad:#bc4c00; --crit:#cf222e;
  --good-bg:rgba(26,127,55,.10); --warn-bg:rgba(154,103,0,.10);
  --bad-bg:rgba(188,76,0,.10); --crit-bg:rgba(207,34,46,.10);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--bg); color:var(--text);
  font-family:var(--sans); font-size:14px; line-height:1.55;
  -webkit-font-smoothing:antialiased;
}
.as-wrap{max-width:1180px; margin:0 auto; padding:28px 24px 80px}
a{color:var(--accent); text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3,h4,h5{margin:0; font-weight:650; letter-spacing:-.01em}
code,.mono{font-family:var(--mono)}

/* Header */
.as-head{display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:8px}
.as-head__title{display:flex; align-items:baseline; gap:12px; flex-wrap:wrap}
.as-head__title h1{font-size:21px}
.as-brand{color:var(--accent); font-family:var(--mono); font-size:13px; letter-spacing:.02em}
.as-head__meta{color:var(--text-faint); font-size:12.5px; font-family:var(--mono)}
.as-toggle{
  border:1px solid var(--border-strong); background:var(--bg-elev); color:var(--text);
  border-radius:999px; padding:7px 12px; cursor:pointer; font-size:13px; line-height:1;
}
.as-toggle:hover{border-color:var(--accent); color:var(--accent)}
.as-sourceline{color:var(--text-faint); font-family:var(--mono); font-size:12px; margin:2px 0 22px}

/* Cards */
.as-cards{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:18px 0}
.as-card{
  background:var(--bg-elev); border:1px solid var(--border); border-radius:var(--radius);
  padding:14px 16px; min-height:78px; display:flex; flex-direction:column; justify-content:center;
}
.as-card__num{font-size:26px; font-weight:700; font-family:var(--mono); letter-spacing:-.02em}
.as-g{display:inline-block; width:0.22em}
.as-card__label{color:var(--text-dim); font-size:12px; margin-top:3px}
.as-card--accent{border-color:var(--accent-dim)}
.as-card--accent .as-card__num{color:var(--accent)}
/* CWE reference grid (3 columns) inside Danger Index section */
.as-cwe-grid{display:grid; grid-template-columns:repeat(3,1fr); gap:0 18px; margin-bottom:14px}
.as-cwe-item{padding:5px 0; border-bottom:1px solid var(--border)}
.as-cwe-item-id{font-family:var(--mono); font-size:11px; font-weight:700; color:var(--accent); display:block; text-decoration:none; margin-bottom:2px}
.as-cwe-item-id:hover{text-decoration:underline}
.as-cwe-item-name{font-size:11.5px; color:var(--text-dim); display:block; line-height:1.3}
.as-cwe-count{font-family:var(--mono); font-size:10px; color:var(--text-faint)}
.as-cwe-top{display:flex; align-items:center; gap:5px; flex-wrap:wrap; margin-bottom:2px}
.as-cwe-langs{display:flex; flex-wrap:wrap; gap:2px}
.as-plat-universal{background:rgba(78,161,255,.18); color:#4ea1ff}

/* Section shell */
.as-section{
  background:var(--bg-elev); border:1px solid var(--border); border-radius:var(--radius);
  padding:20px 22px; margin:16px 0;
}
.as-section__head{display:flex; align-items:center; gap:9px; margin-bottom:14px}
.as-section__head h2,.as-section__head h3{font-size:15.5px}
.as-section__head .ico{font-size:17px; line-height:1}
.as-section__sub{color:var(--text-dim); font-size:12.5px; margin:8px 0 14px}
.as-sub{color:var(--text-dim); font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:.06em; margin:14px 0 8px}
.as-insights{margin:16px 0}
.as-insights__head{display:flex; align-items:center; gap:9px; margin-bottom:10px}
.as-insights__head h3{font-size:16px; font-weight:650; margin:0}
.as-insights__head .ico{font-size:19px; line-height:1}
.as-insights-grid{display:flex; flex-direction:column; gap:12px}
.as-insights-grid .as-section{margin:0}
.as-empty{color:var(--text-faint); font-size:13px; font-style:italic; margin:4px 0}
.as-grid2{display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px}

/* Gauge */
.as-gauge{display:flex; align-items:center; gap:20px; flex-wrap:wrap}
.as-gauge__num{font-family:var(--mono); font-size:40px; font-weight:750; line-height:1}
.as-gauge__den{color:var(--text-faint); font-size:16px; font-weight:500}
.as-gauge__band{font-size:13px; font-weight:650; padding:4px 11px; border-radius:999px; display:inline-block}
.as-gauge__bar{flex:1; min-width:220px}
.band-good{color:var(--good); background:var(--good-bg)}
.band-warn{color:var(--warn); background:var(--warn-bg)}
.band-bad{color:var(--bad); background:var(--bad-bg)}
.band-crit{color:var(--crit); background:var(--crit-bg)}

/* Generic bar */
.as-bar{height:7px; background:var(--bg-inset); border-radius:999px; overflow:hidden; position:relative}
.as-bar__fill{display:block; height:100%; background:var(--accent); border-radius:999px}
.fill-good{background:var(--good)} .fill-warn{background:var(--warn)}
.fill-bad{background:var(--bad)} .fill-crit{background:var(--crit)}

/* Category breakdown */
.as-cats{display:grid; grid-template-columns:repeat(auto-fit,minmax(330px,1fr)); gap:10px 26px; margin-top:6px}
.as-cat{display:grid; grid-template-columns:22px 1fr auto; align-items:center; gap:10px; padding:5px 0}
.as-cat__ico{font-size:15px}
.as-cat__body{min-width:0}
.as-cat__top{display:flex; justify-content:space-between; gap:8px; margin-bottom:4px}
.as-cat__name{font-size:12.5px; color:var(--text); white-space:nowrap; overflow:hidden; text-overflow:ellipsis}
.as-cat__pts{font-family:var(--mono); font-size:11.5px; color:var(--text-dim); white-space:nowrap}
.as-cat--na{opacity:.5}
.as-cat__na{font-size:11px; color:var(--text-faint); font-style:italic}

/* Tabs (pure CSS via radio inputs) */
.as-tabs__radios{position:absolute; opacity:0; pointer-events:none}
.as-tabbar{display:flex; gap:4px; flex-wrap:wrap; border-bottom:2px solid var(--border); margin:8px 0 0}
.as-tab{
  padding:9px 18px; cursor:pointer; font-size:13.5px; font-weight:600; color:var(--text-dim);
  border:1px solid transparent; border-bottom:none; border-radius:8px 8px 0 0; position:relative; top:2px;
  transition:color .12s,background .12s;
}
.as-tab:hover{color:var(--text); background:var(--bg-elev-2)}
.as-tabpanel{display:none; padding-top:4px}
.as-tab__count{font-family:var(--mono); font-size:11px; color:inherit; opacity:.65; margin-left:6px}
.as-tabs--folders .as-tab{font-size:11px; padding:7px 10px}
.as-tab-sep{width:0; border-left:1px dashed var(--border); margin:4px 8px; align-self:stretch}
#t0:checked~.as-tabbar label[for=t0],#t1:checked~.as-tabbar label[for=t1],#t2:checked~.as-tabbar label[for=t2],#t3:checked~.as-tabbar label[for=t3],#t4:checked~.as-tabbar label[for=t4],#t5:checked~.as-tabbar label[for=t5],#t6:checked~.as-tabbar label[for=t6],#t7:checked~.as-tabbar label[for=t7],#t8:checked~.as-tabbar label[for=t8],#t9:checked~.as-tabbar label[for=t9],#t10:checked~.as-tabbar label[for=t10],#t11:checked~.as-tabbar label[for=t11],#t12:checked~.as-tabbar label[for=t12],#t13:checked~.as-tabbar label[for=t13],#t14:checked~.as-tabbar label[for=t14],#t15:checked~.as-tabbar label[for=t15],#t16:checked~.as-tabbar label[for=t16],#t17:checked~.as-tabbar label[for=t17],#t18:checked~.as-tabbar label[for=t18],#t19:checked~.as-tabbar label[for=t19],#t20:checked~.as-tabbar label[for=t20],#t21:checked~.as-tabbar label[for=t21],#t22:checked~.as-tabbar label[for=t22],#t23:checked~.as-tabbar label[for=t23],#t24:checked~.as-tabbar label[for=t24],#t25:checked~.as-tabbar label[for=t25],#t26:checked~.as-tabbar label[for=t26],#t27:checked~.as-tabbar label[for=t27],#t28:checked~.as-tabbar label[for=t28],#t29:checked~.as-tabbar label[for=t29]{
  color:var(--accent-ink); background:var(--accent);
  border-color:var(--accent); border-bottom-color:var(--accent);
}
#t0:checked~.as-panels #p0,#t1:checked~.as-panels #p1,#t2:checked~.as-panels #p2,#t3:checked~.as-panels #p3,#t4:checked~.as-panels #p4,#t5:checked~.as-panels #p5,#t6:checked~.as-panels #p6,#t7:checked~.as-panels #p7,#t8:checked~.as-panels #p8,#t9:checked~.as-panels #p9,#t10:checked~.as-panels #p10,#t11:checked~.as-panels #p11,#t12:checked~.as-panels #p12,#t13:checked~.as-panels #p13,#t14:checked~.as-panels #p14,#t15:checked~.as-panels #p15,#t16:checked~.as-panels #p16,#t17:checked~.as-panels #p17,#t18:checked~.as-panels #p18,#t19:checked~.as-panels #p19,#t20:checked~.as-panels #p20,#t21:checked~.as-panels #p21,#t22:checked~.as-panels #p22,#t23:checked~.as-panels #p23,#t24:checked~.as-panels #p24,#t25:checked~.as-panels #p25,#t26:checked~.as-panels #p26,#t27:checked~.as-panels #p27,#t28:checked~.as-panels #p28,#t29:checked~.as-panels #p29{display:block}
.as-count{font-weight:400; color:var(--text-faint)}

/* Module / package grid */
.as-modgrid{display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:10px}
.as-mod{background:var(--bg-elev-2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:11px 13px}
.as-mod__name{font-family:var(--mono); font-size:13px; font-weight:600; word-break:break-word}
.as-mod__meta{color:var(--text-dim); font-size:11.5px; margin-top:3px}

/* Hotspots */
.as-hot{display:flex; flex-direction:column; gap:6px}
.as-hot__row{display:grid; grid-template-columns:1fr 56px 120px; align-items:center; gap:10px; font-size:12.5px}
.as-hot__name{font-family:var(--mono); white-space:nowrap; overflow:hidden; text-overflow:ellipsis}
.as-hot__score{font-family:var(--mono); color:var(--text-dim); text-align:right}

/* Findings */
.as-sev{display:inline-block; min-width:62px; text-align:center; font-size:10.5px; font-weight:700;
  letter-spacing:.04em; padding:2px 7px; border-radius:5px; font-family:var(--mono)}
.sev-high{color:var(--crit); background:var(--crit-bg)}
.sev-medium{color:var(--bad); background:var(--bad-bg)}
.sev-low{color:var(--warn); background:var(--warn-bg)}
.as-rule{border:1px solid var(--border); border-radius:var(--radius-sm); margin:10px 0; overflow:hidden}
.as-rule__head{display:flex; align-items:center; gap:10px; padding:10px 13px; background:var(--bg-elev-2); flex-wrap:wrap}
.as-rule__name{font-weight:650; font-size:13.5px}
.as-rule__id{font-family:var(--mono); font-size:11px; color:var(--text-faint)}
.as-rule__cwe{font-family:var(--mono); font-size:11px; color:var(--accent); text-decoration:none; opacity:.75}
.as-rule__cwe:hover{opacity:1; text-decoration:underline}
.as-rule__count{margin-left:auto; font-family:var(--mono); font-size:12px; color:var(--text-dim)}
.as-rule__desc{padding:0 13px 11px; color:var(--text-dim); font-size:12.5px; background:var(--bg-elev-2)}
.as-find{display:grid; grid-template-columns:1fr auto; gap:6px 12px; padding:8px 13px; border-top:1px solid var(--border); align-items:baseline}
.as-find__loc{font-family:var(--mono); font-size:12px; color:var(--accent); word-break:break-all}
.as-find__author{font-size:11.5px; color:var(--text-faint)}
.as-find__snip{grid-column:1/-1; font-family:var(--mono); font-size:11.5px; color:var(--text-dim);
  background:var(--bg-inset); border-radius:5px; padding:6px 9px; overflow-x:auto; white-space:pre}
.as-more{color:var(--text-faint); font-size:12px; padding:8px 13px; border-top:1px solid var(--border); font-style:italic}
.as-clean{color:var(--good); font-size:13px}

/* Architecture module */
.as-arch__pattern{border:1px solid var(--border); border-radius:var(--radius-sm); padding:13px 15px; margin:10px 0; background:var(--bg-elev-2)}
.as-arch__pattern--primary{border-color:var(--accent-dim)}
.as-arch__head{display:flex; align-items:baseline; justify-content:space-between; gap:10px}
.as-arch__name{font-weight:650; font-size:14.5px}
.as-arch__pct{font-family:var(--mono); font-weight:700; color:var(--accent)}
.as-arch__pattern .as-bar{margin:8px 0 4px}
.as-arch__hint{color:var(--text-dim); font-size:12px; margin:6px 0 0}
.as-arch__roles{display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:8px; margin-top:12px}
.as-arch__role{background:var(--bg-elev); border:1px solid var(--border); border-radius:var(--radius-sm);
  padding:9px 10px; display:flex; flex-direction:column; gap:2px; border-left-width:3px}
.as-arch__role[data-health="present"]{border-left-color:var(--good)}
.as-arch__role[data-health="weak"]{border-left-color:var(--warn)}
.as-arch__role[data-health="missing"]{border-left-color:var(--text-faint); opacity:.6}
.as-arch__letter{font-family:var(--mono); font-weight:700; font-size:12px; color:var(--accent)}
.as-arch__role-name{font-size:12px; font-weight:600}
.as-arch__role-detail{font-size:11px; color:var(--text-dim)}
.as-arch__components{margin-top:16px}
.as-arch__component-grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:8px}
.as-arch__component{display:flex; align-items:center; gap:9px; background:var(--bg-elev-2);
  border:1px solid var(--border); border-radius:var(--radius-sm); padding:8px 11px}
.as-arch__component-icon{font-size:17px}
.as-arch__component-body{display:flex; flex-direction:column; line-height:1.3}
.as-arch__component-body strong{font-size:12.5px}
.as-arch__component-body em{font-size:11px; color:var(--text-dim); font-style:normal}

/* Design-pattern module */
.as-dp{display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:18px}
.as-dp__items{display:flex; flex-direction:column; gap:7px}
.as-dp__item{background:var(--bg-elev-2); border:1px solid var(--border); border-radius:var(--radius-sm);
  padding:8px 11px; display:grid; grid-template-columns:1fr auto; gap:2px 8px; align-items:baseline}
.as-dp__name{font-weight:600; font-size:13px}
.as-dp__count{font-family:var(--mono); font-size:11.5px; color:var(--accent)}
.as-dp__ex{grid-column:1/-1; font-family:var(--mono); font-size:10.5px; color:var(--text-faint); word-break:break-word}

/* OOP vs POP module */
.as-pop__verdict{font-size:15px; font-weight:650; margin-bottom:12px}
.as-pop__scale{display:flex; align-items:center; gap:10px}
.as-pop__end{font-family:var(--mono); font-size:11px; color:var(--text-faint); font-weight:600}
.as-pop__track{position:relative; flex:1; height:9px; background:var(--bg-inset); border-radius:999px}
.as-pop__fill{position:absolute; left:0; top:0; height:100%; background:linear-gradient(90deg,var(--bad),var(--accent)); border-radius:999px}
.as-pop__marker{position:absolute; top:50%; width:3px; height:17px; background:var(--text); transform:translate(-50%,-50%); border-radius:2px}
.as-pop__legend{color:var(--text-dim); font-size:12px; margin-top:8px}
.as-pop__counts{display:grid; grid-template-columns:repeat(auto-fit,minmax(90px,1fr)); gap:8px; margin-top:14px}
.as-pop__chip{background:var(--bg-elev-2); border:1px solid var(--border); border-radius:var(--radius-sm);
  padding:9px; text-align:center; border-top-width:3px}
.as-pop__chip[data-kind="value"]{border-top-color:var(--good)}
.as-pop__chip[data-kind="proto"]{border-top-color:var(--accent)}
.as-pop__chip[data-kind="ref"]{border-top-color:var(--bad)}
.as-pop__num{display:block; font-family:var(--mono); font-size:19px; font-weight:700}
.as-pop__lbl{font-size:11px; color:var(--text-dim)}

/* Module panel wrapper inside a tab */
.as-modpanel{margin-top:16px}
.as-modpanel__head{display:flex; align-items:baseline; gap:10px; margin-bottom:4px}
.as-modpanel__head h4{font-size:14px}

/* Git tables */
.as-table{width:100%; border-collapse:collapse; font-size:12.5px}
.as-table th{text-align:left; color:var(--text-dim); font-weight:600; font-size:11px; text-transform:uppercase;
  letter-spacing:.05em; padding:6px 10px; border-bottom:1px solid var(--border)}
.as-table td{padding:7px 10px; border-bottom:1px solid var(--border)}
.as-table td.mono{font-family:var(--mono)}
.as-table tr:last-child td{border-bottom:none}
.as-tag{display:inline-block; font-family:var(--mono); font-size:11px; padding:1px 7px; border-radius:5px;
  background:var(--accent-dim); color:var(--accent); margin:2px 3px 2px 0}
.as-model{display:flex; align-items:center; gap:14px; flex-wrap:wrap}
.as-model__ico{font-size:30px}
.as-model__name{font-size:16px; font-weight:650}
.as-model__detail{color:var(--text-dim); font-size:12.5px}
.as-model__conf{font-family:var(--mono); font-size:12px; color:var(--text-dim)}
.as-signals{display:flex; flex-wrap:wrap; gap:6px; margin-top:10px}
.as-signal{font-size:11px; padding:2px 8px; border-radius:999px; background:var(--bg-elev-2); border:1px solid var(--border); color:var(--text-dim)}

.as-foot{margin-top:30px; color:var(--text-faint); font-size:11.5px; text-align:center; font-family:var(--mono)}
.as-foot a{color:var(--text-dim)}

/* VS Code deep links */
.as-vs{color:var(--accent); text-decoration:none}
.as-vs:hover{text-decoration:underline}
a.as-mod{display:block; text-decoration:none; color:inherit; transition:border-color .12s}
a.as-mod:hover{border-color:var(--accent)}

/* Per-module / per-microservice detail (bottom) */
.as-pkg-section{padding:14px 0 4px; border-top:1px solid var(--border)}
.as-pkg-section:first-of-type{border-top:none}
.as-pkg-section h3{font-size:15px; display:flex; align-items:baseline; gap:8px; flex-wrap:wrap}
.as-bs-badge{font-family:var(--mono); font-size:10px; padding:1px 7px; border-radius:5px;
  background:var(--accent-dim); color:var(--accent); font-weight:600}
.as-pkg-stats{font-weight:400; color:var(--text-faint); font-size:12.5px; margin-left:auto}
.as-pkg-detail{color:var(--text-dim); font-size:12.5px; margin:6px 0 12px}
.as-file-table{width:100%; table-layout:fixed}
.as-file-table th:first-child,.as-file-table td:first-child{width:50%; overflow:hidden}
.as-file-table th:nth-child(2),.as-file-table td:nth-child(2),
.as-file-table th:nth-child(3),.as-file-table td:nth-child(3),
.as-file-table th:nth-child(4),.as-file-table td:nth-child(4){text-align:right; width:60px; white-space:nowrap}
.as-file-table td{vertical-align:top}
.as-file-dir{color:var(--text-faint); font-weight:400}
.as-file-desc{color:var(--text-faint); font-size:11.5px; font-style:italic; margin-top:2px}
.as-gen-sub{margin-top:18px; color:var(--text-faint)}
.as-decl-tags{font-size:11.5px; line-height:1.9; color:var(--text-dim); font-family:var(--mono)}
.as-decl-more{color:var(--text-faint)}
.as-decl-link{color:var(--text-dim); text-decoration:none}
.as-decl-link:hover{color:var(--accent); text-decoration:none}


/* Backend architecture (goscope-style layered view) */
.as-archcols{display:grid; grid-template-columns:1.4fr 1fr; gap:22px; margin-top:6px}
.as-archcol h5{margin-bottom:8px}
.as-layers{display:flex; flex-direction:column; gap:8px}
.as-layer__row{display:flex; align-items:center; gap:7px; font-size:12.5px; margin-bottom:4px}
.as-layer__icon{font-size:14px; flex-shrink:0}
.as-layer__name{flex:1; color:var(--text)}
.as-layer__count{color:var(--text-faint); font-size:11px; white-space:nowrap; font-family:var(--mono)}
.as-layer .as-bar{height:5px}
.as-comps{display:flex; flex-direction:column; gap:7px}
.as-comp{display:flex; align-items:center; gap:8px; font-size:12.5px; color:var(--text)}
.as-comp__icon{font-size:16px; flex-shrink:0}
.as-comp em{color:var(--text-dim); font-style:normal; font-size:11.5px}

/* Dependency-hotspot table + inline module graph */
.as-hot__table th:not(:first-child),.as-hot__table td:not(:first-child){text-align:right; width:72px}
.as-graph{border:1px solid var(--border); border-radius:var(--radius); background:var(--bg-inset); margin:4px 0 14px; overflow:hidden}
.as-graph__svg{display:block; width:100%; height:auto}
.as-graph__lbl{fill:var(--text-dim); font-family:var(--mono); font-size:9.5px}
.as-fg-container{width:100%; height:460px; border:1px solid var(--border); border-radius:var(--radius); margin:4px 0 14px; overflow:hidden; background:var(--bg-inset)}
.as-fg-container--decl{height:280px; margin:0 0 10px}
.as-fg-container canvas{display:block}
.as-fg-container>div{height:100%}
.as-graph-offline{color:var(--text-faint); font-size:11px; margin:8px 0 0; font-style:italic}
.as-decl-chips{padding:6px 0 12px;line-height:2.4}
.as-chip{display:inline-block;margin:2px 3px;padding:2px 9px;border-radius:6px;font-size:11px;font-family:var(--mono);text-decoration:none;white-space:nowrap}
a.as-chip:hover{opacity:.8}
.as-pkg--link:hover{border-color:var(--accent)!important;opacity:.85}

/* Danger Index — half-gauge + weight bars + platform row */
.as-sec-toprow{display:flex; gap:20px; align-items:flex-start; flex-wrap:wrap; margin-top:8px}
.as-sec-gauge-wrap{display:flex; flex-direction:column; align-items:center; padding:14px 18px;
  background:var(--bg-inset); border-radius:var(--radius); flex:0 0 220px}
.as-sec-gauge-svg{width:200px; height:124px}
.as-sec-gauge-label{font-family:var(--mono); font-size:10px; color:var(--text-faint); letter-spacing:.08em; margin-top:6px; text-transform:uppercase}
.as-sec-gauge-val{font-size:26px; font-weight:700; margin-top:2px; font-family:var(--mono)}
.as-sec-gauge-band{font-size:11px; font-weight:600; margin-top:6px; padding:2px 8px; border-radius:6px}
.as-sec-gauge-band.band-good{background:rgba(90,138,122,.18); color:#5a8a7a}
.as-sec-gauge-band.band-warn{background:rgba(160,160,48,.18); color:#a0a030}
.as-sec-gauge-band.band-bad{background:rgba(192,160,48,.18); color:#c0a030}
.as-sec-gauge-band.band-crit{background:rgba(192,80,64,.18); color:#c05040}
.as-sec-gauge-desc{font-size:11px; margin-top:10px; align-self:stretch; line-height:2}
.as-sec-weight-bars{flex:1; min-width:260px}
.as-sec-weight-title{font-size:10px; font-weight:600; color:var(--text-faint); letter-spacing:.06em; text-transform:uppercase; margin-bottom:8px}
.as-sec-wb-row{display:flex; align-items:center; gap:8px; margin-bottom:4px}
.as-sec-wb-name{font-size:11px; color:var(--text2); min-width:200px; display:flex; align-items:center; gap:4px}
.as-sec-wb-num{display:inline-flex; align-items:center; justify-content:center; width:16px; height:16px;
  border-radius:4px; background:var(--bg-elev3,#444); color:var(--text-faint); font-size:9px; font-weight:700; flex-shrink:0}
.as-sec-wb-track{flex:1; height:6px; background:var(--bg-inset); border-radius:3px; overflow:hidden; min-width:50px}
.as-sec-wb-fill{height:100%; border-radius:3px}
.as-sec-wb-na{height:100%; background:repeating-linear-gradient(45deg,var(--border),var(--border) 3px,transparent 3px,transparent 6px)}
.as-sec-wb-pts{font-family:var(--mono); font-size:11px; font-weight:600; min-width:50px; text-align:right}
.as-sec-wb-na{font-size:10px; color:var(--text-faint); font-style:italic; min-width:50px; text-align:right}
.as-sec-wb-w{font-family:var(--mono); font-size:10px; color:var(--text-faint); min-width:30px; text-align:right}
.as-sec-plat-row{display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px}
.as-sec-plat-card{background:var(--bg-inset); border:1px solid var(--border); border-radius:var(--radius-sm);
  padding:8px 12px; min-width:100px}
.as-sec-plat-name{font-size:11px; color:var(--text-faint); font-weight:600; text-transform:uppercase; letter-spacing:.04em}
.as-sec-plat-count{font-size:20px; font-weight:700; font-family:var(--mono); margin-top:2px; display:flex; align-items:center; gap:6px}

/* Architecture layers */
.arch-layers{display:flex; flex-direction:column; gap:5px; margin-top:8px}
.arch-layer{display:flex; flex-direction:column; gap:3px}
.layer-bar-row{display:flex; align-items:center; gap:8px; font-size:12px}
.layer-icon{font-size:13px; width:20px; flex-shrink:0}
.layer-name{color:var(--text2); font-size:12px; min-width:160px}
.layer-count{color:var(--text-faint); font-size:11px; font-family:var(--mono); margin-left:auto}
.layer-bar-track{height:5px; background:var(--bg-inset); border-radius:3px; overflow:hidden}
.layer-bar-fill{height:100%; background:var(--accent); border-radius:3px; opacity:0.75}

/* Tech components */
.arch-components{display:flex; flex-wrap:wrap; gap:6px; margin-top:8px}
.arch-component{display:inline-flex; align-items:center; gap:5px; background:var(--bg-elev-2);
  border:1px solid var(--border); border-radius:var(--radius-sm); padding:4px 10px; font-size:12px}
.comp-icon{font-size:14px}


/* OOP vs POP — ArchSwiftScope report style */
.as-pop__sub{color:var(--text-dim); font-size:12px; margin:0 0 12px}
.as-pop__cats{margin:16px 0 18px; display:flex; flex-direction:column; gap:8px}
.as-pop__catbar{display:flex; align-items:center; gap:10px}
.as-pop__catlabel{font-size:12px; color:var(--text-dim); min-width:140px}
.as-pop__catbar .as-bar{flex:1; height:6px}
.as-pop__catpct{font-family:var(--mono); font-size:11.5px; min-width:34px; text-align:right}
.as-pop__catw{font-size:10px; color:var(--text-faint); min-width:42px}
.as-pop__t-good{color:var(--good)} .as-pop__t-warn{color:var(--warn)} .as-pop__t-crit{color:var(--crit)}
.as-pop__metrics{width:100%; border-collapse:collapse; font-size:12.5px; margin-top:6px; table-layout:fixed}
.as-pop__metrics th{text-align:left; color:var(--text-dim); font-weight:600; font-size:10.5px;
  text-transform:uppercase; letter-spacing:.05em; padding:6px 8px; border-bottom:1px solid var(--border)}
.as-pop__metrics td{padding:6px 8px; border-bottom:1px solid var(--border); vertical-align:middle}
.as-pop__metrics th:nth-child(1),.as-pop__metrics td:nth-child(1){width:26px}
.as-pop__metrics th:nth-child(3),.as-pop__metrics td:nth-child(3){width:34%}
.as-pop__metrics th:nth-child(4),.as-pop__metrics td:nth-child(4){width:110px}
.as-pop__metrics th:nth-child(5),.as-pop__metrics td:nth-child(5){width:66px}
.as-pop__metrics code{font-size:11.5px; background:var(--bg-inset); padding:0 4px; border-radius:4px}
.as-pop__inv{font-size:10px; color:var(--text-faint)}
.as-pop__infocell{color:var(--text-dim)}
.as-pop__sect td{padding:11px 8px 4px; font-size:10.5px; font-weight:700; color:var(--text-dim);
  letter-spacing:.06em; text-transform:uppercase; border-top:1px solid var(--border-strong); border-bottom:none}
.as-mini{height:5px; background:var(--bg-inset); border-radius:3px; overflow:hidden; min-width:54px}
.as-mini__fill{display:block; height:100%; border-radius:3px; background:var(--accent)}

/* Generic tag chips (goscope-flavored, retuned for the dark theme) */
.as-tag{display:inline-block; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:600;
  font-family:var(--mono); margin:2px}
.tag-pop,.tag-tech{color:var(--good); background:var(--good-bg)}
.tag-oop,.tag-foreign{color:var(--bad); background:var(--bad-bg)}
.tag-mixed{color:var(--warn); background:var(--warn-bg)}
.tag-local{color:var(--accent); background:var(--accent-dim)}

/* Tech-stack tag cloud */
.as-tagcloud{line-height:2.2; margin-top:4px}

/* Packages & Modules grid (goscope pkg-grid) */
.as-pkggrid{display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:6px 8px; margin-top:4px}
.as-pkg{display:flex; align-items:center; justify-content:space-between; gap:8px;
  background:var(--bg-elev-2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:8px 11px}
.as-pkg__name{font-family:var(--mono); font-size:12.5px; font-weight:600; overflow:hidden;
  text-overflow:ellipsis; white-space:nowrap; min-width:0}
.as-pkg__meta{display:flex; align-items:center; gap:4px; margin-left:auto; flex-shrink:0}
.as-pkg__loc{color:var(--text-faint); font-size:9.5px; font-family:var(--mono); font-weight:400}
.as-plat-badge{font-size:9px; font-weight:700; padding:1px 5px; border-radius:4px; letter-spacing:.02em}
.as-plat-go{background:#00acd7,20%; background:rgba(0,172,215,.18); color:#00acd7}
.as-plat-swift_objc{background:rgba(250,95,30,.18); color:#fa5f1e}
.as-plat-kotlin{background:rgba(127,82,255,.18); color:#7f52ff}
.as-plat-python{background:rgba(55,118,171,.18); color:#3776ab}
.as-plat-ts_js{background:rgba(49,120,198,.18); color:#3178c6}

/* Prompt card */
.as-prompt{margin-top:18px}
.as-prompt__bar{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap}
.as-prompt__tab{padding:4px 14px;border-radius:5px;border:1px solid var(--border);background:var(--bg-card);
  color:var(--text-dim);font-size:12px;font-weight:600;cursor:pointer;transition:background .15s,color .15s;font-family:var(--mono)}
.as-prompt__tab:hover{background:var(--bg-elev-2);color:var(--text)}
.as-prompt__tab--active{background:var(--accent-dim);color:var(--accent);border-color:var(--accent)}
.as-prompt__copy{margin-left:auto;padding:4px 14px;border-radius:5px;border:1px solid var(--border);
  background:transparent;color:var(--text-faint);font-size:12px;cursor:pointer;transition:color .15s}
.as-prompt__copy:hover{color:var(--accent)}
.as-prompt__copy--ok{color:var(--good)!important}
.as-prompt__body{display:none}
.as-prompt__body--active{display:block}
.as-prompt__pre{background:var(--bg-inset);border:1px solid var(--border);border-radius:6px;padding:14px 16px;
  font-family:var(--mono);font-size:11.5px;color:var(--text-dim);white-space:pre-wrap;word-break:break-word;
  max-height:420px;overflow-y:auto;line-height:1.55;margin:0}

`

// JS toggles the color theme (persisted only in-memory per session — no
// localStorage, per artifact constraints) and is otherwise unnecessary because
// tabs are pure CSS. It is intentionally tiny.
const JS = `
(function(){
  var btn=document.getElementById('as-theme-toggle');
  if(btn){
    btn.addEventListener('click',function(){
      var root=document.documentElement;
      var light=root.getAttribute('data-theme')==='light';
      if(light){root.removeAttribute('data-theme');btn.textContent='☀ Light';}
      else{root.setAttribute('data-theme','light');btn.textContent='🌙 Dark';}
    });
  }
  document.addEventListener('click',function(e){
    var card=e.target.closest('.as-sec-plat-card[data-tab]');
    if(!card)return;
    var idx=card.getAttribute('data-tab');
    var radio=document.getElementById('t'+idx);
    if(radio)radio.checked=true;
    setTimeout(function(){
      var panel=document.getElementById('p'+idx);
      var sec=panel&&panel.querySelector('.as-danger-section');
      if(sec)sec.scrollIntoView({behavior:'smooth',block:'start'});
    },50);
  });
  // Module card → jump to platform tab + scroll to module
  document.addEventListener('click',function(e){
    var card=e.target.closest('.as-pkg--link[data-mod]');
    if(!card)return;
    var modId='mod-'+card.getAttribute('data-mod');
    var el=document.getElementById(modId);
    if(!el)return;
    var panel=el.closest('[id^="p"]');
    if(!panel)return;
    var idx=panel.id.slice(1);
    var radio=document.getElementById('t'+idx);
    if(radio)radio.checked=true;
    setTimeout(function(){el.scrollIntoView({behavior:'smooth',block:'start'});},50);
  });
  // VS Code path updater
  var vsBtn=document.getElementById('as-vs-btn');
  if(vsBtn){
    vsBtn.addEventListener('click',function(){
      var inp=document.getElementById('as-vs-path');
      var msg=document.getElementById('as-vs-msg');
      if(!inp)return;
      var newBase=inp.value.trim().replace(/\/+$/,'');
      var origBase=inp.dataset.orig;
      if(!newBase||newBase===origBase)return;
      var prefix='vscode://file'+origBase;
      var newPrefix='vscode://file'+newBase;
      var links=document.querySelectorAll('a[href^="'+prefix+'"]');
      links.forEach(function(a){
        a.setAttribute('href',newPrefix+a.getAttribute('href').slice(prefix.length));
      });
      inp.dataset.orig=newBase;
      if(msg)msg.textContent=links.length+' links updated';
    });
  }
  // Prompt card: tab switching + clipboard copy
  document.addEventListener('click',function(e){
    var tab=e.target.closest('.as-prompt__tab[data-prompt-tab]');
    if(tab){
      var card=tab.closest('.as-prompt');
      if(!card)return;
      card.querySelectorAll('.as-prompt__tab').forEach(function(t){t.classList.remove('as-prompt__tab--active');});
      tab.classList.add('as-prompt__tab--active');
      var id=tab.getAttribute('data-prompt-tab');
      card.querySelectorAll('.as-prompt__body').forEach(function(b){b.classList.remove('as-prompt__body--active');});
      var body=card.querySelector('.as-prompt__body[data-prompt-body="'+id+'"]');
      if(body)body.classList.add('as-prompt__body--active');
      return;
    }
    var copyBtn=e.target.closest('.as-prompt__copy');
    if(copyBtn){
      var card=copyBtn.closest('.as-prompt');
      var active=card&&card.querySelector('.as-prompt__body--active .as-prompt__pre');
      if(!active)return;
      var text=active.textContent||'';
      if(navigator.clipboard){
        navigator.clipboard.writeText(text).then(function(){
          copyBtn.classList.add('as-prompt__copy--ok');
          copyBtn.textContent='Copied!';
          setTimeout(function(){copyBtn.classList.remove('as-prompt__copy--ok');copyBtn.textContent='Copy';},1800);
        });
      } else {
        var ta=document.createElement('textarea');
        ta.value=text; ta.style.position='fixed'; ta.style.opacity='0';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy');
        document.body.removeChild(ta);
        copyBtn.textContent='Copied!';
        setTimeout(function(){copyBtn.textContent='Copy';},1800);
      }
    }
  });
})();
`
