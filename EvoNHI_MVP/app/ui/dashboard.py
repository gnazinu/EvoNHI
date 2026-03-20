from __future__ import annotations

from html import escape
from typing import Any


def _pct(value: float) -> str:
    return f"{round(value * 100)}%"


def _metric_card(label: str, value: Any, tone: str = "default") -> str:
    return (
        f'<article class="metric tone-{escape(tone)}">'
        f'<span class="metric-label">{escape(str(label))}</span>'
        f'<strong class="metric-value">{escape(str(value))}</strong>'
        "</article>"
    )


def _action_card(action: dict[str, Any]) -> str:
    return (
        '<article class="action-card">'
        f'<h4>{escape(action.get("title", "Untitled action"))}</h4>'
        f'<p>{escape(action.get("description", ""))}</p>'
        '<div class="action-meta">'
        f'<span>Cost {escape(str(action.get("cost", 0)))}</span>'
        f'<span>Impact {escape(str(action.get("impact", 0)))}</span>'
        f'<span>{escape(action.get("action_type", "change"))}</span>'
        "</div>"
        f'<small>{escape(action.get("rationale", ""))}</small>'
        "</article>"
    )


def _plan_card(plan: dict[str, Any], featured: bool = False) -> str:
    featured_class = " featured-plan" if featured else ""
    selected_actions = "".join(_action_card(action) for action in plan.get("selected_actions", []))
    return (
        f'<section class="plan-card{featured_class}">'
        f'<div class="plan-head"><h3>{escape(plan.get("title", "Plan"))}</h3>'
        f'<span class="pill">{_pct(plan.get("coverage_ratio", 0.0))} path reduction</span></div>'
        f'<p class="plan-reasoning">{escape(plan.get("reasoning", ""))}</p>'
        '<div class="plan-metrics">'
        f'{_metric_card("Paths removed", plan.get("reduced_paths", 0), "positive")}'
        f'{_metric_card("Remaining", plan.get("remaining_paths", 0), "warning")}'
        f'{_metric_card("Cost score", plan.get("cost", 0))}'
        f'{_metric_card("Operational impact", plan.get("operational_impact", 0))}'
        "</div>"
        '<div class="action-grid">'
        f"{selected_actions or '<p class=\"muted\">No concrete actions were selected for this plan.</p>'}"
        "</div>"
        "</section>"
    )


def _path_card(path: dict[str, Any]) -> str:
    steps = []
    for step in path.get("steps", []):
        steps.append(
            '<li class="step">'
            f'<div><strong>{escape(step.get("from", ""))}</strong> '
            f'<span>{escape(step.get("label", ""))}</span> '
            f'<strong>{escape(step.get("to", ""))}</strong></div>'
            f'<p>{escape(step.get("why", ""))}</p>'
            "</li>"
        )
    return (
        '<article class="story-card">'
        f'<div class="story-head"><h4>{escape(path.get("headline", "Attack story"))}</h4>'
        f'<span class="score">Score {escape(str(path.get("score", "")))}</span></div>'
        f'<ol class="story-steps">{"".join(steps)}</ol>'
        "</article>"
    )


def render_analysis_dashboard(payload: dict[str, Any]) -> str:
    executive = payload.get("executive", {})
    summary = payload.get("summary", {})
    run = payload.get("run", {})
    plans = payload.get("plans", [])
    top_plan = payload.get("top_plan")
    path_cards = payload.get("path_cards", [])
    crown_jewels = payload.get("crown_jewels", [])
    risk_color = payload.get("risk_color", "#ef7d57")

    featured_plan = _plan_card(top_plan, featured=True) if top_plan else '<p class="muted">No remediation plan available yet.</p>'
    additional_plans = "".join(_plan_card(plan) for plan in plans[1:3])
    stories = "".join(_path_card(path) for path in path_cards[:4]) or '<p class="muted">No reachable attack stories were found.</p>'
    crown_jewel_chips = "".join(f'<span class="pill neutral">{escape(item)}</span>' for item in crown_jewels)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EvoNHI Executive Dashboard</title>
  <style>
    :root {{
      --bg: #0d1b1e;
      --bg-soft: #14262b;
      --panel: rgba(255,255,255,0.08);
      --panel-strong: rgba(255,255,255,0.12);
      --text: #f5f1e8;
      --muted: #cdd9d3;
      --accent: #7ad3b2;
      --accent-strong: {risk_color};
      --warning: #f4b266;
      --line: rgba(255,255,255,0.14);
      --shadow: 0 20px 60px rgba(0, 0, 0, 0.28);
      --headline-font: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
      --body-font: "Avenir Next", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: var(--body-font);
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(122, 211, 178, 0.18), transparent 32%),
        radial-gradient(circle at top right, rgba(209, 73, 91, 0.25), transparent 28%),
        linear-gradient(160deg, #091012 0%, #0d1b1e 45%, #13252c 100%);
      min-height: 100vh;
    }}
    main {{
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 28px 0 56px;
    }}
    .hero, .panel {{
      background: var(--panel);
      backdrop-filter: blur(14px);
      border: 1px solid var(--line);
      border-radius: 28px;
      box-shadow: var(--shadow);
    }}
    .hero {{
      padding: 28px;
      position: relative;
      overflow: hidden;
      animation: rise 480ms ease-out both;
    }}
    .hero::after {{
      content: "";
      position: absolute;
      inset: auto -80px -100px auto;
      width: 280px;
      height: 280px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(255,255,255,0.16), transparent 70%);
    }}
    h1, h2, h3, h4 {{
      font-family: var(--headline-font);
      margin: 0;
      letter-spacing: -0.02em;
    }}
    h1 {{ font-size: clamp(2.2rem, 4vw, 4rem); max-width: 14ch; }}
    h2 {{ font-size: clamp(1.6rem, 3vw, 2.3rem); margin-bottom: 14px; }}
    p {{ line-height: 1.6; color: var(--muted); }}
    .hero-grid {{
      display: grid;
      grid-template-columns: 1.5fr 1fr;
      gap: 24px;
      align-items: end;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(255,255,255,0.08);
      border: 1px solid rgba(255,255,255,0.14);
      margin-bottom: 18px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 0.78rem;
    }}
    .badge::before {{
      content: "";
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: var(--accent-strong);
      box-shadow: 0 0 0 10px rgba(255,255,255,0.04);
    }}
    .metrics, .plan-metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
      margin-top: 22px;
    }}
    .metric {{
      padding: 16px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.05);
    }}
    .metric-label {{
      display: block;
      color: var(--muted);
      font-size: 0.9rem;
      margin-bottom: 8px;
    }}
    .metric-value {{
      font-size: 1.8rem;
      line-height: 1;
    }}
    .tone-positive .metric-value {{ color: var(--accent); }}
    .tone-warning .metric-value {{ color: var(--warning); }}
    .section-grid {{
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 22px;
      margin-top: 22px;
    }}
    .panel {{
      padding: 24px;
      animation: rise 680ms ease-out both;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 8px 12px;
      border-radius: 999px;
      font-size: 0.84rem;
      background: rgba(122, 211, 178, 0.12);
      border: 1px solid rgba(122, 211, 178, 0.24);
      color: var(--text);
    }}
    .pill.neutral {{
      background: rgba(255,255,255,0.06);
      border-color: rgba(255,255,255,0.14);
    }}
    .pill-row {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 14px;
    }}
    .plan-card {{
      padding: 22px;
      border-radius: 24px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.04);
    }}
    .featured-plan {{
      background: linear-gradient(180deg, rgba(122,211,178,0.12), rgba(255,255,255,0.04));
    }}
    .plan-head, .story-head {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      margin-bottom: 12px;
    }}
    .plan-reasoning {{ margin-top: 6px; }}
    .action-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-top: 18px;
    }}
    .action-card {{
      padding: 16px;
      border-radius: 18px;
      background: rgba(9,16,18,0.32);
      border: 1px solid rgba(255,255,255,0.08);
    }}
    .action-card h4 {{ margin-bottom: 10px; font-size: 1.15rem; }}
    .action-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin: 14px 0 8px;
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .story-card {{
      padding: 20px;
      border-radius: 22px;
      background: rgba(255,255,255,0.04);
      border: 1px solid var(--line);
    }}
    .story-card + .story-card {{ margin-top: 14px; }}
    .story-steps {{
      margin: 14px 0 0;
      padding-left: 18px;
    }}
    .step {{
      margin-bottom: 14px;
      color: var(--muted);
    }}
    .step div {{
      color: var(--text);
      margin-bottom: 6px;
      line-height: 1.45;
    }}
    .score {{
      color: var(--accent);
      font-weight: 600;
      white-space: nowrap;
    }}
    .muted {{
      color: var(--muted);
    }}
    details {{
      margin-top: 18px;
      border-top: 1px solid var(--line);
      padding-top: 14px;
    }}
    summary {{
      cursor: pointer;
      color: var(--text);
      font-weight: 600;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-top: 12px;
    }}
    .stagger {{
      animation: rise 840ms ease-out both;
    }}
    @keyframes rise {{
      from {{
        opacity: 0;
        transform: translateY(16px);
      }}
      to {{
        opacity: 1;
        transform: translateY(0);
      }}
    }}
    @media (max-width: 920px) {{
      .hero-grid, .section-grid {{
        grid-template-columns: 1fr;
      }}
      main {{
        width: min(100% - 20px, 1180px);
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="badge">EvoNHI Executive View</div>
      <div class="hero-grid">
        <div>
          <h1>{escape(executive.get("headline", "Security posture overview"))}</h1>
          <p>{escape(executive.get("non_technical_summary", ""))}</p>
          <p>{escape(executive.get("why_it_matters", ""))}</p>
          <div class="pill-row">{crown_jewel_chips or '<span class="pill neutral">No crown jewels registered</span>'}</div>
        </div>
        <div>
          <div class="metrics">
            {_metric_card("Risk level", executive.get("risk_level", "elevated").title(), "warning")}
            {_metric_card("Reachable paths", summary.get("baseline_paths", 0), "warning")}
            {_metric_card("Candidate actions", summary.get("candidate_actions", 0))}
            {_metric_card("Analysis run", run.get("id", "n/a"))}
          </div>
        </div>
      </div>
    </section>

    <div class="section-grid">
      <section class="panel stagger">
        <h2>Recommended Plan</h2>
        <p>{escape(executive.get("recommended_plan_summary", ""))}</p>
        {featured_plan}
        {additional_plans}
      </section>

      <section class="panel stagger">
        <h2>Why Leadership Should Care</h2>
        <p>{escape(executive.get("business_impact", ""))}</p>
        <div class="metrics">
          {"".join(_metric_card(item.get("title", "Metric"), item.get("value", "")) for item in executive.get("top_findings", [])[:4])}
        </div>
        <details>
          <summary>Technical coverage and confidence</summary>
          <p>{escape(executive.get("confidence_statement", ""))}</p>
          <div class="summary-grid">
            {_metric_card("Workloads", summary.get("workloads", 0))}
            {_metric_card("Service accounts", summary.get("service_accounts", 0))}
            {_metric_card("Secrets", summary.get("secrets", 0))}
            {_metric_card("Permissions", summary.get("permissions", 0))}
            {_metric_card("Graph nodes", summary.get("graph_nodes", 0))}
            {_metric_card("Graph edges", summary.get("graph_edges", 0))}
          </div>
        </details>
      </section>
    </div>

    <section class="panel stagger" style="margin-top: 22px;">
      <h2>Attack Stories</h2>
      <p>These are the clearest paths the engine found from exposed workloads to your crown jewels.</p>
      {stories}
    </section>
  </main>
</body>
</html>"""


def render_home_page(cards: list[dict[str, Any]], auth_enabled: bool, link_suffix: str = "") -> str:
    overview_cards = []
    for card in cards:
        run = card.get("run", {})
        executive = card.get("executive", {})
        summary = card.get("summary", {})
        href = f"/dashboard/runs/{run.get('id', '')}{link_suffix}"
        overview_cards.append(
            '<a class="home-card" href="{href}">'
            '<span class="home-kicker">Analysis run #{run_id}</span>'
            "<h3>{headline}</h3>"
            "<p>{body}</p>"
            '<div class="home-meta">'
            '<span>Paths {paths}</span>'
            '<span>Actions {actions}</span>'
            '<span>Risk {risk}</span>'
            "</div>"
            "</a>".format(
                href=escape(href),
                run_id=escape(str(run.get("id", ""))),
                headline=escape(executive.get("headline", "Security posture overview")),
                body=escape(executive.get("non_technical_summary", "")),
                paths=escape(str(summary.get("baseline_paths", 0))),
                actions=escape(str(summary.get("candidate_actions", 0))),
                risk=escape(executive.get("risk_level", "elevated")),
            )
        )

    empty_state = (
        '<div class="empty-state"><h2>No analyses yet</h2>'
        "<p>Create a tenant, workspace, environment and run an analysis to unlock the executive dashboard.</p>"
        "</div>"
    )

    auth_note = (
        "<p class='note'>API key protection is enabled. You can keep browsing these dashboards by passing <code>?api_key=...</code> in the URL or using the <code>X-API-Key</code> header.</p>"
        if auth_enabled
        else "<p class='note'>Local developer mode is active. Set <code>EVONHI_API_KEY</code> to protect the API and dashboards.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EvoNHI Control Center</title>
  <style>
    :root {{
      --bg: #f3efe5;
      --text: #1f2a2e;
      --muted: #5f6c71;
      --card: rgba(255,255,255,0.72);
      --line: rgba(31,42,46,0.12);
      --accent: #0f766e;
      --accent-soft: #d5eee8;
      --headline-font: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
      --body-font: "Avenir Next", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: var(--body-font);
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(15,118,110,0.14), transparent 28%),
        linear-gradient(180deg, #f7f3eb 0%, var(--bg) 100%);
      min-height: 100vh;
    }}
    main {{
      width: min(1100px, calc(100% - 32px));
      margin: 0 auto;
      padding: 36px 0 56px;
    }}
    .hero {{
      padding: 28px;
      border-radius: 28px;
      background: linear-gradient(145deg, rgba(255,255,255,0.76), rgba(255,255,255,0.58));
      border: 1px solid var(--line);
      box-shadow: 0 24px 60px rgba(31,42,46,0.08);
    }}
    h1, h2, h3 {{ font-family: var(--headline-font); margin: 0; letter-spacing: -0.02em; }}
    h1 {{ font-size: clamp(2.2rem, 4vw, 4rem); max-width: 12ch; }}
    p {{ line-height: 1.6; color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      margin-top: 24px;
    }}
    .home-card {{
      display: block;
      text-decoration: none;
      color: inherit;
      padding: 22px;
      border-radius: 24px;
      background: var(--card);
      border: 1px solid var(--line);
      box-shadow: 0 18px 44px rgba(31,42,46,0.08);
      transition: transform 180ms ease, box-shadow 180ms ease;
    }}
    .home-card:hover {{
      transform: translateY(-4px);
      box-shadow: 0 26px 56px rgba(31,42,46,0.12);
    }}
    .home-kicker {{
      display: inline-block;
      padding: 8px 12px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 0.82rem;
      margin-bottom: 16px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
    }}
    .home-meta {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 18px;
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .note {{
      margin-top: 16px;
      padding: 14px 16px;
      border-left: 4px solid var(--accent);
      background: rgba(15,118,110,0.08);
      border-radius: 10px;
    }}
    .empty-state {{
      margin-top: 24px;
      padding: 28px;
      border-radius: 24px;
      background: rgba(255,255,255,0.62);
      border: 1px dashed var(--line);
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>EvoNHI Control Center</h1>
      <p>Security analytics for Kubernetes non-human identities, now with an executive lens that explains what is exposed, why it matters and which remediation plan gives the best trade-off.</p>
      {auth_note}
    </section>
    <div class="grid">
      {''.join(overview_cards) or empty_state}
    </div>
  </main>
</body>
</html>"""
