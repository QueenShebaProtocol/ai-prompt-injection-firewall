"""SHEBA SHIELD — Master Stylesheet & Design System.
High-scale, fixed-sidebar layout faithfully reproducing index/index.html.
"""

from __future__ import annotations

import streamlit as st

MASTER_CSS = """
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@500;600;700&display=swap" rel="stylesheet" />

<style>
  :root {
    --bg: #070B16;
    --surface: #0E1424;
    --surface-2: #131B30;
    --line: #1F2942;
    --line-soft: #182136;
    --gold: #D9AE5B;
    --gold-2: #F1D08C;
    --gold-dim: rgba(217, 174, 91, .16);
    --ivory: #ECE6D6;
    --muted: #8C95AB;
    --faint: #5E6782;
    --danger: #E5554F;
    --danger-dim: rgba(229, 85, 79, .16);
    --safe: #3DBE8B;
    --safe-dim: rgba(61, 190, 139, .16);
    --warn: #E7A13C;
    --warn-dim: rgba(231, 161, 60, .16);
    --radius: 14px;
    --sidebar-width: 248px;
  }

  /* Global Reset & Body Styling */
  * { box-sizing: border-box; }
  
  html, body, .stApp {
    background: #070B16 !important;
    background-color: #070B16 !important;
    color: var(--ivory) !important;
    font-family: Geist, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    font-size: 15px !important;
    line-height: 1.6 !important;
  }

  .stApp {
    background:
      radial-gradient(1100px 600px at 85% -10%, rgba(217,174,91,.09), transparent 60%),
      radial-gradient(900px 500px at -10% 110%, rgba(229,85,79,.06), transparent 60%),
      var(--bg) !important;
    min-height: 100vh !important;
  }

  /* Hide Streamlit Default Headers, Toolbar & Footers completely */
  header[data-testid="stHeader"],
  [data-testid="stHeader"],
  header,
  footer,
  #MainMenu,
  div[data-testid="stToolbar"],
  div[data-testid="stDecoration"],
  div[data-testid="stStatusWidget"] {
    display: none !important;
    height: 0 !important;
    min-height: 0 !important;
    max-height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
    visibility: hidden !important;
    pointer-events: none !important;
  }

  div[data-testid="stAppViewContainer"],
  div[data-testid="stAppViewContainer"] > section.main {
    padding-top: 0 !important;
    margin-top: 0 !important;
  }

  .main .block-container,
  div[data-testid="stMainBlockContainer"],
  div[data-testid="stAppViewBlockContainer"] {
    max-width: 100% !important;
    width: 100% !important;
    padding: 24px 32px 48px 32px !important;
    padding-top: 24px !important;
    margin-top: 0 !important;
    box-sizing: border-box !important;
  }

  /* ------------------------------------------------------------- 
     FIXED, PERMANENT, NON-COLLAPSIBLE DESKTOP SIDEBAR (248px)
     ------------------------------------------------------------- */
  section[data-testid="stSidebar"] {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    bottom: 0 !important;
    height: 100vh !important;
    width: var(--sidebar-width) !important;
    min-width: var(--sidebar-width) !important;
    max-width: var(--sidebar-width) !important;
    transform: none !important;
    transition: none !important;
    visibility: visible !important;
    display: flex !important;
    flex-direction: column !important;
    z-index: 1000 !important;
    overflow: hidden !important;
    border-right: 1px solid var(--line) !important;
    background: linear-gradient(180deg, #0B1120 0%, #080C18 100%) !important;
    box-shadow: 4px 0 24px rgba(0, 0, 0, 0.45) !important;
  }
  
  section[data-testid="stSidebar"] > div:first-child,
  section[data-testid="stSidebar"] [data-testid="stSidebarContent"],
  section[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] {
    height: 100% !important;
    min-height: 100vh !important;
    max-height: 100vh !important;
    display: flex !important;
    flex-direction: column !important;
    padding: 0 !important;
    overflow: hidden !important;
    flex: 1 1 auto !important;
  }

  section[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] > div,
  section[data-testid="stSidebar"] [data-testid="stVerticalBlock"],
  section[data-testid="stSidebar"] .stVerticalBlock {
    height: 100% !important;
    min-height: 100vh !important;
    max-height: 100vh !important;
    display: flex !important;
    flex-direction: column !important;
    padding: 22px 16px !important;
    gap: 0 !important;
    box-sizing: border-box !important;
    overflow: hidden !important;
    flex: 1 1 auto !important;
  }

  /* Auto-spacer pushes everything below it to the bottom */
  .side-spacer {
    flex: 1 1 auto !important;
    flex-grow: 1 !important;
    min-height: 20px !important;
    display: block !important;
  }
  section[data-testid="stSidebar"] div:has(.side-spacer),
  section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] > div:has(.side-spacer),
  section[data-testid="stSidebar"] .stVerticalBlock > div:has(.side-spacer) {
    flex: 1 1 auto !important;
    flex-grow: 1 !important;
    min-height: 20px !important;
    margin: 0 !important;
    padding: 0 !important;
  }

  /* PUSH TO BOTTOM: Target the selectbox container so footer sits at the bottom */
  section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] > div:has([data-testid="stSelectbox"]),
  section[data-testid="stSidebar"] .stVerticalBlock > div:has([data-testid="stSelectbox"]),
  section[data-testid="stSidebar"] div[data-testid="stElementContainer"]:has([data-testid="stSelectbox"]),
  section[data-testid="stSidebar"] div[data-testid="element-container"]:has([data-testid="stSelectbox"]),
  section[data-testid="stSidebar"] div:has(> [data-testid="stSelectbox"]),
  section[data-testid="stSidebar"] [data-testid="stSelectbox"] {
    margin-top: auto !important;
    margin-bottom: 0 !important;
    width: 100% !important;
  }

  [data-testid="stSidebarNav"],
  [data-testid="stSidebarNavSeparator"],
  ul[data-testid="stSidebarNavItems"],
  div[data-testid="stSidebarHeader"],
  div[data-testid="stToolbarActions"],
  div[data-testid="stStatusWidget"],
  button[data-testid="stBaseButton-header"],
  div[data-testid="stDeployButton"] {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
  }

  /* Completely eliminate all collapse & hamburger toggle controls */
  [data-testid="stSidebarCollapseButton"],
  [data-testid="stSidebarTrigger"],
  [data-testid="collapsedControl"],
  button[kind="header"] {
    display: none !important;
    visibility: hidden !important;
    pointer-events: none !important;
  }

  /* Offset main content so it NEVER overlaps the sidebar */
  div[data-testid="stAppViewContainer"] {
    margin-left: var(--sidebar-width) !important;
    width: calc(100% - var(--sidebar-width)) !important;
    max-width: calc(100% - var(--sidebar-width)) !important;
    min-height: 100vh !important;
  }

  /* Typography Scale */
  .serif {
    font-family: Cinzel, serif !important;
    letter-spacing: .04em !important;
  }
  .mono {
    font-family: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
  }

  /* Brand Header (Faithful to index.html lines 33-36: NO border-bottom divider) */
  .brand {
    display: flex !important;
    align-items: center !important;
    gap: 12px !important;
    padding: 0 6px !important;
    border-bottom: none !important;
    margin-bottom: 20px !important;
  }
  .brand img {
    width: 44px !important;
    height: 44px !important;
    border-radius: 10px !important;
    border: 1px solid var(--gold-dim) !important;
    object-fit: cover !important;
  }
  .brand b {
    display: block !important;
    font-family: Cinzel, serif !important;
    font-size: 17px !important;
    color: var(--gold-2) !important;
    letter-spacing: .12em !important;
    line-height: 1.1 !important;
  }
  .brand small {
    display: block !important;
    font-size: 9.5px !important;
    color: var(--muted) !important;
    letter-spacing: .22em !important;
    text-transform: uppercase !important;
    margin-top: 4px !important;
  }

  /* Sidebar Navigation */
  .nav {
    display: flex !important;
    flex-direction: column !important;
    gap: 2px !important;
    margin-bottom: 0 !important;
  }
  .nav-label {
    font-size: 10px !important;
    letter-spacing: .2em !important;
    text-transform: uppercase !important;
    color: var(--faint) !important;
    padding: 0 10px 8px !important;
    font-weight: 600 !important;
    display: block !important;
  }
  .nav a.nav-btn {
    display: flex !important;
    align-items: center !important;
    gap: 10px !important;
    background: none !important;
    border: 0 !important;
    border-radius: 8px !important;
    padding: 9px 10px !important;
    color: var(--muted) !important;
    text-decoration: none !important;
    transition: .15s !important;
    position: relative !important;
    font-size: 13.5px !important;
    font-weight: 500 !important;
    margin-bottom: 2px !important;
  }
  .nav a.nav-btn svg {
    width: 17px !important;
    height: 17px !important;
    flex: none !important;
  }
  .nav a.nav-btn:hover {
    color: var(--ivory) !important;
    background: var(--surface) !important;
  }
  .nav a.nav-btn.active {
    color: var(--gold-2) !important;
    background: var(--gold-dim) !important;
    font-weight: 500 !important;
    border-radius: 8px !important;
  }
  /* Eliminate floating yellow notch on active nav */
  .nav a.nav-btn.active::before,
  .nav a.nav-btn::before,
  [data-testid="stSidebar"] [data-testid="stPageLink-NavLink"]::before,
  [data-testid="stSidebar"] [data-testid="stPageLink-NavLink"].active::before,
  [data-testid="stSidebar"] [data-testid="stPageLink-NavLink"][aria-current="page"]::before {
    display: none !important;
    content: none !important;
  }
  .nav a.nav-btn .count {
    margin-left: auto !important;
    font-size: 11px !important;
    background: var(--danger-dim) !important;
    color: var(--danger) !important;
    padding: 1px 7px !important;
    border-radius: 99px !important;
    font-weight: 600 !important;
  }

  [data-testid="stSidebar"] [data-testid="stPageLink-NavLink"] {
    display: flex !important;
    align-items: center !important;
    gap: 10px !important;
    background: none !important;
    border: 0 !important;
    border-radius: 8px !important;
    padding: 9px 10px !important;
    color: var(--muted) !important;
    text-decoration: none !important;
    font-size: 13.5px !important;
    font-weight: 500 !important;
    transition: .15s !important;
    position: relative !important;
    margin-bottom: 2px !important;
  }
  [data-testid="stSidebar"] [data-testid="stPageLink-NavLink"]:hover {
    color: var(--ivory) !important;
    background: var(--surface) !important;
  }
  [data-testid="stSidebar"] [data-testid="stPageLink-NavLink"][aria-current="page"],
  [data-testid="stSidebar"] [data-testid="stPageLink-NavLink"].active {
    color: var(--gold-2) !important;
    background: var(--gold-dim) !important;
    font-weight: 500 !important;
    border-radius: 8px !important;
  }

  /* Sidebar Footer (Pinned to bottom) */
  .side-foot {
    margin-top: auto !important;
    display: flex !important;
    flex-direction: column !important;
    gap: 12px !important;
  }
  section[data-testid="stSidebar"] [data-testid="stSelectbox"] {
    margin-bottom: 0 !important;
  }
  section[data-testid="stSidebar"] [data-testid="stSelectbox"] label,
  section[data-testid="stSidebar"] [data-testid="stSelectbox"] label p {
    font-size: 10px !important;
    letter-spacing: .2em !important;
    text-transform: uppercase !important;
    color: var(--faint) !important;
    font-weight: 600 !important;
    margin-bottom: 6px !important;
    padding: 0 !important;
  }
  section[data-testid="stSidebar"] [data-testid="stSelectbox"] div[data-baseweb="select"] > div {
    background: var(--surface-2) !important;
    border: 1px solid var(--line) !important;
    border-radius: 8px !important;
    min-height: 38px !important;
    height: 38px !important;
    color: var(--ivory) !important;
    font-size: 13.5px !important;
    box-shadow: none !important;
    padding: 0 10px !important;
  }
  section[data-testid="stSidebar"] [data-testid="stSelectbox"] div[data-baseweb="select"] [data-testid="stMarkdownContainer"] p,
  section[data-testid="stSidebar"] [data-testid="stSelectbox"] div[data-baseweb="select"] span {
    color: var(--ivory) !important;
    font-size: 13.5px !important;
  }
  section[data-testid="stSidebar"] [data-testid="stSelectbox"] div[data-baseweb="select"] svg {
    fill: var(--muted) !important;
  }

  .status-card {
    border: 1px solid var(--line) !important;
    border-radius: 10px !important;
    padding: 12px !important;
    background: var(--surface) !important;
    margin-top: 12px !important;
    margin-bottom: 8px !important;
  }
  .status-row {
    display: flex !important;
    align-items: center !important;
    gap: 8px !important;
    font-size: 12px !important;
    color: var(--muted) !important;
    padding: 3px 0 !important;
  }
  .status-row span:last-child {
    margin-left: auto !important;
    color: var(--ivory) !important;
    font-weight: 500 !important;
  }
  .dot {
    width: 7px !important;
    height: 7px !important;
    border-radius: 50% !important;
    background: var(--safe) !important;
    box-shadow: 0 0 0 3px var(--safe-dim) !important;
    display: inline-block !important;
    flex-shrink: 0 !important;
  }
  .dot.warn {
    background: var(--warn) !important;
    box-shadow: 0 0 0 3px var(--warn-dim) !important;
  }
  .dot.danger {
    background: var(--danger) !important;
    box-shadow: 0 0 0 3px var(--danger-dim) !important;
  }
  .dot.off {
    background: var(--faint) !important;
    box-shadow: none !important;
  }

  /* Controls */
  select.ctl, input.ctl {
    background: var(--surface-2);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 10px 14px;
    width: 100%;
    outline: none;
    color: var(--ivory);
    font-size: 14px;
  }
  select.ctl:focus, input.ctl:focus {
    border-color: var(--gold);
  }

  /* Topbar */
  .topbar {
    display: flex;
    align-items: center;
    gap: 16px;
    justify-content: space-between;
    margin-bottom: 28px;
    flex-wrap: wrap;
  }
  .eyebrow {
    font-size: 11.5px;
    letter-spacing: .24em;
    text-transform: uppercase;
    color: var(--gold);
    font-weight: 700;
  }
  h1 {
    font-family: Cinzel, serif !important;
    font-weight: 700 !important;
    font-size: 34px !important;
    letter-spacing: .03em !important;
    margin-top: 5px !important;
    color: var(--ivory) !important;
    line-height: 1.25 !important;
  }
  .sub {
    color: var(--muted);
    margin-top: 6px;
    max-width: 75ch;
    font-size: 15px;
    line-height: 1.6;
  }
  .actions {
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
  }
  .live {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    font-size: 13px;
    color: var(--muted);
    border: 1px solid var(--line);
    border-radius: 99px;
    padding: 8px 16px;
    background: var(--surface);
    font-weight: 500;
  }
  .live .dot {
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    50% { box-shadow: 0 0 0 7px rgba(61,190,139,0); }
  }

  /* -------------------------------------------------------------
     Profile Dropdown (Royal Chamber / Topbar)
     ------------------------------------------------------------- */
  .sheba-profile-menu {
    position: relative;
    display: flex;
    justify-content: flex-end;
    margin-top: 10px;
    z-index: 1000;
  }

  .sheba-profile-pill {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    background: var(--surface-2, #131B30);
    color: var(--ivory, #ECE6D6);
    border: 1px solid var(--line, #1F2942);
    border-radius: 9999px;
    padding: 4px 14px 4px 5px;
    cursor: pointer;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.5);
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    user-select: none;
  }

  .sheba-profile-pill:hover,
  .sheba-profile-menu.open .sheba-profile-pill {
    box-shadow: 0 6px 20px rgba(217, 174, 91, 0.25);
    transform: translateY(-1px);
    border-color: var(--gold, #D9AE5B);
    background: var(--surface, #0E1424);
  }

  .sheba-profile-avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: var(--gold-dim, rgba(217,174,91,.16));
    border: 1.5px solid var(--gold, #D9AE5B);
    color: var(--gold, #D9AE5B);
    font-weight: 700;
    font-size: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    font-family: Cinzel, serif;
  }

  .sheba-profile-name {
    font-size: 13.5px;
    font-weight: 600;
    color: var(--ivory, #ECE6D6);
    line-height: 1;
    white-space: nowrap;
  }

  .sheba-profile-chevron {
    color: var(--muted, #8C95AB);
    transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    flex-shrink: 0;
  }

  .sheba-profile-menu.open .sheba-profile-chevron {
    transform: rotate(180deg);
    color: var(--gold, #D9AE5B);
  }

  .sheba-profile-dropdown {
    position: absolute;
    top: calc(100% + 8px);
    right: 0;
    min-width: 230px;
    background: var(--surface-2, #131B30);
    color: var(--ivory, #ECE6D6);
    border: 1px solid var(--line, #1F2942);
    border-radius: 14px;
    box-shadow: 0 24px 48px rgba(0, 0, 0, 0.7), 0 4px 16px rgba(0, 0, 0, 0.4);
    padding: 10px 0;
    z-index: 999999;
    display: none;
    animation: shebaProfileFade 0.18s cubic-bezier(0.16, 1, 0.3, 1);
  }

  .sheba-profile-menu.open .sheba-profile-dropdown {
    display: block;
  }

  .sheba-profile-dropdown-header {
    padding: 10px 18px 12px;
    border-bottom: 1px solid var(--line, #1F2942);
  }

  .sheba-profile-dropdown-user {
    font-size: 14px;
    font-weight: 700;
    color: var(--gold-2, #F1D08C);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sheba-profile-dropdown-role {
    font-size: 11.5px;
    color: var(--muted, #8C95AB);
    margin-top: 3px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .sheba-profile-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 11px 18px;
    font-size: 13.5px;
    font-weight: 500;
    text-decoration: none !important;
    color: var(--danger, #E5554F) !important;
    cursor: pointer;
    transition: all 0.15s ease;
    user-select: none;
    background: transparent;
    border: none;
    width: 100%;
    box-sizing: border-box;
  }

  .sheba-profile-item:hover {
    background: var(--danger-dim, rgba(229, 85, 79, .16));
    color: #FF6B65 !important;
  }

  .sheba-profile-item svg {
    stroke: var(--danger, #E5554F);
    transition: transform 0.15s ease;
    flex-shrink: 0;
  }

  .sheba-profile-item:hover svg {
    transform: translateX(2px);
    stroke: #FF6B65;
  }

  /* Hide native fallback sign out button */
  .st-key-btn_sign_out,
  button[key="btn_sign_out"],
  div[data-testid="stButton"]:has(button[key="btn_sign_out"]) {
    display: none !important;
    height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
  }

  @keyframes shebaProfileFade {
    from {
      opacity: 0;
      transform: translateY(-6px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  @media (max-width: 768px) {
    .sheba-profile-menu {
      justify-content: flex-start !important;
      margin-top: 6px !important;
      margin-bottom: 12px !important;
    }
    .sheba-profile-dropdown {
      left: 0 !important;
      right: auto !important;
    }
  }

  /* Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    border: 1px solid var(--line);
    background: var(--surface);
    border-radius: 10px;
    padding: 10px 18px;
    cursor: pointer;
    font-weight: 600;
    font-size: 14px;
    transition: .15s;
    white-space: nowrap;
    color: var(--ivory);
    text-decoration: none;
  }
  .btn:hover {
    border-color: #2D3A5C;
    background: var(--surface-2);
    color: #FFF;
  }
  .btn.gold {
    background: linear-gradient(180deg, var(--gold-2), var(--gold)) !important;
    color: #1A1205 !important;
    border-color: transparent !important;
    font-weight: 700 !important;
  }
  .btn.gold:hover {
    filter: brightness(1.08);
  }

  /* Streamlit Button overrides */
  .stButton > button {
    border: 1px solid var(--line) !important;
    background: var(--surface) !important;
    color: var(--ivory) !important;
    border-radius: 10px !important;
    padding: 10px 18px !important;
    font-size: 14px !important;
    font-weight: 600 !important;
    transition: .15s !important;
  }
  .stButton > button:hover {
    border-color: #2D3A5C !important;
    background: var(--surface-2) !important;
    color: #FFF !important;
  }
  .stButton > button[kind="primary"] {
    background: linear-gradient(180deg, var(--gold-2), var(--gold)) !important;
    color: #1A1205 !important;
    border-color: transparent !important;
    font-weight: 700 !important;
  }

  /* Hero Section */
  .hero {
    display: flex;
    gap: 24px;
    align-items: center;
    border: 1px solid rgba(217, 174, 91, .28);
    border-radius: 16px;
    padding: 26px 32px;
    margin-bottom: 24px;
    background:
      linear-gradient(120deg, rgba(217, 174, 91, .12), transparent 45%),
      repeating-linear-gradient(45deg, transparent 0 24px, rgba(217, 174, 91, .03) 24px 25px),
      var(--surface);
  }
  .hero img {
    width: 84px;
    height: 84px;
    border-radius: 16px;
    flex: none;
    border: 1px solid var(--gold-dim);
    object-fit: cover;
  }
  .hero .shield-state {
    margin-left: auto;
    text-align: right;
  }
  .hero .shield-state b {
    font-family: Cinzel, serif;
    font-size: 24px;
    color: var(--safe);
    display: block;
    letter-spacing: .06em;
  }
  .hero .shield-state span {
    color: var(--muted);
    font-size: 13.5px;
  }

  /* Grids & Cards */
  .grid {
    display: grid;
    gap: 20px;
  }
  .kpis {
    grid-template-columns: repeat(4, 1fr);
  }
  .two {
    grid-template-columns: 2fr 1fr;
  }
  .halves {
    grid-template-columns: 1fr 1fr;
  }
  .modules {
    grid-template-columns: repeat(3, 1fr);
  }
  .mt {
    margin-top: 20px;
  }

  .card {
    background: linear-gradient(180deg, var(--surface), #0C1221);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    padding: 24px;
  }
  .card h3 {
    font-size: 15px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 10px;
    color: var(--ivory);
  }
  .card .hint {
    color: var(--muted);
    font-size: 13px;
    margin-top: 3px;
  }
  .card-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
    margin-bottom: 16px;
  }

  /* KPI Cards */
  .kpi .label {
    font-size: 12px;
    letter-spacing: .15em;
    text-transform: uppercase;
    color: var(--muted);
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 600;
  }
  .kpi .val {
    font-size: 38px;
    font-weight: 700;
    margin-top: 10px;
    letter-spacing: -.02em;
    color: var(--ivory);
  }
  .kpi .delta {
    font-size: 13.5px;
    margin-top: 6px;
    color: var(--muted);
  }
  .kpi .delta b {
    font-weight: 600;
  }
  .up { color: var(--danger); }
  .down { color: var(--safe); }
  .kpi.accent {
    border-color: rgba(217, 174, 91, .45);
    background: linear-gradient(160deg, rgba(217, 174, 91, .15), var(--surface) 55%);
  }
  .kpi.accent .val {
    color: var(--gold-2);
  }
  .ico {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    display: grid;
    place-items: center;
    background: var(--surface-2);
    border: 1px solid var(--line);
    flex-shrink: 0;
  }
  .ico svg {
    width: 17px;
    height: 17px;
  }

  /* Inspection Pipeline */
  .pipeline {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 14px;
    align-items: stretch;
  }
  .stage {
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 16px;
    background: var(--surface-2);
    position: relative;
  }
  .stage .k {
    font-size: 11px;
    letter-spacing: .18em;
    color: var(--gold);
    text-transform: uppercase;
    font-weight: 600;
  }
  .stage .n {
    font-weight: 600;
    margin-top: 6px;
    font-size: 14.5px;
  }
  .stage .m {
    font-size: 13px;
    color: var(--muted);
    margin-top: 8px;
    display: flex;
    justify-content: space-between;
  }
  .stage .bar {
    height: 6px;
    background: var(--line);
    border-radius: 6px;
    margin-top: 12px;
    overflow: hidden;
  }
  .stage .bar i {
    display: block;
    height: 100%;
    background: var(--gold);
  }
  .stage.end {
    border-color: rgba(61, 190, 139, .45);
  }
  .stage.end .k {
    color: var(--safe);
  }
  .stage.end .bar i {
    background: var(--safe);
  }

  /* Dashboard Module Link Cards */
  .module {
    cursor: pointer;
    transition: .15s;
    text-align: left;
    color: inherit;
    text-decoration: none;
    display: block;
    padding: 24px;
  }
  .module:hover {
    border-color: rgba(217, 174, 91, .5);
    transform: translateY(-2px);
  }
  .module .k {
    font-size: 11px;
    letter-spacing: .2em;
    color: var(--gold);
    text-transform: uppercase;
    font-weight: 600;
  }
  .module b {
    display: block;
    font-family: Cinzel, serif;
    font-size: 18px;
    margin-top: 8px;
    color: var(--gold-2);
  }
  .module p {
    color: var(--muted);
    font-size: 13.5px;
    margin-top: 6px;
  }

  /* Tables */
  .table-wrap {
    overflow-x: auto;
    border: 1px solid var(--line);
    border-radius: 12px;
    background: var(--surface);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }
  th {
    text-align: left;
    font-weight: 600;
    color: var(--muted);
    font-size: 12px;
    letter-spacing: .1em;
    text-transform: uppercase;
    padding: 14px 18px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--line);
    white-space: nowrap;
  }
  td {
    padding: 14px 18px;
    border-bottom: 1px solid var(--line-soft);
    white-space: nowrap;
    color: var(--ivory);
  }
  tbody tr {
    transition: .12s;
  }
  tbody tr:hover {
    background: rgba(217, 174, 91, .06);
  }
  tbody tr:last-child td {
    border-bottom: 0;
  }
  td.trunc {
    max-width: 420px;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--muted);
  }

  /* Badges & Tags */
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: .06em;
    padding: 4px 11px;
    border-radius: 99px;
  }
  .badge::before {
    content: "";
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
  }
  .b-blocked { color: var(--danger); background: var(--danger-dim); }
  .b-passed { color: var(--safe); background: var(--safe-dim); }
  .b-redacted { color: var(--warn); background: var(--warn-dim); }

  .tag {
    font-size: 12px;
    padding: 3px 10px;
    border-radius: 6px;
    border: 1px solid var(--line);
    color: var(--ivory);
    background: var(--surface-2);
    font-weight: 500;
  }
  .sev-CRITICAL { color: var(--danger); border-color: rgba(229,85,79,.4); }
  .sev-HIGH { color: var(--warn); border-color: rgba(231,161,60,.4); }
  .sev-MEDIUM { color: var(--gold-2); border-color: rgba(217,174,91,.4); }
  .sev-LOW { color: var(--muted); }

  /* Risk Bar */
  .risk {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 140px;
  }
  .risk .track {
    flex: 1;
    height: 6px;
    background: var(--line);
    border-radius: 6px;
    overflow: hidden;
  }
  .risk .track i {
    display: block;
    height: 100%;
    border-radius: 6px;
  }
  .risk span {
    font-size: 13px;
    width: 36px;
    text-align: right;
  }

  /* Banner */
  .banner {
    display: flex;
    gap: 14px;
    align-items: flex-start;
    justify-content: space-between;
    border: 1px solid rgba(231, 161, 60, .35);
    background: linear-gradient(90deg, rgba(231, 161, 60, .12), rgba(231, 161, 60, .03));
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 18px;
    color: #F3D9A9;
    font-size: 13.5px;
    line-height: 1.55;
    position: relative;
    transition: opacity 0.2s ease, max-height 0.25s ease, margin 0.25s ease, padding 0.25s ease;
  }
  .banner.dismissed {
    opacity: 0 !important;
    max-height: 0 !important;
    padding-top: 0 !important;
    padding-bottom: 0 !important;
    margin-top: 0 !important;
    margin-bottom: 0 !important;
    overflow: hidden !important;
    border: none !important;
    pointer-events: none !important;
  }
  .banner svg {
    width: 20px;
    height: 20px;
    flex: none;
    margin-top: 2px;
    color: var(--warn);
  }
  .banner .banner-close {
    background: transparent !important;
    border: none !important;
    color: #D9AE5B !important;
    opacity: 0.55 !important;
    cursor: pointer !important;
    padding: 0 !important;
    margin: 0 !important;
    margin-left: 12px !important;
    width: 20px !important;
    height: 20px !important;
    min-width: 20px !important;
    min-height: 20px !important;
    max-width: 20px !important;
    max-height: 20px !important;
    border-radius: 50% !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    flex: none !important;
    line-height: 1 !important;
    transition: all 0.15s ease !important;
  }
  .banner .banner-close:hover {
    opacity: 1 !important;
    color: #FFFFFF !important;
    background: rgba(255, 255, 255, 0.12) !important;
  }
  .banner .banner-close svg {
    width: 11px !important;
    height: 11px !important;
    min-width: 11px !important;
    min-height: 11px !important;
    max-width: 11px !important;
    max-height: 11px !important;
    margin: 0 !important;
    padding: 0 !important;
    color: inherit !important;
    stroke: currentColor !important;
    stroke-width: 2.2 !important;
    display: block !important;
  }

  /* Filters Form */
  .filters {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 16px;
    align-items: end;
  }
  .field label {
    display: block;
    font-size: 12px;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 8px;
    font-weight: 600;
  }

  /* Decision Drawer & Evidence Slide-out matching index.html */
  .scrim {
    position: fixed !important;
    inset: 0 !important;
    background: rgba(3, 6, 14, .65) !important;
    backdrop-filter: blur(4px) !important;
    -webkit-backdrop-filter: blur(4px) !important;
    opacity: 0 !important;
    visibility: hidden !important;
    pointer-events: none !important;
    transition: opacity .22s ease, visibility .22s ease !important;
    z-index: 9999 !important;
  }
  .scrim.open {
    opacity: 1 !important;
    visibility: visible !important;
    pointer-events: auto !important;
  }
  .drawer {
    position: fixed !important;
    top: 0 !important;
    right: 0 !important;
    height: 100vh !important;
    width: min(540px, 100%) !important;
    background: var(--surface) !important;
    border-left: 1px solid var(--line) !important;
    transform: translateX(100%) !important;
    transition: transform .25s cubic-bezier(.16, 1, .3, 1), visibility .25s ease !important;
    z-index: 10000 !important;
    overflow-y: auto !important;
    padding: 26px !important;
    box-sizing: border-box !important;
    box-shadow: -8px 0 36px rgba(0, 0, 0, .55) !important;
    visibility: hidden !important;
    pointer-events: none !important;
  }
  .drawer.open {
    transform: none !important;
    visibility: visible !important;
    pointer-events: auto !important;
  }
  .kv {
    display: grid !important;
    grid-template-columns: 140px 1fr !important;
    gap: 9px 14px !important;
    font-size: 13.5px !important;
    margin-top: 16px !important;
  }
  .kv dt {
    color: var(--muted) !important;
  }
  .prompt-box {
    margin-top: 14px !important;
    background: #080D19 !important;
    border: 1px solid var(--line) !important;
    border-radius: 10px !important;
    padding: 16px !important;
    font-size: 13px !important;
    line-height: 1.55 !important;
    white-space: pre-wrap !important;
    word-break: break-word !important;
    color: #F1DDB0 !important;
  }
  .layer-trace {
    display: flex !important;
    flex-direction: column !important;
    gap: 8px !important;
    margin-top: 14px !important;
  }
  .trace {
    display: flex !important;
    align-items: center !important;
    gap: 10px !important;
    border: 1px solid var(--line) !important;
    border-radius: 8px !important;
    padding: 10px 14px !important;
    font-size: 13px !important;
  }
  .trace .t-res {
    margin-left: auto !important;
    font-size: 12.5px !important;
    font-weight: 500 !important;
  }
  .trace .t-res.up { color: var(--danger) !important; }
  .trace .t-res.down { color: var(--safe) !important; }
  .trace .t-res.muted { color: var(--muted) !important; font-style: italic !important; }
  tbody tr.clickable { cursor: pointer !important; }
  tbody tr.clickable:hover { background: rgba(217, 174, 91, .07) !important; }
  tbody tr.clickable:hover td { background: rgba(217, 174, 91, .09) !important; }

  /* Streamlit components iframe zero-height cleaner */
  iframe[height="0"], div[data-testid="stCustomComponentV1"]:has(iframe[height="0"]) {
    display: none !important;
    height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
  }

  /* Login / Royal Chamber */
  .login-wrap {
    display: grid;
    place-items: center;
    padding: 60px 0;
  }
  .login {
    width: min(480px, 100%);
    text-align: center;
    padding: 40px;
    background: linear-gradient(180deg, var(--surface), #0C1221);
    border: 1px solid var(--line);
    border-radius: 20px;
    box-shadow: 0 12px 48px rgba(0, 0, 0, 0.5);
  }
  .login img {
    width: 96px;
    height: 96px;
    border-radius: 20px;
    margin: 0 auto 16px;
    display: block;
    border: 1px solid var(--gold-dim);
    object-fit: cover;
  }

  /* Zone Bar */
  .zone {
    margin-top: 16px;
    height: 38px;
    border-radius: 10px;
    display: flex;
    overflow: hidden;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: .08em;
    text-transform: uppercase;
  }
  .zone div {
    display: grid;
    place-items: center;
    transition: width .15s;
  }
  .z-pass { background: var(--safe-dim); color: var(--safe); }
  .z-judge { background: var(--gold-dim); color: var(--gold-2); }
  .z-block { background: var(--danger-dim); color: var(--danger); }

  /* Chips */
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 16px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    border: 1px solid var(--line);
    background: var(--surface-2);
    border-radius: 99px;
    padding: 7px 14px;
    font-size: 13.5px;
    color: var(--ivory);
  }

  /* Savebar */
  .savebar {
    position: sticky;
    bottom: 20px;
    margin-top: 24px;
    display: flex;
    align-items: center;
    gap: 14px;
    justify-content: space-between;
    background: rgba(14, 20, 36, .96);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(217, 174, 91, .4);
    border-radius: 14px;
    padding: 16px 22px;
    flex-wrap: wrap;
    z-index: 20;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }

  /* Audit List */
  .audit li {
    list-style: none;
    display: flex;
    gap: 16px;
    padding: 12px 0;
    border-bottom: 1px solid var(--line-soft);
    font-size: 13.5px;
  }
  .audit li:last-child {
    border-bottom: 0;
  }
  .audit time {
    color: var(--faint);
    width: 150px;
    flex: none;
  }

  /* Flag List */
  .flag-list li {
    list-style: none;
    display: flex;
    justify-content: space-between;
    padding: 12px 0;
    border-bottom: 1px solid var(--line-soft);
    font-size: 14px;
  }
  .flag-list li:last-child {
    border-bottom: 0;
  }

  /* Streamlit Dialog Modal styling */
  div[data-testid="stDialog"] div[role="dialog"] {
    background: var(--surface) !important;
    border: 1px solid var(--line) !important;
    border-radius: 16px !important;
    color: var(--ivory) !important;
    padding: 24px !important;
    max-width: 800px !important;
    width: 800px !important;
  }

  
  /* Single Unified Royal Chamber Login Card matching Image 2 */
  div[data-testid="stForm"] {
    background: linear-gradient(180deg, var(--surface), #0C1221) !important;
    border: 1px solid var(--line) !important;
    border-radius: 18px !important;
    padding: 38px 34px 28px !important;
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.45) !important;
    box-sizing: border-box !important;
  }
  div[data-testid="stForm"] > div {
    gap: 16px !important;
  }
  div[data-testid="stForm"] label p {
    font-size: 11px !important;
    letter-spacing: .12em !important;
    text-transform: uppercase !important;
    color: var(--muted) !important;
    font-weight: 600 !important;
    margin-bottom: 6px !important;
  }
  div[data-testid="stForm"] input {
    background: var(--surface-2) !important;
    border: 1px solid var(--line) !important;
    border-radius: 8px !important;
    padding: 10px 12px !important;
    font-size: 13.5px !important;
    color: var(--ivory) !important;
  }
  div[data-testid="stForm"] input:focus {
    border-color: var(--gold) !important;
  }
  div[data-testid="stForm"] button[kind="primary"],
  div[data-testid="stForm"] button[data-testid="stBaseButton-primary"] {
    background: linear-gradient(180deg, var(--gold-2), var(--gold)) !important;
    color: #1A1205 !important;
    border: none !important;
    font-weight: 700 !important;
    font-size: 14.5px !important;
    border-radius: 10px !important;
    padding: 11px 18px !important;
    margin-top: 8px !important;
    box-shadow: 0 4px 14px rgba(217, 174, 91, 0.2) !important;
    transition: filter .15s ease !important;
  }
  div[data-testid="stForm"] button[kind="primary"]:hover,
  div[data-testid="stForm"] button[data-testid="stBaseButton-primary"]:hover {
    filter: brightness(1.08) !important;
  }

  /* Streamlit text inputs & selects */
  div[data-testid="stTextInput"] input,
  div[data-testid="stTextArea"] textarea,
  div[data-baseweb="select"] {
    background: var(--surface-2) !important;
    border-color: var(--line) !important;
    color: var(--ivory) !important;
    border-radius: 10px !important;
    font-size: 14px !important;
  }

  /* Streamlit label text */
  div[data-testid="stTextInput"] label,
  div[data-testid="stSelectbox"] label,
  div[data-testid="stSlider"] label,
  div[data-testid="stRadio"] label p,
  div[data-testid="stNumberInput"] label {
    font-size: 13px !important;
    color: var(--muted) !important;
    font-weight: 600 !important;
    letter-spacing: .08em !important;
    text-transform: uppercase !important;
  }

  /* Streamlit slider */
  div[data-testid="stSlider"] div[data-baseweb="slider"] div[role="slider"] {
    background-color: var(--gold) !important;
    border-color: var(--gold-2) !important;
  }
  div[data-testid="stSlider"] div[data-baseweb="slider"] div[data-testid="stThumbValue"] {
    color: var(--gold-2) !important;
    font-size: 13px !important;
  }

  /* Radio tabs - sleek segmented pill buttons matching index.html */
  div[data-testid="stRadio"] div[role="radiogroup"] label {
    background: var(--surface-2) !important;
    border: 1px solid var(--line) !important;
    border-radius: 8px !important;
    padding: 7px 16px !important;
    color: var(--muted) !important;
    font-weight: 500 !important;
    font-size: 13.5px !important;
    letter-spacing: normal !important;
    text-transform: none !important;
    cursor: pointer !important;
    transition: .15s !important;
  }
  /* Hide circular radio indicator completely */
  div[data-testid="stRadio"] div[role="radiogroup"] label > div:first-child,
  div[data-testid="stRadio"] div[role="radiogroup"] label input[type="radio"] {
    display: none !important;
  }
  div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) {
    background: var(--gold-dim) !important;
    border-color: rgba(217,174,91,.5) !important;
    color: var(--gold-2) !important;
    font-weight: 600 !important;
  }

  /* =========================================================================
     THREAT LOGS FILTRATION BOARD (Faithfully matching target design screenshot)
     ========================================================================= */
  div[data-testid="stVerticalBlockBorderWrapper"] {
    background: #080D1A !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 8px !important;
    padding: 16px 20px 14px 20px !important;
    margin-bottom: 20px !important;
    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3) !important;
  }

  /* Labels in filtration board: small uppercase, letter spaced, muted slate */
  div[data-testid="stVerticalBlockBorderWrapper"] label,
  div[data-testid="stVerticalBlockBorderWrapper"] [data-testid="stWidgetLabel"] p {
    font-size: 11px !important;
    letter-spacing: .08em !important;
    text-transform: uppercase !important;
    color: #64748B !important;
    font-weight: 600 !important;
    margin-bottom: 6px !important;
    font-family: inherit !important;
  }

  /* Selectboxes and Text Inputs in filtration board */
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-baseweb="select"] > div,
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stTextInput"] input {
    background: #0F1626 !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
    color: #E2E8F0 !important;
    font-size: 13px !important;
    min-height: 38px !important;
    height: 38px !important;
    box-sizing: border-box !important;
  }

  div[data-testid="stVerticalBlockBorderWrapper"] div[data-baseweb="select"] > div:hover,
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stTextInput"] input:hover,
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-baseweb="select"] > div:focus-within,
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stTextInput"] input:focus {
    border-color: rgba(217, 174, 91, 0.4) !important;
  }

  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stTextInput"] input::placeholder {
    color: #475569 !important;
    font-size: 13px !important;
  }

  /* Dropdown icon in select */
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-baseweb="select"] svg {
    color: #64748B !important;
    width: 18px !important;
    height: 18px !important;
  }

  /* Slider in filtration board */
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stSlider"] {
    padding-top: 2px !important;
  }
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stSlider"] div[data-baseweb="slider"] {
    padding-top: 10px !important;
    padding-bottom: 0px !important;
  }
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stSlider"] div[role="slider"] {
    background-color: #D9AE5B !important;
    border: 2px solid #D9AE5B !important;
    width: 14px !important;
    height: 14px !important;
    box-shadow: 0 0 6px rgba(217, 174, 91, 0.4) !important;
  }
  /* Hide the min / max / tick marks underneath the slider */
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stSlider"] [data-testid="stSliderTickBar"],
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stSlider"] div[data-testid="stSliderTickBarMin"],
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stSlider"] div[data-testid="stSliderTickBarMax"],
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stSlider"] div[data-baseweb="slider"] + div {
    display: none !important;
  }
  /* Hide thumb value floating popup */
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stSlider"] div[data-testid="stThumbValue"] {
    display: none !important;
  }

  /* Segmented pill container in filtration board */
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stRadio"] div[role="radiogroup"] {
    display: inline-flex !important;
    flex-direction: row !important;
    align-items: center !important;
    background: #0D1424 !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
    padding: 3px !important;
    gap: 2px !important;
    width: auto !important;
  }

  /* Each pill item */
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stRadio"] div[role="radiogroup"] label {
    background: transparent !important;
    border: none !important;
    border-radius: 4px !important;
    padding: 4px 14px !important;
    margin: 0 !important;
    color: #7D8B9F !important;
    font-size: 12px !important;
    font-weight: 500 !important;
    cursor: pointer !important;
    transition: all 0.15s ease !important;
    display: inline-flex !important;
    align-items: center !important;
  }

  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stRadio"] div[role="radiogroup"] label:hover {
    color: #E2E8F0 !important;
    background: rgba(255, 255, 255, 0.04) !important;
  }

  /* Active / checked pill */
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) {
    background: #1C263A !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3) !important;
  }

  /* Hide circular radio indicator completely */
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stRadio"] div[role="radiogroup"] label > div:first-child,
  div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stRadio"] div[role="radiogroup"] label input[type="radio"] {
    display: none !important;
  }

  /* Matching count label on the right */
  .filter-count-label {
    text-align: right;
    color: #64748B;
    font-size: 12px;
    font-weight: 400;
    padding-top: 7px;
    letter-spacing: 0.01em;
  }

  /* Fullscreen expanded table mode (Wazuh / security dashboard style) */
  .table-wrap.fullscreen {
    position: fixed !important;
    inset: 16px !important;
    z-index: 9998 !important;
    background: #0B1120 !important;
    border: 1px solid var(--line) !important;
    border-radius: 14px !important;
    box-shadow: 0 16px 64px rgba(0, 0, 0, 0.85) !important;
    padding: 24px !important;
    overflow: auto !important;
    max-height: calc(100vh - 32px) !important;
  }

  /* Streamlit selectbox dropdown */
  div[data-baseweb="popover"] ul {
    background: var(--surface-2) !important;
    border: 1px solid var(--line) !important;
    border-radius: 10px !important;
  }
  div[data-baseweb="popover"] li {
    color: var(--ivory) !important;
    font-size: 14px !important;
  }
  div[data-baseweb="popover"] li:hover {
    background: var(--gold-dim) !important;
    color: var(--gold-2) !important;
  }

  /* Streamlit data frame / table */
  div[data-testid="stDataFrame"] {
    border: 1px solid var(--line) !important;
    border-radius: 12px !important;
    overflow: hidden !important;
  }

  /* Number inputs */
  div[data-testid="stNumberInput"] input {
    background: var(--surface-2) !important;
    border-color: var(--line) !important;
    color: var(--ivory) !important;
    border-radius: 10px !important;
    font-size: 14px !important;
  }

  /* Streamlit expander */
  div[data-testid="stExpander"] summary {
    background: var(--surface) !important;
    border: 1px solid var(--line) !important;
    border-radius: 12px !important;
    color: var(--ivory) !important;
    font-size: 15px !important;
    font-weight: 600 !important;
    padding: 14px 20px !important;
  }
  div[data-testid="stExpander"] summary:hover {
    border-color: rgba(217,174,91,.4) !important;
    color: var(--gold-2) !important;
  }
  div[data-testid="stExpander"] div[data-testid="stExpanderDetails"] {
    border: 1px solid var(--line) !important;
    border-top: none !important;
    border-bottom-left-radius: 12px !important;
    border-bottom-right-radius: 12px !important;
    background: var(--surface) !important;
    padding: 20px !important;
  }

  /* Primary button: gold */
  .stButton > button[kind="primary"],
  button[data-testid="stBaseButton-primary"] {
    background: linear-gradient(180deg, var(--gold-2), var(--gold)) !important;
    color: #1A1205 !important;
    border-color: transparent !important;
    font-weight: 700 !important;
    font-size: 14px !important;
  }
  .stButton > button[kind="primary"]:hover,
  button[data-testid="stBaseButton-primary"]:hover {
    filter: brightness(1.08) !important;
  }

  /* st.spinner */
  div[data-testid="stSpinner"] p {
    color: var(--gold) !important;
  }

  /* Plotly chart background transparency */
  div[data-testid="stPlotlyChart"] {
    border-radius: 10px !important;
    overflow: hidden;
  }

  /* st.info / st.error / st.warning / st.success */
  div[data-testid="stAlert"] {
    border-radius: 12px !important;
    font-size: 14px !important;
  }

  /* Page spacing */
  div[data-testid="stVerticalBlock"] > div {
    gap: 0 !important;
  }

  /* Ensure no white/light backgrounds bleed through */
  div[data-testid="stAppViewContainer"] > section > div {
    background: transparent !important;
  }

  /* =========================================================================
     RESPONSIVE DESIGN SYSTEM (Desktop >=1200px, Laptop 769-1199px, Tablet 481-768px, Mobile 320-480px)
     ========================================================================= */

  /* Global fluid responsiveness & overflow protection */
  html, body {
    overflow-x: hidden !important;
    max-width: 100vw !important;
  }

  /* Mobile Top Navigation Header (hidden on desktop >=769px) */
  .mobile-nav-header {
    display: none !important;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 16px;
    background: linear-gradient(180deg, #0D1424 0%, #090E1A 100%);
    border-bottom: 1px solid var(--line);
    position: sticky;
    top: 0;
    z-index: 990;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    margin: -24px -32px 20px -32px;
    width: calc(100% + 64px);
    box-sizing: border-box;
  }

  .mobile-nav-btn {
    background: var(--surface-2) !important;
    border: 1px solid var(--line) !important;
    color: var(--gold-2) !important;
    border-radius: 8px !important;
    width: 40px !important;
    height: 40px !important;
    min-width: 40px !important;
    min-height: 40px !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    cursor: pointer !important;
    flex: none !important;
    transition: all 0.15s ease !important;
  }

  .mobile-nav-btn:hover {
    background: var(--gold-dim) !important;
    border-color: rgba(217, 174, 91, 0.4) !important;
    color: #FFFFFF !important;
  }

  .mobile-nav-brand {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 0;
  }

  .mobile-nav-crest {
    width: 28px;
    height: 28px;
    border-radius: 6px;
    border: 1px solid var(--gold-dim);
    object-fit: cover;
    flex: none;
  }

  .mobile-nav-title {
    font-family: Cinzel, serif;
    font-size: 14px;
    font-weight: 700;
    color: var(--gold-2);
    letter-spacing: .08em;
    white-space: nowrap;
  }

  .mobile-nav-sep {
    color: var(--muted);
    font-size: 13px;
    opacity: 0.6;
  }

  .mobile-nav-page {
    font-size: 12.5px;
    color: var(--ivory);
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .mobile-nav-status {
    display: flex;
    align-items: center;
    flex: none;
  }

  .mobile-nav-status .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: var(--surface-2);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 3px 8px;
    font-size: 11px;
    color: var(--muted);
  }

  .mobile-nav-status .status-pill .status-text {
    display: none;
  }

  /* Sidebar Drawer Backdrop Scrim */
  .sidebar-scrim {
    position: fixed;
    inset: 0;
    background: rgba(3, 6, 14, 0.72);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    opacity: 0;
    visibility: hidden;
    pointer-events: none;
    transition: opacity 0.25s ease, visibility 0.25s ease;
    z-index: 9998;
  }

  .sidebar-scrim.open {
    opacity: 1;
    visibility: visible;
    pointer-events: auto;
  }

  /* Sidebar Close Button */
  .sidebar-close-btn {
    display: none !important;
    background: transparent !important;
    border: 1px solid var(--line) !important;
    color: var(--muted) !important;
    border-radius: 6px !important;
    width: 32px !important;
    height: 32px !important;
    align-items: center !important;
    justify-content: center !important;
    cursor: pointer !important;
    transition: all 0.15s ease !important;
    flex: none !important;
  }

  .sidebar-close-btn:hover {
    background: rgba(255, 255, 255, 0.08) !important;
    color: #FFFFFF !important;
    border-color: rgba(217, 174, 91, 0.3) !important;
  }

  .brand-info {
    display: flex;
    align-items: center;
    gap: 12px;
    flex: 1;
    min-width: 0;
  }

  /* -------------------------------------------------------------
     1. SMALL DESKTOP / LAPTOP (769px to 1199px)
     ------------------------------------------------------------- */
  @media (min-width: 769px) and (max-width: 1199px) {
    :root {
      --sidebar-width: 210px !important;
    }

    section[data-testid="stSidebar"] {
      width: 210px !important;
      min-width: 210px !important;
      max-width: 210px !important;
    }

    section[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] > div,
    section[data-testid="stSidebar"] [data-testid="stVerticalBlock"],
    section[data-testid="stSidebar"] .stVerticalBlock {
      padding: 18px 12px !important;
    }

    div[data-testid="stAppViewContainer"] {
      margin-left: 210px !important;
      width: calc(100% - 210px) !important;
      max-width: calc(100% - 210px) !important;
    }

    .main .block-container,
    div[data-testid="stMainBlockContainer"],
    div[data-testid="stAppViewBlockContainer"] {
      padding: 20px 20px 40px 20px !important;
    }

    .nav a.nav-btn {
      padding: 8px 10px !important;
      font-size: 13px !important;
      gap: 9px !important;
    }

    .brand img {
      width: 38px !important;
      height: 38px !important;
    }

    .brand b {
      font-size: 15px !important;
    }

    .grid.kpis {
      grid-template-columns: repeat(2, 1fr) !important;
      gap: 14px !important;
    }

    .grid.two, .grid.halves {
      grid-template-columns: 1fr !important;
      gap: 16px !important;
    }

    .pipeline {
      grid-template-columns: repeat(3, 1fr) !important;
      gap: 12px !important;
    }

    .drawer {
      width: min(500px, 80vw) !important;
    }
  }

  /* -------------------------------------------------------------
     2. TABLET (481px to 768px)
     ------------------------------------------------------------- */
  @media (max-width: 768px) {
    .mobile-nav-header {
      display: flex !important;
      margin: -16px -16px 16px -16px !important;
      width: calc(100% + 32px) !important;
    }

    .sidebar-close-btn {
      display: inline-flex !important;
    }

    /* Content full width: 0 margin offset */
    div[data-testid="stAppViewContainer"] {
      margin-left: 0 !important;
      width: 100% !important;
      max-width: 100% !important;
    }

    .main .block-container,
    div[data-testid="stMainBlockContainer"],
    div[data-testid="stAppViewBlockContainer"] {
      padding: 16px 16px 40px 16px !important;
      max-width: 100% !important;
      width: 100% !important;
    }

    /* Sidebar transforms into slide-in drawer */
    section[data-testid="stSidebar"] {
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      bottom: 0 !important;
      height: 100vh !important;
      width: 290px !important;
      min-width: 290px !important;
      max-width: 85vw !important;
      transform: translateX(-100%) !important;
      transition: transform 0.28s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.28s ease !important;
      z-index: 10000 !important;
      box-shadow: none !important;
      visibility: visible !important;
      overflow-y: auto !important;
    }

    section[data-testid="stSidebar"].drawer-open {
      transform: translateX(0) !important;
      box-shadow: 12px 0 48px rgba(0, 0, 0, 0.75) !important;
    }

    .topbar {
      flex-direction: column !important;
      align-items: flex-start !important;
      gap: 12px !important;
      margin-bottom: 18px !important;
    }

    .topbar h1 {
      font-size: clamp(22px, 5vw, 28px) !important;
    }

    .topbar .actions {
      width: 100% !important;
      justify-content: flex-start !important;
      flex-wrap: wrap !important;
    }

    .hero {
      flex-direction: column !important;
      align-items: flex-start !important;
      gap: 16px !important;
      padding: 18px !important;
    }

    .hero .actions {
      width: 100% !important;
      justify-content: flex-start !important;
    }

    .grid.kpis {
      grid-template-columns: repeat(2, 1fr) !important;
      gap: 12px !important;
    }

    .grid.two, .grid.halves {
      grid-template-columns: 1fr !important;
      gap: 14px !important;
    }

    .grid.modules {
      grid-template-columns: 1fr !important;
      gap: 12px !important;
    }

    .pipeline {
      grid-template-columns: repeat(2, 1fr) !important;
      gap: 10px !important;
    }

    .drawer {
      width: min(480px, 90vw) !important;
    }

    .table-wrap {
      overflow-x: auto !important;
      -webkit-overflow-scrolling: touch !important;
      width: 100% !important;
      max-width: 100% !important;
    }

    .table-wrap table {
      min-width: 680px !important;
    }

    /* Filter card responsiveness */
    div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stHorizontalBlock"] {
      flex-wrap: wrap !important;
      gap: 10px !important;
    }

    div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stHorizontalBlock"] > div[data-testid="column"] {
      flex: 1 1 180px !important;
      min-width: 140px !important;
    }
  }

  /* -------------------------------------------------------------
     3. MOBILE (320px to 480px)
     ------------------------------------------------------------- */
  @media (max-width: 480px) {
    .mobile-nav-header {
      margin: -14px -12px 14px -12px !important;
      width: calc(100% + 24px) !important;
      padding: 8px 12px !important;
    }

    .main .block-container,
    div[data-testid="stMainBlockContainer"],
    div[data-testid="stAppViewBlockContainer"] {
      padding: 14px 12px 36px 12px !important;
    }

    section[data-testid="stSidebar"] {
      width: min(300px, 86vw) !important;
      min-width: min(300px, 86vw) !important;
    }

    .grid.kpis {
      grid-template-columns: repeat(2, 1fr) !important;
      gap: 10px !important;
    }

    .kpi {
      padding: 14px 12px !important;
    }

    .kpi .val {
      font-size: clamp(20px, 5.5vw, 24px) !important;
    }

    .kpi .label {
      font-size: 11px !important;
    }

    .kpi .delta {
      font-size: 11px !important;
    }

    .pipeline {
      grid-template-columns: 1fr !important;
      gap: 10px !important;
    }

    .stage {
      padding: 12px 14px !important;
    }

    .drawer {
      width: 100vw !important;
      max-width: 100vw !important;
      left: 0 !important;
      right: 0 !important;
      padding: 16px !important;
    }

    .kv {
      grid-template-columns: 110px 1fr !important;
      gap: 6px 10px !important;
      font-size: 12.5px !important;
    }

    div[data-testid="stVerticalBlockBorderWrapper"] {
      padding: 14px 12px 12px 12px !important;
    }

    div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stRadio"] div[role="radiogroup"] {
      flex-wrap: wrap !important;
      width: 100% !important;
    }

    div[data-testid="stVerticalBlockBorderWrapper"] div[data-testid="stRadio"] div[role="radiogroup"] label {
      flex: 1 1 45% !important;
      justify-content: center !important;
      text-align: center !important;
    }

    .filter-count-label {
      text-align: left !important;
      padding-top: 4px !important;
    }
  }

  /* -------------------------------------------------------------
     4. SMALL MOBILE (<= 360px)
     ------------------------------------------------------------- */
  @media (max-width: 360px) {
    .grid.kpis {
      grid-template-columns: 1fr !important;
    }

    .mobile-nav-title {
      font-size: 12px !important;
    }

    .mobile-nav-page {
      display: none !important;
    }

    .mobile-nav-sep {
      display: none !important;
    }
  }
</style>
"""


def inject_theme() -> None:
    """Inject the SHEBA SHIELD master design styles into Streamlit."""
    st.markdown(MASTER_CSS, unsafe_allow_html=True)
