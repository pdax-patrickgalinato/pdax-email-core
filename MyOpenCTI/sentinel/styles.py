"""UI theme / CSS injection (kept separate from Streamlit layout code)."""
from __future__ import annotations

import streamlit as st


def inject_styles() -> None:
    """Load fonts + theme. Uses st.html so CSS never leaks as visible page text."""
    st.html(
        """
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Google+Sans+Code:ital,wght@0,300..800;1,300..800&display=swap" rel="stylesheet">
    <style>
      :root {
        --sf-accent: #0d9488;
        --sf-accent-2: #0284c7;
        --sf-danger: #dc2626;
        --sf-warn: #d97706;
        --sf-font: "Google Sans Code", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        --sf-icon-font: "Material Symbols Rounded", "Material Symbols Outlined",
                        "Material Icons", "Material Icons Outlined";
        /* Standard UI body size (browser default-ish) */
        --sf-font-size: 14px;
      }

      html, body, .stApp, [data-testid="stAppViewContainer"],
      [data-testid="stSidebarContent"], .block-container {
        font-family: var(--sf-font);
        font-size: var(--sf-font-size) !important;
      }

      /* Clear Streamlit's top toolbar so the hero never sits under Deploy / menu */
      header[data-testid="stHeader"] {
        background: transparent;
      }
      .block-container {
        padding-top: 3.25rem !important;
        padding-bottom: 2rem;
        max-width: 1380px;
      }
      section[data-testid="stSidebar"] > div {
        padding-top: 1.25rem;
      }

      .stMarkdown, .stText, .stCaption, .stAlert,
      .stSelectbox, .stMultiSelect, .stTextInput, .stTextArea,
      .stNumberInput, .stSlider, .stCheckbox, .stRadio, .stExpander,
      .stTabs, .stDataFrame, .stMetric, .stTooltipContent,
      section[data-testid="stSidebar"] .stMarkdown,
      section[data-testid="stSidebar"] label,
      section[data-testid="stSidebar"] p,
      div[data-testid="stMetricLabel"],
      div[data-testid="stMetricValue"],
      div[data-testid="stMetricDelta"],
      .stButton > button,
      button[data-baseweb="tab"],
      input, textarea, select, code, pre, p, label {
        font-family: var(--sf-font) !important;
        font-size: var(--sf-font-size) !important;
      }

      /* Keep Material icon ligatures working (do not inherit Google Sans Code) */
      [data-testid="stIconMaterial"],
      [data-testid="stExpanderToggleIcon"],
      [data-testid="stExpanderIcon"],
      .material-icons,
      .material-symbols-rounded,
      .material-symbols-outlined,
      .material-symbols-sharp,
      span[class*="material-symbols"],
      i[class*="material-symbols"],
      i.material-icons {
        font-family: var(--sf-icon-font) !important;
        font-weight: normal !important;
        font-style: normal !important;
        font-size: 1.25em !important;
        line-height: 1 !important;
        letter-spacing: normal !important;
        text-transform: none !important;
        white-space: nowrap !important;
        -webkit-font-feature-settings: "liga" !important;
        font-feature-settings: "liga" !important;
        font-variation-settings: "FILL" 0, "wght" 400, "GRAD" 0, "opsz" 24 !important;
      }

      section[data-testid="stSidebar"] {
        border-right: 1px solid rgba(13,148,136,0.15);
      }
      section[data-testid="stSidebar"] textarea {
        min-height: 5rem !important;
      }
      .stButton > button { padding: 0.4rem 0.75rem !important; }
      button[data-baseweb="tab"] { font-weight: 600; }
      .stCaption, [data-testid="stCaptionContainer"] {
        font-size: 0.875rem !important; /* 12.25px @ 14px root — secondary text */
      }

      .sf-hero {
        padding: 0 0 0.5rem; margin: 0 0 0.5rem 0;
        background: none; border: none; box-shadow: none; border-radius: 0;
        position: relative;
        z-index: 1;
      }
      .sf-kicker {
        font-size: 0.75rem; font-weight: 600; letter-spacing: 0.08em;
        text-transform: uppercase; color: #0f766e; margin: 0 0 0.25rem 0;
      }
      .sf-title {
        font-size: 1.25rem; /* 20px — standard page title */
        font-weight: 600; letter-spacing: normal; margin: 0; line-height: 1.3;
        font-family: var(--sf-font) !important;
        color: #0f766e;
        background: none !important;
        text-shadow: none !important;
        -webkit-text-fill-color: #0f766e !important;
        -webkit-background-clip: unset !important;
        background-clip: unset !important;
      }
      .sf-tag {
        color: #64748b; font-size: 0.875rem; margin-top: 0.2rem; line-height: 1.4;
      }

      .sf-section {
        font-size: 0.75rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
        color: #0f766e; margin: 0.35rem 0 0.5rem 0;
      }
      .sf-item {
        padding: 0.55rem 0.75rem 0.35rem; margin: 0 0 0.55rem 0; border-radius: 10px;
        border: 1px solid rgba(100,116,139,0.18);
        background: rgba(248,250,252,0.55);
      }
      .sf-item-title {font-size:1rem; font-weight:600; line-height:1.35; margin:0;}
      .sf-item-title a {text-decoration:none;}
      .sf-item-title a:hover {text-decoration:underline;}
      .sf-meta {color:#64748b; font-size:0.8125rem;}
      .sf-score {font-variant-numeric: tabular-nums; font-weight:700;}
      .sf-summary-clip {color:#475569; font-size:0.875rem; margin: 0.3rem 0 0.1rem 0;
                        display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical;
                        overflow:hidden;}

      .sf-badge {display:inline-block; padding:2px 8px; border-radius:999px; font-size:0.75rem;
                 font-weight:600; margin-right:4px; margin-top:2px;
                 border:1px solid rgba(128,128,128,0.28); background: rgba(128,128,128,0.06);}
      .sf-badge-kev {background: rgba(220,38,38,0.12); color:#b91c1c; border-color: rgba(220,38,38,0.35);}
      .sf-badge-actor {background: rgba(2,132,199,0.12); color:#0369a1; border-color: rgba(2,132,199,0.35);}
      .sf-badge-cve {background: rgba(13,148,136,0.12); color:#0f766e; border-color: rgba(13,148,136,0.35);}

      div[data-testid="stHorizontalBlock"]:has(div[data-testid="stMetric"]) {
        align-items: stretch;
      }
      div[data-testid="stHorizontalBlock"]:has(div[data-testid="stMetric"])
        div[data-testid="column"] {
        display: flex;
      }
      div[data-testid="stHorizontalBlock"]:has(div[data-testid="stMetric"])
        div[data-testid="column"] > div {
        width: 100%;
        display: flex;
      }
      div[data-testid="stMetric"] {
        background: linear-gradient(180deg, rgba(13,148,136,0.06), rgba(128,128,128,0.03));
        border: 1px solid rgba(13,148,136,0.16);
        padding: 10px 12px; border-radius: 10px;
        width: 100%;
        min-height: 88px;
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: center;
        box-sizing: border-box;
      }
      div[data-testid="stMetricLabel"] {
        min-height: 1.15rem;
        font-size: 0.8125rem !important;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      div[data-testid="stMetricValue"] {
        font-size: 1.25rem !important; font-weight:700; line-height: 1.2;
        min-height: 1.4rem;
      }
      div[data-testid="stMetricDelta"] {
        min-height: 1rem;
        font-size: 0.8125rem !important;
      }

      .stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #0d9488, #0284c7);
        border: none; font-weight: 700;
      }
      hr {margin: 0.4rem 0;}
      .sf-item details {border: none !important;}
    </style>
        """
    )
