"""
HTML Report Template Module for OGhidra

This module provides the CSS styles and HTML template structure for generating
styled vulnerability analysis reports. Based on the WiseDiskCleaner report template.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import html
import json

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ReportSection:
    """A section in the HTML report."""
    id: str                     # e.g., "executive_summary"
    title: str                  # e.g., "Executive Summary"
    icon: str                   # e.g., "📋"
    content_type: str           # "html", "table", "flow_diagram", "timeline", "cards"
    content: str                # HTML content or JSON data for structured types

@dataclass
class ReportMetadata:
    """Metadata for the HTML report."""
    binary_name: str
    analysis_date: str = field(default_factory=lambda: datetime.now().strftime("%B %d, %Y"))
    report_id: str = field(default_factory=lambda: f"OGH-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    severity: str = "MEDIUM"  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    subtitle: str = "Binary Analysis Report"
    tool_name: str = "OGhidra MCP"
    duration: str = ""

# ============================================================================
# CSS STYLES
# ============================================================================

REPORT_CSS_STYLES = """
:root {
    --bg-primary: #0a0a0f;
    --bg-secondary: #12121a;
    --bg-card: rgba(20, 20, 30, 0.9);
    --bg-glass: rgba(20, 20, 30, 0.6);
    --border-color: rgba(139, 92, 246, 0.2);
    --border-glow: rgba(139, 92, 246, 0.5);
    --text-primary: #f0f0f5;
    --text-secondary: #8888aa;
    --text-muted: #555577;
    --neon-purple: #8b5cf6;
    --neon-cyan: #06b6d4;
    --neon-pink: #ec4899;
    --neon-green: #10b981;
    --neon-orange: #f59e0b;
    --neon-red: #ef4444;
    --accent-blue: #3b82f6;
    --accent-cyan: #06b6d4;
    --accent-purple: #8b5cf6;
    --accent-red: #ef4444;
    --accent-orange: #f59e0b;
    --accent-green: #10b981;
    --gradient-main: linear-gradient(135deg, #8b5cf6 0%, #06b6d4 50%, #ec4899 100%);
    --gradient-1: linear-gradient(135deg, #8b5cf6 0%, #ec4899 100%);
    --gradient-2: linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%);
    --gradient-danger: linear-gradient(135deg, #ef4444 0%, #f59e0b 100%);
    --gradient-success: linear-gradient(135deg, #10b981 0%, #06b6d4 100%);
    --glow-purple: 0 0 20px rgba(139, 92, 246, 0.4), 0 0 40px rgba(139, 92, 246, 0.2);
    --glow-cyan: 0 0 20px rgba(6, 182, 212, 0.4), 0 0 40px rgba(6, 182, 212, 0.2);
    --glow-red: 0 0 20px rgba(239, 68, 68, 0.4), 0 0 40px rgba(239, 68, 68, 0.2);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
}

/* Animated background */
body::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background:
        radial-gradient(ellipse at 20% 20%, rgba(139, 92, 246, 0.1) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 80%, rgba(6, 182, 212, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 50%, rgba(236, 72, 153, 0.05) 0%, transparent 60%);
    pointer-events: none;
    z-index: -1;
}

/* Grid pattern overlay */
body::after {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image:
        linear-gradient(rgba(139, 92, 246, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(139, 92, 246, 0.03) 1px, transparent 1px);
    background-size: 50px 50px;
    pointer-events: none;
    z-index: -1;
}

/* Logo Section */
.logo-section { display: flex; align-items: center; gap: 1rem; }
.logo {
    width: 60px; height: 60px;
    background: var(--gradient-main);
    border-radius: 16px;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Orbitron', 'JetBrains Mono', monospace;
    font-size: 1.5rem; font-weight: 700;
    box-shadow: var(--glow-purple);
}
.brand-text {
    font-family: 'Orbitron', 'JetBrains Mono', monospace;
    font-size: 1.5rem; letter-spacing: 0.1em;
    background: var(--gradient-main);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.header {
    position: relative;
    padding: 3rem 2rem;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border-color);
    overflow: hidden;
}

.header::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: var(--gradient-1);
}

.header-content {
    max-width: 1400px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 1.5rem;
}

.header-main h1 {
    font-size: 2rem;
    font-weight: 700;
    background: var(--gradient-1);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.5rem;
}

.subtitle {
    color: var(--text-secondary);
    font-size: 1rem;
}

.severity-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.75rem 1.25rem;
    border-radius: 9999px;
    font-weight: 600;
    font-size: 0.875rem;
}

.severity-badge.critical {
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid rgba(239, 68, 68, 0.4);
    color: var(--accent-red);
}

.severity-badge.high {
    background: rgba(245, 158, 11, 0.15);
    border: 1px solid rgba(245, 158, 11, 0.4);
    color: var(--accent-orange);
}

.severity-badge.medium {
    background: rgba(139, 92, 246, 0.15);
    border: 1px solid rgba(139, 92, 246, 0.4);
    color: var(--accent-purple);
}

.severity-badge.low {
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid rgba(16, 185, 129, 0.4);
    color: var(--accent-green);
}

.meta-info {
    display: flex;
    flex-wrap: wrap;
    gap: 1.5rem;
    margin-top: 1rem;
}

.meta-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.875rem;
    color: var(--text-secondary);
}

.meta-item span {
    color: var(--text-primary);
    font-weight: 500;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
}

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.card {
    background: var(--bg-card);
    backdrop-filter: blur(10px);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 1.5rem;
    transition: transform 0.2s, box-shadow 0.2s;
}

.card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 30px rgba(139, 92, 246, 0.15);
}

.card-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
}

.card-icon {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.25rem;
    background: var(--gradient-1);
}

.card h3 {
    font-size: 1rem;
    font-weight: 600;
}

.stat-value {
    font-size: 2rem;
    font-weight: 700;
    background: var(--gradient-1);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.stat-label {
    font-size: 0.875rem;
    color: var(--text-secondary);
}

/* Stats Grid - Neon Style */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1.5rem;
    margin-bottom: 3rem;
}

.stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 1.5rem;
    text-align: center;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--gradient-main);
    opacity: 0;
    transition: opacity 0.3s ease;
}

.stat-card:hover {
    border-color: var(--border-glow);
    transform: translateY(-4px);
    box-shadow: var(--glow-purple);
}

.stat-card:hover::before {
    opacity: 1;
}

.stat-icon {
    font-size: 2rem;
    margin-bottom: 0.75rem;
}

.stat-card .stat-value {
    font-size: 2.5rem;
    font-weight: 700;
    background: var(--gradient-main);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.stat-card .stat-label {
    font-size: 0.85rem;
    color: var(--text-secondary);
    margin-top: 0.25rem;
}

/* Key Findings Cards */
.findings-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1.5rem;
}

.finding-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 1.5rem;
    position: relative;
    overflow: hidden;
    transition: all 0.3s ease;
}

.finding-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 4px; height: 100%;
}

.finding-card.critical::before { background: var(--neon-red); }
.finding-card.high::before { background: var(--neon-orange); }
.finding-card.medium::before { background: var(--neon-purple); }
.finding-card.low::before { background: var(--neon-cyan); }

.finding-card:hover {
    border-color: var(--border-glow);
    transform: translateX(4px);
}

.finding-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 1rem;
}

.finding-title {
    font-weight: 600;
    font-size: 1.1rem;
    color: var(--text-primary);
}

.finding-badge {
    font-size: 0.7rem;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-weight: 600;
    text-transform: uppercase;
}

.finding-badge.critical { background: rgba(239, 68, 68, 0.2); color: var(--neon-red); }
.finding-badge.high { background: rgba(245, 158, 11, 0.2); color: var(--neon-orange); }
.finding-badge.medium { background: rgba(139, 92, 246, 0.2); color: var(--neon-purple); }
.finding-badge.low { background: rgba(6, 182, 212, 0.2); color: var(--neon-cyan); }

.finding-desc {
    font-size: 0.9rem;
    color: var(--text-secondary);
    margin-bottom: 1rem;
}

.finding-apis {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
}

.finding-api {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    padding: 0.25rem 0.5rem;
    background: rgba(139, 92, 246, 0.15);
    border-radius: 4px;
    color: var(--neon-purple);
}

/* Risk Meter */
.risk-meter {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}

.risk-circle {
    width: 140px;
    height: 140px;
    border-radius: 50%;
    background: conic-gradient(from 0deg, var(--neon-green) 0%, var(--neon-cyan) 25%, var(--neon-purple) 50%, var(--neon-orange) 75%, var(--neon-red) 100%);
    padding: 6px;
    animation: pulse-glow 3s ease-in-out infinite;
}

@keyframes pulse-glow {
    0%, 100% { box-shadow: 0 0 20px rgba(139, 92, 246, 0.3); }
    50% { box-shadow: 0 0 40px rgba(139, 92, 246, 0.5), 0 0 60px rgba(6, 182, 212, 0.3); }
}

.risk-inner {
    width: 100%;
    height: 100%;
    background: var(--bg-secondary);
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}

.risk-score {
    font-size: 2.5rem;
    font-weight: 700;
    background: var(--gradient-danger);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.risk-label {
    font-size: 0.75rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.1em;
}

/* Executive Summary */
.executive-summary {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 2rem;
}

.summary-grid {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 2rem;
    align-items: center;
}

.summary-text h3 {
    font-size: 1.1rem;
    margin-bottom: 1rem;
    color: var(--text-primary);
}

.summary-text p {
    color: var(--text-secondary);
    margin-bottom: 1rem;
    line-height: 1.7;
}

.summary-text code {
    font-family: 'JetBrains Mono', monospace;
    background: rgba(139, 92, 246, 0.15);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    color: var(--neon-purple);
    font-size: 0.85rem;
}

.section {
    margin-bottom: 2rem;
}

.section-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.section-header h2 {
    font-size: 1.5rem;
    font-weight: 600;
}

.section-line {
    flex: 1;
    height: 1px;
    background: var(--border-color);
}

.attack-vectors {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 1.5rem;
}

.attack-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 1.5rem;
    position: relative;
    overflow: hidden;
}

.attack-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 3px;
}

.attack-card.critical::before {
    background: var(--accent-red);
}

.attack-card.high::before {
    background: var(--accent-orange);
}

.attack-card.medium::before {
    background: var(--accent-purple);
}

.attack-card h4 {
    font-size: 1.1rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
}

.attack-card p {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 1rem;
}

.api-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
}

.api-tag {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    padding: 0.25rem 0.5rem;
    background: rgba(139, 92, 246, 0.2);
    border-radius: 4px;
    color: var(--accent-purple);
}

/* CSS Flow Diagram */
.flow-diagram {
    background: var(--bg-secondary);
    border-radius: 12px;
    padding: 2rem;
    margin: 1rem 0;
    overflow-x: auto;
}

.flow-row {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-bottom: 0.5rem;
}

.flow-node {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    padding: 0.75rem 1rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-primary);
    white-space: nowrap;
    text-align: center;
}

.flow-node.start {
    background: linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%);
    border-color: #6d28d9;
    color: white;
    font-weight: 600;
}

.flow-node.danger {
    background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
    border-color: #b91c1c;
    color: white;
    font-weight: 600;
}

.flow-node.warning {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
    border-color: #d97706;
    color: white;
    font-weight: 500;
}

.flow-arrow {
    color: var(--accent-cyan);
    font-size: 1.25rem;
    padding: 0 0.25rem;
}

.flow-connector {
    text-align: center;
    color: var(--accent-cyan);
    font-size: 1.5rem;
    padding: 0.5rem 0;
}

.flow-branches {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
}

.flow-branch {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    padding: 1rem;
    background: var(--bg-card);
    border-radius: 8px;
    border: 1px solid var(--border-color);
}

.flow-branch-title {
    font-size: 0.75rem;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.5rem;
}

.flow-step {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    padding: 0.4rem 0.6rem;
    background: rgba(139, 92, 246, 0.15);
    border-radius: 4px;
    color: var(--text-primary);
    margin: 0.2rem 0;
}

.timeline {
    position: relative;
    padding-left: 2.5rem;
}

.timeline::before {
    content: '';
    position: absolute;
    left: 0.75rem;
    top: 0;
    bottom: 0;
    width: 2px;
    background: linear-gradient(to bottom, var(--accent-purple) 0%, var(--accent-cyan) 100%);
}

.timeline-item {
    position: relative;
    margin-bottom: 1.5rem;
    padding: 1.25rem;
    background: var(--bg-card);
    border-radius: 12px;
    border: 1px solid var(--border-color);
}

.timeline-item::before {
    content: '';
    position: absolute;
    left: -2rem;
    top: 1.5rem;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: var(--accent-purple);
    border: 3px solid var(--bg-primary);
    box-shadow: 0 0 0 2px var(--accent-purple);
}

.timeline-step {
    font-size: 0.7rem;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.5rem;
}

.timeline-title {
    font-weight: 600;
    margin-bottom: 0.5rem;
}

.timeline-content {
    font-size: 0.875rem;
    color: var(--text-secondary);
}

.timeline-reasoning {
    margin-top: 0.75rem;
    padding: 0.75rem;
    background: rgba(139, 92, 246, 0.1);
    border-radius: 6px;
    font-size: 0.8rem;
    font-style: italic;
    color: var(--text-secondary);
    border-left: 3px solid var(--accent-purple);
}

.code-block {
    background: #0d1117;
    border: 1px solid rgba(48, 54, 61, 0.5);
    border-radius: 8px;
    padding: 1rem;
    overflow-x: auto;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    line-height: 1.5;
    margin: 1rem 0;
}

.code-block .keyword { color: #ff7b72; }
.code-block .function { color: #d2a8ff; }
.code-block .string { color: #a5d6ff; }
.code-block .comment { color: #8b949e; }
.code-block .type { color: #7ee787; }

.highlight-box {
    background: rgba(245, 158, 11, 0.15);
    border: 1px solid rgba(245, 158, 11, 0.3);
    border-radius: 8px;
    padding: 1rem;
    margin: 1rem 0;
}

.highlight-box code {
    font-family: 'JetBrains Mono', monospace;
    color: var(--accent-orange);
    word-break: break-all;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
}

th, td {
    text-align: left;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border-color);
}

th {
    color: var(--text-secondary);
    font-weight: 500;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

td {
    font-size: 0.875rem;
}

.address {
    font-family: 'JetBrains Mono', monospace;
    color: var(--accent-cyan);
}

.tag {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
}

.tag-critical {
    background: rgba(239, 68, 68, 0.15);
    color: var(--accent-red);
}

.tag-high {
    background: rgba(245, 158, 11, 0.15);
    color: var(--accent-orange);
}

.tag-medium {
    background: rgba(139, 92, 246, 0.15);
    color: var(--accent-purple);
}

.tag-low {
    background: rgba(16, 185, 129, 0.15);
    color: var(--accent-green);
}

.tag-info {
    background: rgba(6, 182, 212, 0.15);
    color: var(--accent-cyan);
}

.collapsible {
    cursor: pointer;
}

.collapsible-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.5rem;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    margin-bottom: 0.5rem;
    transition: all 0.2s;
}

.collapsible-header:hover {
    border-color: var(--accent-purple);
}

.collapsible-header h4 {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-weight: 500;
}

.collapsible-arrow {
    transition: transform 0.3s;
}

.collapsible.active .collapsible-arrow {
    transform: rotate(180deg);
}

.collapsible-content {
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.3s ease-out;
    background: var(--bg-secondary);
    border-radius: 12px;
    margin-bottom: 0.5rem;
}

.collapsible.active .collapsible-content {
    max-height: 3000px;
}

.collapsible-inner {
    padding: 1.5rem;
}

.summary-content {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 1.5rem;
    border: 1px solid var(--border-color);
}

.summary-content p {
    margin-bottom: 1rem;
    color: var(--text-secondary);
}

.summary-content ul {
    margin-left: 1.5rem;
    color: var(--text-secondary);
}

.summary-content li {
    margin-bottom: 0.5rem;
}

.recommendations {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 1.5rem;
    border: 1px solid var(--border-color);
}

.recommendations ol {
    margin-left: 1.5rem;
    color: var(--text-secondary);
}

.recommendations li {
    margin-bottom: 0.75rem;
}

.footer {
    text-align: center;
    padding: 2rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
    border-top: 1px solid var(--border-color);
    margin-top: 2rem;
}

@media (max-width: 768px) {
    .header-content {
        flex-direction: column;
    }
    .attack-vectors {
        grid-template-columns: 1fr;
    }
    .flow-branches {
        grid-template-columns: 1fr;
    }
}

/* Vulnerability Discovery Accordion */
.discovery-section { display: flex; flex-direction: column; gap: 1rem; }
.discovery-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; overflow: hidden; transition: all 0.3s; }
.discovery-card:hover { border-color: rgba(139, 92, 246, 0.5); }
.discovery-header { display: flex; align-items: center; gap: 1rem; padding: 1.25rem 1.5rem; cursor: pointer; transition: background 0.2s; }
.discovery-header:hover { background: rgba(139, 92, 246, 0.05); }
.discovery-severity { width: 4px; height: 40px; border-radius: 2px; flex-shrink: 0; }
.discovery-severity.high { background: var(--accent-orange); }
.discovery-severity.critical { background: var(--accent-red); }
.discovery-severity.medium { background: var(--accent-purple); }
.discovery-severity.low { background: var(--accent-cyan); }
.discovery-info { flex: 1; }
.discovery-title { font-weight: 600; font-size: 1rem; margin-bottom: 0.25rem; }
.discovery-subtitle { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--accent-cyan); }
.discovery-toggle { font-size: 1.25rem; color: var(--text-secondary); transition: transform 0.3s; }
.discovery-card.open .discovery-toggle { transform: rotate(180deg); }
.discovery-body { display: none; padding: 0 1.5rem 1.5rem; border-top: 1px solid var(--border-color); }
.discovery-card.open .discovery-body { display: block; }

/* Investigation Path Timeline */
.inv-path { display: flex; flex-direction: column; margin: 1rem 0; }
.inv-step { display: flex; gap: 1rem; padding-bottom: 1rem; }
.inv-timeline { display: flex; flex-direction: column; align-items: center; width: 24px; }
.inv-dot { width: 12px; height: 12px; background: var(--accent-purple); border-radius: 50%; flex-shrink: 0; z-index: 1; }
.inv-line { width: 2px; flex: 1; background: linear-gradient(var(--accent-purple), var(--accent-cyan)); min-height: 20px; }
.inv-content { flex: 1; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 10px; padding: 1rem; }
.inv-header { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
.inv-tool { font-family: 'JetBrains Mono', monospace; font-weight: 600; color: var(--accent-purple); font-size: 0.85rem; }
.inv-time { font-size: 0.7rem; color: var(--text-secondary); }
.inv-params { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; background: rgba(0,0,0,0.3); padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 0.75rem; color: var(--accent-cyan); }
.inv-result { font-size: 0.875rem; color: var(--text-secondary); border-left: 2px solid var(--accent-purple); padding-left: 0.75rem; }
.inv-result strong { color: var(--text-primary); }
.inv-result code { font-family: 'JetBrains Mono', monospace; background: rgba(139, 92, 246, 0.15); padding: 0.1rem 0.3rem; border-radius: 3px; color: var(--accent-purple); font-size: 0.8rem; }

/* Evidence Grid */
.evidence-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 0.75rem; margin: 1rem 0; }
.evidence-item { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 0.75rem; }
.evidence-type { font-size: 0.65rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem; }
.evidence-value { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--accent-cyan); word-break: break-all; }
.evidence-addr { font-size: 0.7rem; color: var(--text-secondary); margin-top: 0.15rem; }

/* Impact Box */
.impact-box { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 10px; padding: 1rem; margin-top: 1rem; }
.impact-title { font-weight: 600; color: var(--accent-red); margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem; }
.impact-desc { font-size: 0.875rem; color: var(--text-secondary); }
.impact-desc code { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); padding: 0.1rem 0.3rem; border-radius: 3px; font-family: 'JetBrains Mono', monospace; }

/* Code Snippet Block */
.code-snippet { background: #0d1117; border: 1px solid var(--border-color); border-radius: 10px; overflow: hidden; margin: 1rem 0; }
.code-snippet-header { padding: 0.6rem 1rem; background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; font-size: 0.8rem; }
.code-snippet-filename { font-family: 'JetBrains Mono', monospace; color: var(--text-secondary); }
.code-snippet-addr { font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan); }
.code-snippet-content { padding: 1rem; overflow-x: auto; }
.code-snippet-content pre { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.6; }
.kw { color: #ff7b72; } .fn { color: #d2a8ff; } .str { color: #a5d6ff; } .cmt { color: #8b949e; } .typ { color: #7ee787; } .num { color: #79c0ff; } .hl { background: rgba(245, 158, 11, 0.2); border-radius: 2px; padding: 0 2px; }

.section-label { font-size: 0.7rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.75rem; margin-top: 1rem; }
"""

# ============================================================================
# HTML TEMPLATE
# ============================================================================

def _get_severity_icon(severity: str) -> str:
    """Get icon for severity level."""
    icons = {
        "CRITICAL": "🔥",
        "HIGH": "⚠️",
        "MEDIUM": "🔶",
        "LOW": "ℹ️"
    }
    return icons.get(severity.upper(), "📊")

def generate_html_report(sections: List[ReportSection], metadata: ReportMetadata) -> str:
    """
    Generate a complete HTML report from sections and metadata.
    
    Args:
        sections: List of ReportSection objects
        metadata: ReportMetadata with binary info
        
    Returns:
        Complete HTML document as string
    """
    severity_lower = metadata.severity.lower()
    severity_icon = _get_severity_icon(metadata.severity)
    
    # Build sections HTML
    sections_html = ""
    for section in sections:
        sections_html += _render_section(section)
    
    # Build meta info items
    meta_items = f'''
        <div class="meta-item">📁 Binary: <span>{html.escape(metadata.binary_name)}</span></div>
        <div class="meta-item">📅 Analyzed: <span>{html.escape(metadata.analysis_date)}</span></div>
        <div class="meta-item">🔧 Tool: <span>{html.escape(metadata.tool_name)}</span></div>
    '''
    if metadata.duration:
        meta_items += f'<div class="meta-item">⏱️ Duration: <span>{html.escape(metadata.duration)}</span></div>'
    
    html_doc = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(metadata.binary_name)} - {html.escape(metadata.subtitle)}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    <style>
{REPORT_CSS_STYLES}
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="logo-section">
                <div class="logo">OG</div>
                <span class="brand-text">GHIDRA</span>
            </div>
            <div class="severity-badge {severity_lower}">{severity_icon} {metadata.severity.upper()}</div>
        </div>
        <div style="max-width: 1400px; margin: 2rem auto 0;">
            <h1 class="header-main" style="font-size: 2rem; font-weight: 700; background: var(--gradient-1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin-bottom: 0.5rem;">{html.escape(metadata.binary_name)}</h1>
            <p class="subtitle">{html.escape(metadata.subtitle)}</p>
            <div class="meta-info">
                {meta_items}
            </div>
        </div>
    </header>

    <main class="container">
        {sections_html}
    </main>

    <footer class="footer">
        <p>Generated by <strong>OGhidra</strong> • AI-Powered Binary Analysis</p>
        <p style="margin-top: 0.5rem; font-size: 0.75rem;">Report ID: {html.escape(metadata.report_id)}</p>
    </footer>

    <script>
        function toggleCollapsible(element) {{
            element.classList.toggle('active');
        }}
        function toggleDiscovery(element) {{
            const card = element.closest('.discovery-card');
            if (card) card.classList.toggle('open');
        }}
    </script>
</body>
</html>'''
    
    return html_doc


def _render_section(section: ReportSection) -> str:
    """Render a single section to HTML."""
    section_html = f'''
        <section class="section" id="{html.escape(section.id)}">
            <div class="section-header">
                <h2>{section.icon} {html.escape(section.title)}</h2>
                <div class="section-line"></div>
            </div>
            {section.content}
        </section>
    '''
    return section_html

# ============================================================================
# HELPER FUNCTIONS FOR BUILDING SECTIONS
# ============================================================================

def build_stats_grid(stats: List[Dict[str, Any]]) -> str:
    """
    Build a statistics grid from a list of stat items.
    
    Args:
        stats: List of dicts with 'icon', 'value', 'label' keys
        
    Returns:
        HTML for stats grid with neon styling
    """
    cards = ""
    for stat in stats:
        cards += f'''
            <div class="stat-card">
                <div class="stat-icon">{stat.get('icon', '📊')}</div>
                <div class="stat-value">{html.escape(str(stat.get('value', '0')))}</div>
                <div class="stat-label">{html.escape(str(stat.get('label', '')))}</div>
            </div>
        '''
    return f'<div class="stats-grid">{cards}</div>'


def build_attack_vectors(vectors: List[Dict[str, Any]]) -> str:
    """
    Build attack vector cards.
    
    Args:
        vectors: List of dicts with 'title', 'severity', 'description', 'apis' keys
        
    Returns:
        HTML for attack vectors section
    """
    cards = ""
    for vec in vectors:
        severity = vec.get('severity', 'medium').lower()
        apis_html = ""
        for api in vec.get('apis', []):
            apis_html += f'<span class="api-tag">{html.escape(api)}</span>'
        
        cards += f'''
            <div class="attack-card {severity}">
                <h4>{html.escape(vec.get('title', ''))}</h4>
                <p>{html.escape(vec.get('description', ''))}</p>
                <div class="api-list">{apis_html}</div>
            </div>
        '''
    return f'<div class="attack-vectors">{cards}</div>'

def build_timeline(items: List[Dict[str, Any]]) -> str:
    """
    Build a timeline of investigation steps.
    
    Args:
        items: List of dicts with 'step', 'title', 'content', 'reasoning' keys
        
    Returns:
        HTML for timeline
    """
    timeline_html = ""
    for item in items:
        reasoning_html = ""
        if item.get('reasoning'):
            reasoning_html = f'<div class="timeline-reasoning">💭 {html.escape(item["reasoning"])}</div>'
        
        timeline_html += f'''
            <div class="timeline-item">
                <div class="timeline-step">{html.escape(str(item.get('step', '')))}</div>
                <div class="timeline-title">{html.escape(item.get('title', ''))}</div>
                <div class="timeline-content">{html.escape(item.get('content', ''))}</div>
                {reasoning_html}
            </div>
        '''
    return f'<div class="timeline">{timeline_html}</div>'

def build_key_findings(findings: List[Dict[str, Any]]) -> str:
    """
    Build key findings cards with severity indicators.
    
    Args:
        findings: List of dicts with 'title', 'severity', 'description', 'apis' keys
        
    Returns:
        HTML for key findings section
    """
    cards = ""
    for finding in findings:
        severity = finding.get('severity', 'medium').lower()
        apis_html = ""
        for api in finding.get('apis', []):
            apis_html += f'<span class="finding-api">{html.escape(str(api))}</span>'
        
        cards += f'''
            <div class="finding-card {severity}">
                <div class="finding-header">
                    <div class="finding-title">{html.escape(finding.get('title', ''))}</div>
                    <span class="finding-badge {severity}">{severity.upper()}</span>
                </div>
                <div class="finding-desc">{html.escape(finding.get('description', ''))}</div>
                <div class="finding-apis">{apis_html}</div>
            </div>
        '''
    return f'<div class="findings-grid">{cards}</div>'

def build_risk_meter(score: float, label: str = "Risk Score") -> str:
    """
    Build a circular risk meter gauge.
    
    Args:
        score: Risk score (0-10)
        label: Label for the risk level (e.g., "MEDIUM-HIGH RISK")
        
    Returns:
        HTML for risk meter
    """
    return f'''
        <div class="risk-meter">
            <div class="risk-circle">
                <div class="risk-inner">
                    <div class="risk-score">{score:.1f}</div>
                    <div class="risk-label">Risk Score</div>
                </div>
            </div>
            <p style="margin-top: 1rem; color: var(--text-secondary); text-align: center; font-size: 0.85rem;">
                {html.escape(label)}
            </p>
        </div>
    '''

def build_security_imports(imports: List[Dict[str, Any]]) -> str:
    """
    Build a styled security imports table.
    
    Args:
        imports: List of dicts with 'api', 'address', 'category', 'risk' keys
        
    Returns:
        HTML for security imports table
    """
    rows_html = ""
    for imp in imports:
        risk = imp.get('risk', 'low').lower()
        risk_class = f"tag-{risk}" if risk in ['critical', 'high', 'medium', 'low'] else "tag-info"
        
        rows_html += f'''
            <tr>
                <td><span class="address">{html.escape(str(imp.get('address', '')))}</span></td>
                <td><code class="api-tag">{html.escape(str(imp.get('api', '')))}</code></td>
                <td>{html.escape(str(imp.get('category', '')))}</td>
                <td><span class="tag {risk_class}">{html.escape(str(imp.get('risk', '')))}</span></td>
            </tr>
        '''
    
    return f'''
        <table>
            <thead>
                <tr>
                    <th>Address</th>
                    <th>API</th>
                    <th>Category</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>{rows_html}</tbody>
        </table>
    '''

def build_table(headers: List[str], rows: List[List[str]], address_columns: List[int] = None) -> str:

    """
    Build an HTML table.
    
    Args:
        headers: List of header strings
        rows: List of row data (each row is a list of cell strings)
        address_columns: Indices of columns that should be styled as addresses
        
    Returns:
        HTML for table
    """
    address_columns = address_columns or []
    
    headers_html = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    
    rows_html = ""
    for row in rows:
        cells_html = ""
        for i, cell in enumerate(row):
            if i in address_columns:
                cells_html += f'<td class="address">{html.escape(str(cell))}</td>'
            else:
                cells_html += f'<td>{html.escape(str(cell))}</td>'
        rows_html += f"<tr>{cells_html}</tr>"
    
    return f'''
        <table>
            <thead><tr>{headers_html}</tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
    '''

def build_flow_diagram(nodes: List[Dict[str, Any]], layout: str = "linear") -> str:
    """
    Build a CSS flow diagram.
    
    Args:
        nodes: List of node dicts with 'label', 'type' (start/danger/warning/normal)
        layout: "linear" or "branched"
        
    Returns:
        HTML for flow diagram
    """
    if layout == "linear":
        # Simple linear flow
        flow_html = '<div class="flow-row">'
        for i, node in enumerate(nodes):
            node_class = f"flow-node {node.get('type', '')}"
            flow_html += f'<div class="{node_class}">{html.escape(node.get("label", ""))}</div>'
            if i < len(nodes) - 1:
                flow_html += '<div class="flow-arrow">→</div>'
        flow_html += '</div>'
        return f'<div class="flow-diagram">{flow_html}</div>'
    else:
        # Content is passed through as-is for complex diagrams
        return '<div class="flow-diagram">' + "".join(
            f'<div class="flow-node {n.get("type", "")}">{html.escape(n.get("label", ""))}</div>'
            for n in nodes
        ) + '</div>'

def build_vulnerability_discovery(discoveries: List[Dict[str, Any]]) -> str:
    """
    Build vulnerability discovery accordion cards.
    
    Args:
        discoveries: List of discovery dicts with:
            - title: str
            - subtitle: str (e.g. address)
            - severity: str (critical/high/medium/low)
            - investigation_path: List[Dict] with tool, time, params, result
            - evidence: List[Dict] with type, value, address
            - code: Optional Dict with filename, address, content
            - impact: Dict with title, description
            
    Returns:
        HTML for discovery section
    """
    cards_html = ""
    for i, disc in enumerate(discoveries):
        severity = disc.get('severity', 'medium').lower()
        open_class = " open" if i == 0 else ""
        
        # Investigation path
        path_html = ""
        inv_path = disc.get('investigation_path', [])
        for j, step in enumerate(inv_path):
            is_last = j == len(inv_path) - 1
            line_html = "" if is_last else '<div class="inv-line"></div>'
            path_html += f'''
                <div class="inv-step">
                    <div class="inv-timeline"><div class="inv-dot"></div>{line_html}</div>
                    <div class="inv-content">
                        <div class="inv-header"><span class="inv-tool">{html.escape(step.get('tool', ''))}</span><span class="inv-time">{html.escape(step.get('time', ''))}</span></div>
                        <div class="inv-params">{html.escape(step.get('params', ''))}</div>
                        <div class="inv-result">{step.get('result', '')}</div>
                    </div>
                </div>
            '''
        
        # Evidence grid
        evidence_html = ""
        for ev in disc.get('evidence', []):
            evidence_html += f'''
                <div class="evidence-item">
                    <div class="evidence-type">{html.escape(ev.get('type', ''))}</div>
                    <div class="evidence-value">{html.escape(ev.get('value', ''))}</div>
                    <div class="evidence-addr">{html.escape(ev.get('address', ''))}</div>
                </div>
            '''
        
        # Code block (optional)
        code_html = ""
        if disc.get('code'):
            code = disc['code']
            code_html = f'''
                <div class="section-label">Vulnerable Code</div>
                <div class="code-snippet">
                    <div class="code-snippet-header"><span class="code-snippet-filename">{html.escape(code.get('filename', ''))}</span><span class="code-snippet-addr">{html.escape(code.get('address', ''))}</span></div>
                    <div class="code-snippet-content"><pre>{code.get('content', '')}</pre></div>
                </div>
            '''
        
        # Impact box
        impact = disc.get('impact', {})
        impact_html = f'''
            <div class="impact-box">
                <div class="impact-title">🔥 {html.escape(impact.get('title', 'Security Impact'))}</div>
                <div class="impact-desc">{impact.get('description', '')}</div>
            </div>
        '''
        
        cards_html += f'''
            <div class="discovery-card{open_class}">
                <div class="discovery-header" onclick="toggleDiscovery(this)">
                    <div class="discovery-severity {severity}"></div>
                    <div class="discovery-info">
                        <div class="discovery-title">{html.escape(disc.get('title', ''))}</div>
                        <div class="discovery-subtitle">{html.escape(disc.get('subtitle', ''))}</div>
                    </div>
                    <span class="tag tag-{severity}">{severity.upper()}</span>
                    <span class="discovery-toggle">▼</span>
                </div>
                <div class="discovery-body">
                    <div class="section-label">Investigation Path</div>
                    <div class="inv-path">{path_html}</div>
                    {code_html}
                    <div class="section-label">Evidence</div>
                    <div class="evidence-grid">{evidence_html}</div>
                    {impact_html}
                </div>
            </div>
        '''
    
    return f'<div class="discovery-section">{cards_html}</div>'

def get_discovery_javascript() -> str:
    """Return JavaScript for discovery accordion toggle."""
    return '''
    <script>
        function toggleDiscovery(header) {
            const card = header.parentElement;
            card.classList.toggle('open');
        }
    </script>
    '''
