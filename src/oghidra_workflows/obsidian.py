"""Obsidian vault integration for function analysis notes."""

import re
from datetime import UTC, datetime
from typing import Any

from mcp import ClientSession
from pydantic import BaseModel

from .diagnostics import logger, operation
from .workflow import Proposal, result_data


class FunctionLink(BaseModel):
    """A link to another function with stable address-based reference."""
    address: str
    name: str


class FunctionNote(BaseModel):
    """Structured representation of a function analysis note."""

    address: str
    binary_name: str
    entry_point: str | None = None
    original_name: str
    current_name: str
    signature: str | None = None
    last_analyzed: str
    analyzed_by: str = "oghidra-dspy"
    confidence: str = "medium"
    tags: list[str] = []
    summary: str = ""
    behavior: str = ""
    key_observations: str = ""
    callees: list[FunctionLink] = []
    callers: list[FunctionLink] = []
    security_notes: str = ""
    human_notes: str = ""


def format_address(address: str) -> str:
    """Format address as hex string for filenames and links."""
    # Remove any 0x prefix and ensure consistent format
    addr = address.lower().replace("0x", "").lstrip("0") or "0"
    return f"0x{addr}"


def sanitize_filename(name: str) -> str:
    """Sanitize function name for use in filename."""
    # Remove or replace characters that are invalid in filenames
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    return name


def make_note_filename(function_name: str) -> str:
    """Create filename from function name.

    Format: {sanitized_name}.md
    Example: validateClfsHeaderAndSetupState.md
    """
    sanitized = sanitize_filename(function_name)
    return f"{sanitized}.md"


def format_frontmatter(note: FunctionNote) -> str:
    """Format YAML frontmatter for the function note with aliases."""
    # Include both current and original names as aliases for flexible linking
    aliases = [note.current_name]
    if note.original_name != note.current_name:
        aliases.append(note.original_name)

    frontmatter = {
        "aliases": aliases,
        "address": note.address,
        "binary_name": note.binary_name,
        "original_name": note.original_name,
        "current_name": note.current_name,
        "last_analyzed": note.last_analyzed,
        "analyzed_by": note.analyzed_by,
        "confidence": note.confidence,
        "tags": note.tags,
    }
    if note.entry_point:
        frontmatter["entry_point"] = note.entry_point
    if note.signature:
        frontmatter["signature"] = note.signature

    lines = ["---"]
    for key, value in frontmatter.items():
        if isinstance(value, list):
            if key == "aliases":
                # Format aliases without quotes for cleaner YAML
                lines.append(f"{key}: [{', '.join(value)}]")
            else:
                lines.append(f"{key}: [{', '.join(value)}]")
        else:
            lines.append(f'{key}: "{value}"')
    lines.append("---")
    return "\n".join(lines)


def format_function_note(
    address: str,
    binary_name: str,
    original_name: str,
    current_name: str,
    proposal: Proposal,
    confidence: str,
    signature: str | None = None,
    entry_point: str | None = None,
    callees: list[FunctionLink] | None = None,
    callers: list[FunctionLink] | None = None,
    existing_human_notes: str = "",
) -> str:
    """Generate a complete Obsidian note from analysis results.

    Uses address-based linking for stable cross-references.
    Preserves existing human notes section if provided.

    Args:
        confidence: Required confidence rating (e.g., "low", "medium", "high")
                   calculated by the workflow based on analysis quality.
    """
    now = datetime.now(UTC).isoformat()

    # Extract tags from analysis (simple keyword extraction)
    tags = extract_tags(proposal.analysis + " " + proposal.behavior_summary)

    note = FunctionNote(
        address=format_address(address),
        binary_name=binary_name,
        entry_point=format_address(entry_point) if entry_point else format_address(address),
        original_name=original_name,
        current_name=current_name,
        signature=signature or "// Signature unknown",
        last_analyzed=now,
        confidence=confidence,
        tags=tags,
        summary=proposal.behavior_summary,
        behavior=proposal.analysis,
        callees=callees or [],
        callers=callers or [],
        human_notes=existing_human_notes,
    )

    sections = [
        format_frontmatter(note),
        f"\n# {current_name}\n",
        f"\n**Address:** `{note.address}`\n",
    ]

    if note.signature:
        sections.append(f"\n```c\n{note.signature}\n```\n")

    sections.extend(
        [
            "\n## Summary\n",
            f"{note.summary}\n",
            "\n## Behavior Analysis\n",
            f"{note.behavior}\n",
            "\n## Rationale\n",
            f"{proposal.rationale}\n",
        ]
    )

    if note.callees:
        sections.append("\n## Callees\n")
        for callee in note.callees:
            # Simple link - Obsidian handles resolution and updates
            sections.append(f"- [[{callee.name}]]\n")

    if note.callers:
        sections.append("\n## Callers\n")
        for caller in note.callers:
            sections.append(f"- [[{caller.name}]]\n")

    if note.human_notes:
        sections.extend(["\n## Human Notes\n", f"{note.human_notes}\n"])

    sections.append(
        f"\n---\n*Last analyzed: {note.last_analyzed} by {note.analyzed_by}*\n"
    )

    return "".join(sections)


def extract_tags(text: str) -> list[str]:
    """Extract potential tags from analysis text.

    Looks for common reverse engineering keywords.
    """
    keywords = {
        "network",
        "networking",
        "socket",
        "http",
        "https",
        "crypto",
        "encryption",
        "hash",
        "parse",
        "parsing",
        "input",
        "validation",
        "authentication",
        "auth",
        "file",
        "io",
        "buffer",
        "memory",
        "allocation",
        "string",
        "compression",
        "encoding",
        "decoding",
        "protocol",
        "api",
        "callback",
        "handler",
        "unsafe",
        "vulnerable",
        "security",
    }

    text_lower = text.lower()
    found_tags = []

    for keyword in keywords:
        if keyword in text_lower:
            found_tags.append(keyword)

    return sorted(set(found_tags))[:10]  # Limit to 10 tags


def parse_frontmatter(content: str) -> tuple[dict[str, Any], str]:
    """Parse YAML frontmatter from note content.

    Returns (frontmatter_dict, remaining_content).
    """
    if not content.startswith("---\n"):
        return {}, content

    # Find closing ---
    end_idx = content.find("\n---\n", 4)
    if end_idx == -1:
        return {}, content

    frontmatter_text = content[4:end_idx]
    remaining = content[end_idx + 5 :]

    # Simple YAML-like parsing (not full YAML, but sufficient for our structured format)
    frontmatter = {}
    for line in frontmatter_text.split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"')

        # Handle lists
        if value.startswith("[") and value.endswith("]"):
            value = [v.strip() for v in value[1:-1].split(",")]

        frontmatter[key] = value

    return frontmatter, remaining


def extract_human_notes(content: str) -> str:
    """Extract the Human Notes section from existing content.

    Preserves user annotations for merging.
    """
    match = re.search(
        r"## Human Notes\n(.*?)(?=\n##|\n---\n|$)", content, re.DOTALL | re.IGNORECASE
    )
    if match:
        return match.group(1).strip()
    return ""


def merge_with_user_notes(existing_content: str, new_content: str) -> str:
    """Merge new analysis with existing user notes.

    Preserves human annotations while updating automated sections.
    """
    human_notes = extract_human_notes(existing_content)

    if human_notes:
        # Replace or append human notes section in new content
        if "## Human Notes" in new_content:
            new_content = re.sub(
                r"## Human Notes\n.*?(?=\n##|\n---\n|$)",
                f"## Human Notes\n{human_notes}\n",
                new_content,
                flags=re.DOTALL,
            )
        else:
            # Add before final metadata line
            new_content = re.sub(
                r"(\n---\n\*Last analyzed:)",
                f"\n## Human Notes\n{human_notes}\n\\1",
                new_content,
            )

    return new_content


async def read_function_note(
    session: ClientSession, _vault_path: str, function_name: str, address: str
) -> tuple[str | None, str | None]:
    """Read existing function note from Obsidian vault.

    Returns (content, current_path) tuple.
    Tries by function name first, then searches by address in frontmatter.
    """
    formatted_addr = format_address(address)
    note_filename = make_note_filename(function_name)
    note_path = f"functions/{note_filename}"

    with operation("obsidian.read_note", function_name=function_name, address=formatted_addr):
        # Try direct read by function name
        try:
            read_result = await session.call_tool("vault_read", {"path": note_path})
            if not read_result.isError:
                content = result_data(read_result)
                content_str = content.get("content", "") if isinstance(content, dict) else str(content)
                return content_str, note_path
        except Exception:
            pass

        # Search by address in frontmatter if name-based lookup failed
        try:
            search_result = await session.call_tool("search_simple", {"query": formatted_addr})
            if not search_result.isError:
                data = result_data(search_result)
                if isinstance(data, list) and len(data) > 0:
                    for item in data:
                        filename = item.get("filename", "")
                        if filename and filename.startswith("functions/"):
                            read_result = await session.call_tool("vault_read", {"path": filename})
                            if not read_result.isError:
                                content = result_data(read_result)
                                content_str = content.get("content", "") if isinstance(content, dict) else str(content)
                                return content_str, filename
        except Exception as e:
            logger.debug("obsidian.search_failed", extra={"error": str(e)})

        return None, None


async def write_function_note(
    session: ClientSession,
    _vault_path: str,
    address: str,
    old_name: str,
    new_name: str,
    note_content: str,
    existing_path: str | None = None,
    existing_content: str | None = None,
) -> None:
    """Write or update function note in Obsidian vault.

    Uses {name}.md filename. When name changes, vault_move triggers
    Obsidian's automatic link update. Creates functions/ directory if needed.

    If the function was renamed and no existing note exists, creates a stub
    with the OLD name first, then moves it to NEW name. This ensures Obsidian
    updates all existing links pointing to the old name.
    """
    formatted_addr = format_address(address)
    new_filename = make_note_filename(new_name)
    new_path = f"functions/{new_filename}"

    if existing_content:
        note_content = merge_with_user_notes(existing_content, note_content)

    with operation("obsidian.write_note", function_name=new_name, address=formatted_addr, path=new_path):
        try:
            # If function was renamed and no existing note found, create stub with old name first
            if old_name != new_name and not existing_path:
                old_filename = make_note_filename(old_name)
                old_path = f"functions/{old_filename}"

                logger.info("obsidian.creating_stub_for_rename", extra={
                    "old_name": old_name,
                    "new_name": new_name
                })

                # Create stub with old name
                stub_result = await session.call_tool(
                    "vault_write", {"path": old_path, "content": note_content}
                )

                if not stub_result.isError:
                    # Now move it to new name - triggers Obsidian's link update
                    existing_path = old_path

            # If file exists at old path and name changed, use vault_move
            # This triggers Obsidian's link update mechanism
            if existing_path and existing_path != new_path:
                try:
                    move_result = await session.call_tool(
                        "vault_move",
                        {
                            "path": existing_path,
                            "destination": new_path,
                            "allowOverwrite": True
                        }
                    )
                    if not move_result.isError:
                        logger.info("obsidian.note_renamed", extra={
                            "old_path": existing_path,
                            "new_path": new_path
                        })
                        return  # Successfully renamed, content already written
                except Exception as e:
                    logger.warning("obsidian.rename_failed", extra={
                        "error": str(e),
                        "falling_back_to_write": True
                    })

            # Write/update content (fallback or direct write if no rename)
            result = await session.call_tool(
                "vault_write", {"path": new_path, "content": note_content}
            )
            if result.isError:
                error_msg = "\n".join(
                    b.text for b in result.content if b.type == "text"
                )
                logger.warning(
                    "obsidian.write_failed",
                    extra={"path": new_path, "error": error_msg},
                )
            else:
                action = "updated" if existing_content else "created"
                logger.info(f"obsidian.note_{action}", extra={"path": new_path, "function": new_name})
        except Exception as e:
            logger.error(
                "obsidian.write_error", extra={"path": new_path, "error": str(e)}
            )
