from __future__ import annotations
from pathlib import Path
from string import Template
import re

TEMPLATES_DIR = Path(__file__).with_suffix("").parent / "templates"

def _slugify(s: str) -> str:
    """Convert a string to a Python-safe slug.
    
    Converts to lowercase, replaces spaces and hyphens with underscores,
    and removes any characters that aren't alphanumeric, underscore, or dot.
    
    Args:
        s: String to slugify
        
    Returns:
        Slugified string suitable for use in filenames and identifiers
    """
    s = s.strip().lower().replace(" ", "_").replace("-", "_")
    s = re.sub(r"[^a-z0-9_\.]", "", s)
    return s

def render_template(name: str, mapping: dict) -> str:
    """Render a template file with variable substitution.
    
    Args:
        name: Template filename (relative to templates directory)
        mapping: Dictionary of template variables to substitute
        
    Returns:
        Rendered template string
    """
    tpl = (TEMPLATES_DIR / name).read_text()
    return Template(tpl).substitute(mapping)

def create_check(tech: str, name: str, out_dir: Path) -> Path:
    """Generate a new check file and its test file from templates.
    
    Creates a check class file in src/auditx/checks/{tech}/{slug}_check.py
    and a corresponding test file in tests/checks/test_{slug}_check.py.
    
    Args:
        tech: Technology namespace (e.g., 'linux', 'mysql', 'zabbix')
        name: Human-readable check name (e.g., 'File descriptor limits')
        out_dir: Repository root directory where files will be created
        
    Returns:
        Path to the created check file
    """
    slug = _slugify(name)
    # Convert snake_case to PascalCase for class name
    class_name = "".join([part.capitalize() for part in slug.split("_")]) + "Check"
    mapping = {
        "tech": tech,
        "slug": slug,
        "class_name": class_name,
        "human_name": name,
        "check_name": name,
        "short_description": "Short description of what this check verifies.",
        "long_description": "Explain what this check verifies and how.",
        "severity": "LOW",
        "tags": '"configuration"',
        "inputs": "()",
        "required_facts": "()",
        "module_path": f"auditx.checks.{tech}.{slug}_check",
    }
    code = render_template("check.py.tpl", mapping)
    test = render_template("test_check.py.tpl", mapping)
    
    # Create check file
    pkg_dir = out_dir / "src" / "auditx" / "checks" / tech
    pkg_dir.mkdir(parents=True, exist_ok=True)
    fpath = pkg_dir / f"{slug}_check.py"
    fpath.write_text(code)
    
    # Create test file
    tdir = out_dir / "tests" / "checks"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / f"test_{slug}_check.py").write_text(test)
    return fpath

def create_provider(tech: str, name: str, out_dir: Path) -> Path:
    """Generate a new provider module from template.
    
    Creates a provider file in src/auditx/providers/{tech}_{fn}_provider.py
    
    Args:
        tech: Technology namespace (e.g., 'linux', 'mysql', 'zabbix')
        name: Provider name (e.g., 'base facts')
        out_dir: Repository root directory where files will be created
        
    Returns:
        Path to the created provider file
    """
    fn = _slugify(name) + "_provider"
    mapping = {
        "tech": tech,
        "fn_name": fn,
    }
    code = render_template("provider.py.tpl", mapping)
    pkg_dir = out_dir / "src" / "auditx" / "providers"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    fpath = pkg_dir / f"{tech}_{fn}.py"
    fpath.write_text(code)
    return fpath
