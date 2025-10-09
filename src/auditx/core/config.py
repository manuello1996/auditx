from __future__ import annotations
import os
from pathlib import Path
from textwrap import dedent
from typing import Any, Dict, List, Sequence, Union
import yaml

_CONFIG_DIR_ENV = "AUDITX_CONFIG_DIR"

_DEFAULT_TEMPLATE_YAML = dedent(
    """
    mysql:
      host: db1.example.com
      user: auditor
      password: ${env:MYSQL_AUDITOR_PASS}
      database: appdb

    zabbix:
      api_url: https://zabbix.example.com/api_jsonrpc.php
      api_token: ""
      username: auditor
      password: ${env:ZABBIX_PASS}
      config_file: /etc/zabbix/zabbix_server.conf
      config_duplicate_ignore_keys: []
      host_encryption_ignore_hosts: []
      template_version_ignore: []
      hosts_unavailable_threshold_hours: 24
      lld_min_refresh_seconds: 3600
      item_min_refresh_seconds: 60
      item_refresh_excluded_keys: []
      unsupported_item_threshold_minutes: 60

    linux:
      method: local
    """
)


def _candidate_config_dirs() -> List[Path]:
    """Ordered list of directories to scan for configuration files."""

    directories: List[Path] = []

    home_dir = Path.home() / ".auditx"
    directories.append(home_dir)

    cwd_dir = Path.cwd() / "config"
    if cwd_dir not in directories:
        directories.append(cwd_dir)

    env_value = os.environ.get(_CONFIG_DIR_ENV, "")
    for fragment in (part.strip() for part in env_value.split(os.pathsep) if part.strip()):
        candidate = Path(fragment).expanduser()
        if candidate not in directories:
            directories.append(candidate)

    return directories


def _candidate_config_files() -> List[Path]:
    """Fallback individual configuration files to consider."""

    files: List[Path] = []
    candidates = [
        Path.cwd() / "auditx.yaml",
        Path.cwd() / "auditx.yml",
        Path.home() / ".auditx" / "auditx.yaml",
        Path.home() / ".auditx" / "auditx.yml",
    ]

    env_value = os.environ.get(_CONFIG_DIR_ENV, "")
    for fragment in (part.strip() for part in env_value.split(os.pathsep) if part.strip()):
        candidate = Path(fragment).expanduser()
        if candidate.suffix.lower() in {".yaml", ".yml"}:
            candidates.append(candidate)

    seen: set[Path] = set()
    for path in candidates:
        if path not in seen:
            files.append(path)
            seen.add(path)

    return files

PathLike = Union[str, Path]


def load_project_config(explicit_files: Sequence[PathLike] | None = None) -> Dict[str, Any]:
    """Load and merge all YAML configuration files from the config/ directory.
    
    Scans for .yml and .yaml files in the config/ directory (or legacy auditx.yaml)
    and merges them in lexicographic order using deep merge.
    
    Returns:
        Merged configuration dictionary
    """
    files: List[Path] = []
    seen: set[Path] = set()

    for directory in _candidate_config_dirs():
        if directory.exists() and directory.is_dir():
            for pattern in ("*.yml", "*.yaml"):
                for path in sorted(directory.glob(pattern)):
                    if path not in seen:
                        files.append(path)
                        seen.add(path)

    data: Dict[str, Any] = {}
    if not files:
        for candidate in _candidate_config_files():
            if candidate.exists() and candidate.is_file() and candidate not in seen:
                files.append(candidate)
                seen.add(candidate)

    if explicit_files:
        for spec in explicit_files:
            candidate = Path(spec).expanduser()
            if candidate not in seen:
                files.append(candidate)
                seen.add(candidate)

    for path in files:
        try:
            content = yaml.safe_load(path.read_text())
        except FileNotFoundError:
            continue
        if content:
            deep_merge(data, content)
    return data

def deep_merge(a: dict, b: dict) -> dict:
    """Recursively merge dictionary b into dictionary a.
    
    For nested dictionaries, performs a deep merge. For other values,
    b's values take precedence over a's values.
    
    Args:
        a: Target dictionary (modified in place)
        b: Source dictionary to merge from
        
    Returns:
        The modified dictionary a
    """
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            deep_merge(a[k], v)
        else:
            a[k] = v
    return a

def env_to_overrides(env: dict[str, str]) -> dict:
    """Convert AUDITX__ prefixed environment variables to config overrides.
    
    Transforms environment variables like AUDITX__mysql__host into nested
    configuration: {mysql: {host: value}}.
    
    Args:
        env: Environment variables dictionary
        
    Returns:
        Nested configuration dictionary
    """
    out: dict = {}
    prefix = "AUDITX__"
    for key, value in env.items():
        if key.startswith(prefix):
            # Split path by __ separator
            path = key[len(prefix):].split("__")
            current = out
            # Navigate/create nested structure
            for segment in path[:-1]:
                current = current.setdefault(segment, {})
            # Set the final value
            current[path[-1]] = value
    return out

def deep_set(d: dict, dotted: str, value: str) -> None:
    """Set a value in a nested dictionary using dot notation.
    
    Creates intermediate dictionaries as needed.
    
    Args:
        d: Target dictionary to modify
        dotted: Dot-separated path (e.g., "mysql.host")
        value: Value to set at the path
    """
    current = d
    parts = dotted.split('.')
    for key in parts[:-1]:
        current = current.setdefault(key, {})
    current[parts[-1]] = value

def merge_overrides(
    cfg: dict,
    *,
    vars_file: Path | None,
    set_kv: list[str],
    env: dict[str, str]
) -> dict:
    """Merge configuration overrides from multiple sources.
    
    Applies overrides in order:
    1. Base configuration
    2. Variables file (--vars-file)
    3. Key-value pairs (--set)
    4. Environment variables (AUDITX__)
    
    Args:
        cfg: Base configuration dictionary
        vars_file: Optional path to YAML file with overrides
        set_kv: List of key=value override strings
        env: Environment variables dictionary
        
    Returns:
        Merged configuration dictionary
        
    Raises:
        SystemExit: If --set parameter is malformed
    """
    merged = dict(cfg)
    if vars_file and vars_file.exists():
        merged = deep_merge(merged, yaml.safe_load(vars_file.read_text()) or {})
    for item in set_kv:
        if "=" not in item:
            raise SystemExit("--set expects key=value")
        key, value = item.split('=', 1)
        deep_set(merged, key, value)
    return deep_merge(merged, env_to_overrides(env))

def _resolve_token(token: str, ask: bool) -> str:
    """Resolve a secret token placeholder to its actual value.
    
    Supports placeholders:
    - ${env:VAR_NAME} - read from environment variable
    - ${file:/path/to/file} - read from file
    - Other values - prompt user if ask=True
    
    Args:
        token: Token string to resolve
        ask: Whether to prompt user for unknown tokens
        
    Returns:
        Resolved value string
    """
    if token.startswith('${env:') and token.endswith('}'):
        return os.environ.get(token[6:-1], '')
    if token.startswith('${file:') and token.endswith('}'):
        return Path(token[7:-1]).read_text().strip()
    return token if not ask else input(f"Enter secret for {token}: ")

def _walk(obj: Any, ask: bool) -> Any:
    """Recursively walk a data structure and resolve secret tokens.
    
    Args:
        obj: Object to walk (dict, list, or scalar)
        ask: Whether to prompt for unknown secrets
        
    Returns:
        Object with resolved secrets
    """
    if isinstance(obj, dict):
        return {k: _walk(v, ask) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(x, ask) for x in obj]
    if isinstance(obj, str) and obj.startswith('${'):
        return _resolve_token(obj, ask)
    return obj

def resolve_secrets(cfg: dict, *, ask: bool) -> dict:
    """Resolve secret placeholders in configuration.
    
    Walks the configuration tree and resolves any secret tokens
    like ${env:VAR} or ${file:/path}.
    
    Args:
        cfg: Configuration dictionary
        ask: Whether to prompt for unresolved secrets
        
    Returns:
        Configuration with resolved secrets
    """
    return _walk(cfg, ask)

def load_default_template() -> Dict[str, Any]:
    """Load the default configuration template.
    
    Reads config/auditx.yaml.default to use as a template for
    interactive configuration setup.
    
    Returns:
        Template configuration dictionary, or empty dict if not found
    """
    candidate_paths: List[Path] = []
    for directory in _candidate_config_dirs():
        candidate_paths.append(directory / "auditx.yaml.default")
    candidate_paths.append(Path.cwd() / "config" / "auditx.yaml.default")

    for path in candidate_paths:
        if path.exists() and path.is_file():
            content = yaml.safe_load(path.read_text())
            return content or {}

    return yaml.safe_load(_DEFAULT_TEMPLATE_YAML) or {}
