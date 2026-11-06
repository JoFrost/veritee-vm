import argparse
from pathlib import Path
from typing import Sequence

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError


def _environment(directory: str) -> Environment:
    # OS configuration is plain text. Missing variables must stop the build.
    return Environment(
        loader=FileSystemLoader(directory),
        autoescape=False,
        undefined=StrictUndefined,
        # Apply the same whitespace rules to every profile and generated file.
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(variables: dict, template_path: str, template_root: str = ".") -> str:
    """Render a template without writing to the filesystem."""
    template = _environment(template_root).get_template(template_path)
    return template.render(variables)


def _load_context(profile: Path) -> dict:
    context = yaml.safe_load(profile.read_text(encoding="utf-8"))
    if not isinstance(context, dict) or any(not isinstance(key, str) for key in context):
        raise ValueError(f"Profile '{profile}' must contain a YAML mapping with string keys")
    return context


def render_template(config_path: str | Path, template_path: str | Path) -> None:
    """Render beside the source template, removing its final .j2 suffix."""
    profile, source = Path(config_path), Path(template_path)
    if source.suffix != ".j2":
        raise ValueError(f"Template path must end with '.j2', got '{source}'")

    context = _load_context(profile)
    # Resolve includes beside the template, independently of the caller's cwd.
    contents = render(context, source.name, str(source.parent))
    destination = source.with_suffix("")
    # Render fully before opening the destination so template errors preserve it.
    destination.write_text(contents, encoding="utf-8")
    print(f"Rendered '{source}' to '{destination}' using '{profile}'")


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render a Veritee OS template using a YAML build profile."
    )
    parser.add_argument("config_path", type=Path, help="YAML build profile")
    parser.add_argument("file_path", type=Path, help="Source template ending in .j2")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    try:
        render_template(arguments.config_path, arguments.file_path)
    except (OSError, ValueError, yaml.YAMLError, TemplateError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
