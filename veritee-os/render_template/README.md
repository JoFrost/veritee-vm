# Veritee template renderer

Generate OS build files from a YAML profile and a Jinja template:

```sh
render_template ../config-azure.yaml mkosi.conf.j2
```

The output is written beside the template with the `.j2` suffix removed.
Profiles must be YAML mappings. Missing variables and invalid inputs stop the
command before it replaces an existing output file. Includes are resolved
relative to the source template; profiles and output files use UTF-8.
