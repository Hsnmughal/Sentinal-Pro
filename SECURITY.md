# Security

Sentinal Pro runs a local dashboard and stores its state in SQLite. Keep the
default `127.0.0.1` binding. This release is intended for a single user on their
own machine; its HTTP API does not have a multi-user authentication layer.

Monitoring makes outbound requests to the platforms you configure. Put your own
credentials in environment variables or a local `.env` next to `config.toml`.
Neither credentials nor local databases should be committed or attached to
issues. Treat local exports and backups as private unless you have reviewed them.

The tool fetches remote metadata and recorded patches; it does not clone,
install, or execute monitored repositories. Review exported patches before
applying them. Only install adapters you trust: adapters are local Python code.

For a suspected vulnerability in this tool, use the repository's **Security →
Report a vulnerability** option when available. If private reporting has not
been enabled, open a minimal issue requesting a private contact route without
including exploit details, credentials, private repositories, or personal data.
The publishing maintainer should enable private vulnerability reporting before
opening the repository to public contributions.

Include the app/Python version, operating system, and a minimal reproduction
against disposable data in a private report. Reports about monitored projects
belong with those projects' own disclosure processes.
