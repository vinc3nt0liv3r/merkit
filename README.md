# Merkit

Native Windows desktop tool for reviewing and managing Active Directory delegation (OU permissions),
in the style of the RSAT tools. Work in progress.

- `src/Merkit.Core` - SDDL handling, ACL linter, delegation templates, backup vault, audit log, safe-apply with rollback
- `tests/` - unit tests (run on Windows CI)

Build: `dotnet build Merkit.sln -c Release` (.NET 8 SDK, Windows).
