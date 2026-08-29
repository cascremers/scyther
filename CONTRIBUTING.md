# Contributing to Scyther

Thank you for taking an interest in Scyther. Every careful report, tidy fix,
and well-tested protocol model helps keep this  project useful for the
people who still rely on it.

Scyther is minimally maintained with very limited resources. Its purpose is to
support educators and existing users; major new features are not planned. For
new, state-of-the-art research projects, please consider the
[Tamarin Prover](https://tamarin-prover.com/). We ask for your understanding
and a little patience when replies or reviews take time.

## Before you begin

Please read the [Code of Conduct](CODE_OF_CONDUCT.md). Be kind, be specific,
and leave room for people to learn. Contributions must be your own work and
must be accurate, relevant, and reviewed before submission.

Before opening an issue or pull request, search existing reports and try the
current version where practical. A small, reproducible example can save a
maintainer a great deal of time.

## Reporting bugs

Open an issue with enough information for someone else to understand and
reproduce the problem:

- A clear description of the observed behavior and the expected behavior.
- Steps to reproduce it, including a minimal SPDL model or command when
  applicable.
- Your operating system, Scyther version or commit, and relevant build details.
- Exact output, error messages, or a short trace of the failure.

Issues that contain no real content and simply link to external documents are
not accepted. Put the relevant context, a concise problem statement, and
reproduction details in the issue itself. Links may support a report, but they
cannot replace it. Maintainers may close link-only issues without further
discussion.

Please do not use public issues to report security vulnerabilities. Contact a
maintainer privately using the contact information published with the project,
and include the details needed to assess the report.

## Proposing changes

Small, focused pull requests are the easiest ones to review. Explain what the
change does, why it belongs in Scyther, and how you tested it. Keep unrelated
formatting, generated files, and refactoring out of the same pull request.

For changes to the verifier or bundled models, add or update a focused test or
protocol example when practical. Run the relevant checks before opening the
pull request:

```bash
make
make test
```

For documentation-only changes, please check links, commands, and Markdown
rendering. Let us know when a check cannot run in your environment.

New protocol models, corrections to existing models, documentation repairs,
and modest maintenance fixes are especially welcome. Please talk with us in an
issue before investing substantial time in a new feature: it may not fit the
project's limited support capacity.

## Review and follow-up

Maintainers may ask for a smaller scope, more evidence, tests, or a revision.
They may also decline a contribution that cannot be maintained with the time
available. That is not a judgment on the worth of your effort; it is an honest
account of this project's resources.

Thank you for bringing your best manners and your sharpest thinking. We are
glad to have your help keeping Scyther useful.