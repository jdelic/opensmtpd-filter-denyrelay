Golang implementation of an authenticated relay denylist filter for OpenSMTPD
=============================================================================

This filter uses `opensmtpd-filters-go <https://github.com/jdelic/opensmtpd-filters-go>`__
and inspects authenticated SMTP sessions. Accounts listed in the denylist are
blocked from relaying mail, either entirely or to all recipients except an
explicit allowlist. It can also validate one-time agent email auth tokens
issued by `jdelic/authserver <https://github.com/jdelic/authserver>`__ and
strip them back out of the delivered message body.

Denylist format
---------------

Pass the denylist path as the first positional argument to the executable.
Each non-empty, non-comment line must contain either a single email address or
an authenticated user plus an allowed recipient separated by ``=``.
Authenticated usernames are matched case-insensitively, and denylist entries for
``user@example.com`` also apply to ``user+suffix@example.com`` and
``user-suffix@example.com``.

::

    # example denylist
    norelay@example.com
    relayonlyto@example.com=other@example.com
    relayoptions@example.com=one@example.com
    relayoptions@example.com=two@example.com

In this example:

* ``norelay@example.com`` cannot send mail to any recipient.
* ``relayonlyto@example.com`` may only send mail to ``other@example.com``.
* ``relayoptions@example.com`` may only send mail to ``one@example.com`` and
  ``two@example.com``.

Email agent auth token support
------------------------------

When ``-agent-email-auth-validation-url`` is configured, the filter also checks
the first line of the message body for::

    X-Agent-Email-Auth: <token>

If present, the filter validates the token against authserver's
``POST /email-agent-auth-tokens/validate/`` endpoint, burns it on success, and
removes the token line from the message body before the message is accepted. If
the token line is followed by an empty line, that extra empty line is removed
as well.

For authenticated users who would otherwise be blocked by the denylist, a valid
token allows the message to proceed. Invalid or reused tokens are rejected, and
temporary authserver failures are soft-rejected.

The request and response contract for this endpoint is documented in the
authserver repository at ``.agent-docs/agent-tokens/email/README.rst`` (see
`authserver PR #508 <https://github.com/jdelic/authserver/pull/508>`__ until it
lands on the default branch).

Example usage in smtpd.conf
---------------------------

::

    filter "denyrelay" proc-exec "/usr/lib/x86_64-linux-gnu/opensmtpd/filter-denyrelay -agent-email-auth-validation-url https://auth.example.com/email-agent-auth-tokens/validate/ /etc/opensmtpd/denyrelay.list"
    listen on 0.0.0.0 port submission auth filter denyrelay

Sessions without successful SMTP authentication are ignored by the filter.
