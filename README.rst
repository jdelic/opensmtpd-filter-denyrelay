Golang implementation of an authenticated relay denylist filter for OpenSMTPD
=============================================================================

This filter uses `opensmtpd-filters-go <https://github.com/jdelic/opensmtpd-filters-go>`__
and inspects authenticated SMTP sessions. Accounts listed in the denylist are
blocked from relaying mail, either entirely or to all recipients except an
explicit allowlist.

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

Example usage in smtpd.conf
---------------------------

::

    filter "denyrelay" proc-exec "/usr/lib/x86_64-linux-gnu/opensmtpd/filter-denyrelay /etc/opensmtpd/denyrelay.list"
    listen on 0.0.0.0 port submission auth filter denyrelay

Sessions without successful SMTP authentication are ignored by the filter.
