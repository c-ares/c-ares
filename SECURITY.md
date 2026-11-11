# c-ares Security Reporting Policy

- [Publishing](#publishing)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)
  - [Reporting Requirements](#reporting-requirements)
- [Vulnerability Handling](#vulnerability-handling)
- [Joining the Security Team](#joining-the-security-team)

This document is intended to provide guidance on how security vulnerabilities
should be handled in the c-ares project.

## Publishing

All known and public c-ares vulnerabilities will be listed on [the c-ares web
site](https://c-ares.org/vulns.html).

Security vulnerabilities should not be entered in the project's public bug
tracker unless the necessary configuration is in place to limit access to the
issue to only the reporter and the project's security team.

## Reporting Vulnerabilities

- The person discovering the issue, the reporter, reports the vulnerability
  privately to [c-ares-security@haxx.se](mailto:c-ares-security@haxx.se). That's
  an email alias that reaches a handful of selected and trusted people.

- Messages that do not relate to the reporting or managing of an undisclosed
  security vulnerability in c-ares are ignored and no further action is
  required.

### Reporting Requirements

1. The reporter should take great care in ensuring the security vulnerability
   report is valid and accurate.  The reporter must understand reviewing
   security vulnerability reports is a time consuming process and the c-ares
   security team are volunteers.  A vast majority of vulnerability reports
   we receive are invalid.  Please don't waste their time.
2. The report must have a detailed description of the issue or issues.
3. The report must contain the c-ares version that was tested.  If from an
   unreleased version (e.g. from git main), please provide the branch name and
   git hash tested.
4. The report should have a valid minimal test case to reproduce the issue.
   1. Any code in a test case that isn't relevant to reproducing the issue
      ***must*** be removed.
   2. The test case ***must*** compile cleanly with warnings enabled, for
      clang/gcc at a minimum, `-Wall -W`, or `/W3` for MSVC.
   3. The reporter ***must*** validate the API being called is being used in an
      appropriate manner, in accordance with common C best practices and
      requirements. e.g.:
      1. If an API takes a C string, that means the input must be a valid C
         string (e.g. NULL terminated).
      2. Must not cast incompatible data types to silence compiler warnings
         as this will cause undefined behavior.  Use the right data types. (e.g.
         `struct ares_txt_reply *` can't be cast to `ares_dns_record_t *`, they
         are different types).
      3. Make sure to free/destroy any c-ares generated objects using the
         correct function as documented in the man page of the function that
         generated the object (e.g. use `ares_free_hostent()` to free
         a `struct hostent *` created by `ares_parse_ptr_reply()`, not
         `ares_free_data()`).
5. The report should include a stacktrace/backtrace of the issue if possible.
6. Include the below acknowledgement statement in the email containing the
   vulnerability report.  Evaluation of the vulnerabilities will not occur
   without this statement.  The team will simply respond redirecting you to this
   document on reporting requirements if the statement is not included.
   Acknowledgement statement:
   ```
   I acknowledge I have read and complied with the security reporting
   requirements as described in https://c-ares.org/security.html
   ```

## Vulnerability Handling

The typical process for handling a new security vulnerability is as follows.

No information should be made public about a vulnerability until it is
formally announced at the end of this process. That means, for example that a
bug tracker entry must NOT be created to track the issue since that will make
the issue public and it should not be discussed on the project's public
mailing list. Also messages associated with any commits should not make any
reference to the security nature of the commit if done prior to the public
announcement.

- A vulnerability report is sent as per [Reporting Vulnerabilities](#reporting-vulnerabilities).

- A person in the security team sends an e-mail to the original reporter to
  acknowledge the report.

- The security team investigates the report and either rejects it or accepts
  it.

- If the report is rejected, the team writes to the reporter to explain why.

- If the report is accepted, the team writes to the reporter to let them
  know it is accepted and that they are working on a fix.

- The release of the information should be "as soon as possible" and is most
  often synced with an upcoming release that contains the fix. If the
  reporter, or anyone else, thinks the next planned release is too far away
  then a separate earlier release for security reasons should be considered.

- Write a security advisory draft about the problem that explains what the
  problem is, its impact, which versions it affects, solutions or
  workarounds, when the release is out and make sure to credit all
  contributors properly.

- Request a CVE number from GitHub by drafting a security advisory via
  [GitHub Security](https://github.com/c-ares/c-ares/security), then requesting
  a CVE be assigned.

- The security team discusses the problem, works out a fix, considers the
  impact of the problem and suggests a release schedule. This discussion
  should involve the reporter as much as possible.

- The security team commits the fix in a private branch automatically generated
  by the GitHub security advisory creation process. The commit message
  should ideally contain the CVE number. This fix is usually also distributed
  to the 'distros' mailing list to allow them to use the fix prior to the
  public announcement.

- Send the advisory draft to [distros@openwall](http://oss-security.openwall.org/wiki/mailing-lists/distros)
  to prepare them for the upcoming public security vulnerability announcement.
  For high-severity fixes, a patch should also be attached so it can be
  integrated prior to the official release. Note that 'distros' won't accept an
  embargo longer than 19 days.

- At the day of the next release, the private branch is merged into the master
  branch and pushed, the GitHub advisory is made public.  Once pushed, the
  information is accessible to the public and the actual release should follow
  suit immediately afterwards.

- The project team creates a release that includes the fix.

- The project team announces the release and the vulnerability to the world in
  the same manner we always announce releases. It gets sent to the c-ares
  mailing list and the oss-security mailing list.

- The security web page on the web site should get the new vulnerability
  mentioned.


## Joining the Security Team

Who is on the security team receiving notices via [c-ares-security@haxx.se](mailto:c-ares-security@haxx.se)?

There are a couple of criteria you must meet, and then we might ask you to join
the list or you can ask to join it. It really isn't very formal. We basically
only require that you have a long-term presence in the c-ares project and you
have shown an understanding for the project and its way of working. You must've
been around for a good while and you should have no plans in vanishing in the
near future.

We do not make the list of partipants public mostly because it tends to vary
somewhat over time and a list somewhere will only risk getting outdated.
