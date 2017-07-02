c-ares release procedure - how to do a release
==============================================

in the source code repo
-----------------------

- edit `RELEASE-NOTES` to be accurate

- make sure all relevant changes are committed on the master branch

- tag the git repo in this style: `git tag -a cares-1_13_0` -a annotates the
  tag and we use underscores instead of dots in the version number.

- run "./maketgz 1.13.0" to build the release tarball. It is important that
  you run this on a machine with the correct set of autotools etc installed
  as this is what then will be shipped and used by most users on *nix like
  systems.

- push the git commits and the new tag

- gpg sign the tarball

- upload the resulting files to https://c-ares.haxx.se/download/

- update `ares_version.h` for the next version

in the c-ares-www repo
----------------------

- edit `index.t` (version number and date),

- edit `changelog.t` (add the new release in there)

- commit all local changes

- tag the repo with the same tag as used for the source repo

- push the git commits and the new tag

inform
------

- send an email to the c-ares mailing list. Insert the RELEASE-NOTES into the
  mail.

celebrate
---------

- suitable beverage intake is encouraged for the festivities
