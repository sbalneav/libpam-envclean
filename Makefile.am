AUTOMAKE_OPTIONS = dist-bzip2
DISTCLEANFILES = ChangeLog
EXTRA_DIST = autogen.sh

SUBDIRS = src man

.PHONY: ChangeLog
ChangeLog:
		git log > ChangeLog || touch ChangeLog

dist-hook: ChangeLog
