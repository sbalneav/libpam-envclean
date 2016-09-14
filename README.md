libpam-envclean
===============

What is it?
-----------

It's a pam module that removes the XDG_RUNTIME_DIR environment variable from
the environment if the user authenticating is different from the user owning
it.  This is for the case of programs like gksu clobbering the users' dconf
settings.

How do I use it?
----------------

Simply place it after the pam_systemd.so line:

session optional        pam_systemd.so
session optional        pam_envclean.so
