pammod_PROGRAMS = pam_envclean.so
pammoddir=/lib/security

pam_envclean_so_SOURCES = pam_envclean.c
pam_envclean_so_CFLAGS = -fpic $(GLIB_CFLAGS)
pam_envclean_so_LDFLAGS = -shared
pam_envclean_so_LDADD = $(PAM_LIBS) $(CRYPT_LIBS) $(GLIB_LIBS)
