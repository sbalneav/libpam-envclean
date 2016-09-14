/*
 * pam_envclean: PAM module for cleaning the environment of XDG_RUNTIME_DIR
 * Copyright (C) 2016 Scott Balneaves <sbalneav@ltsp.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <pwd.h>
#include <config.h>

/*
 * PAM_SM_* define.
 */

#define PAM_SM_SESSION		/* supports session managemtent */

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>

#define ENVVAR "XDG_RUNTIME_DIR"

/*
 * PAM functions
 */

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh, int flags, int argc,
		     const char **argv)
{
  const char *username;
  char *runtime_dir;
  struct passwd *pw;
  struct stat st;
  int pam_result;

  /*
   * Get the username.
   */

  pam_result = pam_get_user (pamh, &username, NULL);
  if (pam_result != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "Couldn't determine username.");
      return pam_result;
    }

  pw = pam_modutil_getpwnam (pamh, username);
  if (!pw)
    {
      pam_syslog (pamh, LOG_ERR, "Cannot lookup user %s passwd entry", username);
      return PAM_SYSTEM_ERR;
    }

  /*
   * Deal with env variable
   */

  runtime_dir = getenv(ENVVAR);
  if (runtime_dir == NULL)
    {
      pam_syslog(pamh, LOG_INFO, "Couldn't find %s envvar", ENVVAR);
      /* envvar isn't there, just return quietly */
      return PAM_SUCCESS;
    }

  if (lstat (runtime_dir, &st))
    {
      pam_syslog(pamh, LOG_ERR, "Failed to stat %s: %s", ENVVAR, strerror(errno));
     return PAM_SYSTEM_ERR;
    }

  if (st.st_uid != pw->pw_uid)
    {
      if (unsetenv(ENVVAR))
        {
          return PAM_SYSTEM_ERR;
        }
      else
        {
          return PAM_SUCCESS;
        }
    }
  else
    {
      return PAM_SUCCESS;
    }
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh, int flags, int argc,
		     const char **argv)
{
    return PAM_SUCCESS;
}
