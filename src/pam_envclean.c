/*
 * pam_sshauth: PAM module for authentication via a remote ssh server.
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

#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <config.h>

/*
 * PAM_SM_* define.
 */

#define PAM_SM_SESSION		/* supports session managemtent */

#include <security/pam_modules.h>
#include <security/pam_modutils.h>

#define ENVVAR "XDG_RUNTIME_DIR"

/*
 * PAM functions
 */

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh, int flags, int argc,
		     const char **argv)
{
  const char *username;
  const char *runtime_dir;
  struct passwd *pwent;
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

  pwent = pam_modutil_getpwnam (pamh, username);
  if (!pwent)
    {
      pam_syslog (pamh, LOG_ERR, "Cannot lookup user %s passwd entry", username);
      return PAM_SYSTEM_ERR;
    }

  /*
   * Deal with env variable
   */

  if (!(runtime_dir = pam_getenv(pamh, envvar)))
    {
      /* envvar isn't there, just return quietly */
      return PAM_SUCCESS;
    }

  if (lstat (runtime_dir, &st))
    {
      pam_syslog(handle, LOG_ERR, "Failed to stat %s: %s", envvar, strerror(errno));
     return PAM_SYSTEM_ERR;
    }

  if (st.st_uid != pw->pw_uid)
    {
      pam_result = pam_putenv(handle, envvar);
      return pam_result;
    }
  else
    {
      return PAM_SUCCESS;
    }
}
