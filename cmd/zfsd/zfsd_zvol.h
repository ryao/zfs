// SPDX-License-Identifier: CDDL-1.0
#ifndef	_ZFSD_ZVOL_H
#define	_ZFSD_ZVOL_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

int zfsd_zvol_publish(const char *dsname);
int zfsd_zvol_unpublish(const char *dsname);
int zfsd_zvol_release_idle(const char *dsname);
int zfsd_zvol_publish_pool(const char *pool);
void zfsd_zvol_unpublish_pool(const char *pool);
boolean_t zfsd_zvol_published_match(const char *name);
void zfsd_zvol_rename_published(const char *oldname, const char *newname);
int zfsd_zvol_set_prop_ro(const char *name, boolean_t val);
void zfsd_zvol_ctrl_fini(void);
void zfsd_zvol_flush_bdevs(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _ZFSD_ZVOL_H */
