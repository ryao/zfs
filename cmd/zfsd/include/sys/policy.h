// SPDX-License-Identifier: CDDL-1.0
/*
 * secpolicy_* used by module/zfs/zfs_vnops.c and the zfsd OS glue.
 */
#ifndef	_SYS_POLICY_H
#define	_SYS_POLICY_H

#include <sys/cred.h>
#include <sys/types.h>
#include <sys/xvattr.h>

struct znode;
struct inode;
struct vattr;

int secpolicy_vnode_setid_retain(struct znode *, const cred_t *, boolean_t);
int secpolicy_xvattr(xvattr_t *, uid_t, cred_t *, mode_t);
int secpolicy_vnode_access2(const cred_t *, struct inode *,
    uid_t, mode_t, mode_t);
int secpolicy_vnode_setdac(const cred_t *, uid_t);
int secpolicy_vnode_chown(const cred_t *, uid_t);
int secpolicy_vnode_remove(const cred_t *);
int secpolicy_vnode_create_gid(const cred_t *);
int secpolicy_basic_link(const cred_t *);
void secpolicy_setid_clear(vattr_t *, cred_t *);
int secpolicy_setid_setsticky_clear(struct inode *, struct vattr *,
    const struct vattr *, cred_t *);
int secpolicy_vnode_setattr(cred_t *, struct inode *, struct vattr *,
    const struct vattr *, int, int (*)(void *, int, cred_t *), void *);
int secpolicy_zfs(const cred_t *);
int secpolicy_sys_config(const cred_t *, boolean_t);
int secpolicy_zinject(const cred_t *);

#endif	/* _SYS_POLICY_H */
