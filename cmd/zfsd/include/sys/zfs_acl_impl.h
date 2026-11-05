// SPDX-License-Identifier: CDDL-1.0
#ifndef	_ZFS_ACL_IMPL_H
#define	_ZFS_ACL_IMPL_H

#include <sys/zfs_acl.h>
#include <sys/zpl.h>

int zfs_acl_ids_create(struct znode *, int, vattr_t *,
    cred_t *, vsecattr_t *, zfs_acl_ids_t *, zidmap_t *);
void zfs_acl_ids_free(zfs_acl_ids_t *);
boolean_t zfs_acl_ids_overquota(struct zfsvfs *, zfs_acl_ids_t *, uint64_t);
int zfs_fastaccesschk_execute(struct znode *, cred_t *);
int zfs_zaccess_unix(void *, int, cred_t *);
int zfs_acl_chmod_setattr(struct znode *, zfs_acl_t **, uint64_t);
int zfs_zaccess_idmap(struct znode *, int, int, boolean_t, cred_t *,
    zidmap_t *);
int zfs_zaccess_rwx_idmap(struct znode *, mode_t, int, cred_t *, zidmap_t *);
int zfs_zaccess_delete(struct znode *, struct znode *, cred_t *, zidmap_t *);
int zfs_zaccess_rename(struct znode *, struct znode *,
    struct znode *, struct znode *, cred_t *cr, zidmap_t *idmap);
void zfs_acl_free(zfs_acl_t *);
int zfs_vsec_2_aclp(struct zfsvfs *, umode_t, vsecattr_t *, cred_t *,
    struct zfs_fuid_info **, zfs_acl_t **);
int zfs_aclset_common(struct znode *, zfs_acl_t *, cred_t *, dmu_tx_t *);
int zfs_znode_acl_version(struct znode *);
zfs_acl_t *zfs_acl_alloc(int);
zfs_acl_node_t *zfs_acl_node_alloc(size_t);
uint64_t zfs_mode_compute(uint64_t, zfs_acl_t *,
    uint64_t *, uint64_t, uint64_t);
int zfs_acl_chown_setattr(struct znode *);

#endif
