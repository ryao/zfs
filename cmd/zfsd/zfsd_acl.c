// SPDX-License-Identifier: CDDL-1.0
/*
 * zfsd OS ACL and policy. Same names as module/os/linux/zfs/zfs_acl.c
 * and policy.c. SA DACL is read and evaluated; trivial unix-mode ACLs
 * keep native SA znodes kernel-readable.
 */

#include <sys/zfs_context.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_acl_impl.h>
#include <sys/zfs_fuid.h>
#include <sys/zfs_quota.h>
#include <sys/zfs_sa.h>
#include <sys/sa.h>
#include <sys/dmu.h>
#include <sys/dnode.h>
#include <sys/policy.h>
#include <sys/vnode.h>
#include <sys/zpl.h>
#include <sys/xvattr.h>
#include <sys/acl.h>

#include <sys/stat.h>
#include <sys/byteorder.h>
#include <sys/zfs_ioctl.h>
#include <string.h>

zidmap_t *zfs_init_idmap = NULL;

#define	ALLOW	ACE_ACCESS_ALLOWED_ACE_TYPE
#define	DENY	ACE_ACCESS_DENIED_ACE_TYPE
#define	MAX_ACE_TYPE	ACE_SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
#define	OWNING_GROUP		(ACE_GROUP|ACE_IDENTIFIER_GROUP)
#define	WRITE_MASK_DATA (ACE_WRITE_DATA|ACE_APPEND_DATA|ACE_WRITE_NAMED_ATTRS)
#define	WRITE_MASK_ATTRS (ACE_WRITE_ACL|ACE_WRITE_OWNER|ACE_WRITE_ATTRIBUTES| \
    ACE_DELETE|ACE_DELETE_CHILD)
#define	WRITE_MASK (WRITE_MASK_DATA|WRITE_MASK_ATTRS)
#define	ACE_TYPE_FLAGS	(ACE_OWNER|ACE_GROUP|ACE_EVERYONE|ACE_IDENTIFIER_GROUP)
#define	ALL_MODE_EXECS	(S_IXUSR | S_IXGRP | S_IXOTH)
#define	ZFS_CHECKED_MASKS (ACE_READ_ACL|ACE_READ_ATTRIBUTES|ACE_READ_DATA| \
    ACE_READ_NAMED_ATTRS|ACE_WRITE_DATA|ACE_WRITE_ATTRIBUTES| \
    ACE_WRITE_NAMED_ATTRS|ACE_APPEND_DATA|ACE_EXECUTE|ACE_WRITE_OWNER| \
    ACE_WRITE_ACL|ACE_DELETE|ACE_DELETE_CHILD|ACE_SYNCHRONIZE)
#define	V4_ACL_WIDE_FLAGS (ZFS_ACL_AUTO_INHERIT|ZFS_ACL_DEFAULTED|\
    ZFS_ACL_PROTECTED)
#define	ZFS_ACL_WIDE_FLAGS (V4_ACL_WIDE_FLAGS|ZFS_ACL_TRIVIAL|ZFS_INHERIT_ACE|\
    ZFS_ACL_OBJ_ACE)
#define	IDMAP_WK_CREATOR_OWNER_UID	2147483648U

static boolean_t zfs_write_implies_delete_child = B_TRUE;

typedef struct trivial_acl {
	uint32_t	allow0;
	uint32_t	deny1;
	uint32_t	deny2;
	uint32_t	owner;
	uint32_t	group;
	uint32_t	everyone;
} trivial_acl_t;

static uint16_t
zfs_ace_v0_get_type(void *acep)
{
	return (((zfs_oldace_t *)acep)->z_type);
}

static uint16_t
zfs_ace_v0_get_flags(void *acep)
{
	return (((zfs_oldace_t *)acep)->z_flags);
}

static uint32_t
zfs_ace_v0_get_mask(void *acep)
{
	return (((zfs_oldace_t *)acep)->z_access_mask);
}

static uint64_t
zfs_ace_v0_get_who(void *acep)
{
	return (((zfs_oldace_t *)acep)->z_fuid);
}

static void
zfs_ace_v0_set_type(void *acep, uint16_t type)
{
	((zfs_oldace_t *)acep)->z_type = type;
}

static void
zfs_ace_v0_set_flags(void *acep, uint16_t flags)
{
	((zfs_oldace_t *)acep)->z_flags = flags;
}

static void
zfs_ace_v0_set_mask(void *acep, uint32_t mask)
{
	((zfs_oldace_t *)acep)->z_access_mask = mask;
}

static void
zfs_ace_v0_set_who(void *acep, uint64_t who)
{
	((zfs_oldace_t *)acep)->z_fuid = (uint32_t)who;
}

static size_t
zfs_ace_v0_size(void *acep)
{
	(void) acep;
	return (sizeof (zfs_oldace_t));
}

static size_t
zfs_ace_v0_abstract_size(void)
{
	return (sizeof (zfs_oldace_t));
}

static int
zfs_ace_v0_mask_off(void)
{
	return (offsetof(zfs_oldace_t, z_access_mask));
}

static int
zfs_ace_v0_data(void *acep, void **datap)
{
	(void) acep;
	*datap = NULL;
	return (0);
}

static const acl_ops_t zfs_acl_v0_ops = {
	.ace_mask_get = zfs_ace_v0_get_mask,
	.ace_mask_set = zfs_ace_v0_set_mask,
	.ace_flags_get = zfs_ace_v0_get_flags,
	.ace_flags_set = zfs_ace_v0_set_flags,
	.ace_type_get = zfs_ace_v0_get_type,
	.ace_type_set = zfs_ace_v0_set_type,
	.ace_who_get = zfs_ace_v0_get_who,
	.ace_who_set = zfs_ace_v0_set_who,
	.ace_size = zfs_ace_v0_size,
	.ace_abstract_size = zfs_ace_v0_abstract_size,
	.ace_mask_off = zfs_ace_v0_mask_off,
	.ace_data = zfs_ace_v0_data
};

static uint16_t
zfs_ace_fuid_get_type(void *acep)
{
	return (((zfs_ace_hdr_t *)acep)->z_type);
}

static uint16_t
zfs_ace_fuid_get_flags(void *acep)
{
	return (((zfs_ace_hdr_t *)acep)->z_flags);
}

static uint32_t
zfs_ace_fuid_get_mask(void *acep)
{
	return (((zfs_ace_hdr_t *)acep)->z_access_mask);
}

static uint64_t
zfs_ace_fuid_get_who(void *args)
{
	uint16_t entry_type;
	zfs_ace_t *acep = args;

	entry_type = acep->z_hdr.z_flags & ACE_TYPE_FLAGS;
	if (entry_type == ACE_OWNER || entry_type == OWNING_GROUP ||
	    entry_type == ACE_EVERYONE)
		return ((uint64_t)-1);
	return (acep->z_fuid);
}

static void
zfs_ace_fuid_set_type(void *acep, uint16_t type)
{
	((zfs_ace_hdr_t *)acep)->z_type = type;
}

static void
zfs_ace_fuid_set_flags(void *acep, uint16_t flags)
{
	((zfs_ace_hdr_t *)acep)->z_flags = flags;
}

static void
zfs_ace_fuid_set_mask(void *acep, uint32_t mask)
{
	((zfs_ace_hdr_t *)acep)->z_access_mask = mask;
}

static void
zfs_ace_fuid_set_who(void *arg, uint64_t who)
{
	zfs_ace_t *acep = arg;
	uint16_t entry_type = acep->z_hdr.z_flags & ACE_TYPE_FLAGS;

	if (entry_type == ACE_OWNER || entry_type == OWNING_GROUP ||
	    entry_type == ACE_EVERYONE)
		return;
	acep->z_fuid = who;
}

static size_t
zfs_ace_fuid_size(void *acep)
{
	zfs_ace_hdr_t *zacep = acep;
	uint16_t entry_type;

	switch (zacep->z_type) {
	case ACE_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
	case ACE_ACCESS_DENIED_OBJECT_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
	case ACE_SYSTEM_ALARM_OBJECT_ACE_TYPE:
		return (sizeof (zfs_object_ace_t));
	case ALLOW:
	case DENY:
		entry_type = zacep->z_flags & ACE_TYPE_FLAGS;
		if (entry_type == ACE_OWNER ||
		    entry_type == OWNING_GROUP ||
		    entry_type == ACE_EVERYONE)
			return (sizeof (zfs_ace_hdr_t));
		zfs_fallthrough;
	default:
		return (sizeof (zfs_ace_t));
	}
}

static size_t
zfs_ace_fuid_abstract_size(void)
{
	return (sizeof (zfs_ace_hdr_t));
}

static int
zfs_ace_fuid_mask_off(void)
{
	return (offsetof(zfs_ace_hdr_t, z_access_mask));
}

static int
zfs_ace_fuid_data(void *acep, void **datap)
{
	zfs_ace_t *zacep = acep;
	zfs_object_ace_t *zobjp;

	switch (zacep->z_hdr.z_type) {
	case ACE_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
	case ACE_ACCESS_DENIED_OBJECT_ACE_TYPE:
	case ACE_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
	case ACE_SYSTEM_ALARM_OBJECT_ACE_TYPE:
		zobjp = acep;
		*datap = (caddr_t)zobjp + sizeof (zfs_ace_t);
		return (sizeof (zfs_object_ace_t) - sizeof (zfs_ace_t));
	default:
		*datap = NULL;
		return (0);
	}
}

static const acl_ops_t zfs_acl_fuid_ops = {
	.ace_mask_get = zfs_ace_fuid_get_mask,
	.ace_mask_set = zfs_ace_fuid_set_mask,
	.ace_flags_get = zfs_ace_fuid_get_flags,
	.ace_flags_set = zfs_ace_fuid_set_flags,
	.ace_type_get = zfs_ace_fuid_get_type,
	.ace_type_set = zfs_ace_fuid_set_type,
	.ace_who_get = zfs_ace_fuid_get_who,
	.ace_who_set = zfs_ace_fuid_set_who,
	.ace_size = zfs_ace_fuid_size,
	.ace_abstract_size = zfs_ace_fuid_abstract_size,
	.ace_mask_off = zfs_ace_fuid_mask_off,
	.ace_data = zfs_ace_fuid_data
};

zfs_acl_t *
zfs_acl_alloc(int vers)
{
	zfs_acl_t *aclp;

	aclp = kmem_zalloc(sizeof (zfs_acl_t), KM_SLEEP);
	list_create(&aclp->z_acl, sizeof (zfs_acl_node_t),
	    offsetof(zfs_acl_node_t, z_next));
	aclp->z_version = (vers != 0) ? (uint_t)vers : ZFS_ACL_VERSION;
	if (aclp->z_version == ZFS_ACL_VERSION_FUID)
		aclp->z_ops = &zfs_acl_fuid_ops;
	else
		aclp->z_ops = &zfs_acl_v0_ops;
	return (aclp);
}

zfs_acl_node_t *
zfs_acl_node_alloc(size_t size)
{
	zfs_acl_node_t *n;

	n = kmem_zalloc(sizeof (zfs_acl_node_t), KM_SLEEP);
	if (size != 0) {
		n->z_acldata = kmem_zalloc(size, KM_SLEEP);
		n->z_allocdata = n->z_acldata;
		n->z_allocsize = size;
		n->z_size = size;
	}
	return (n);
}

static void
zfs_acl_node_free(zfs_acl_node_t *n)
{
	if (n->z_allocdata != NULL)
		kmem_free(n->z_allocdata, n->z_allocsize);
	kmem_free(n, sizeof (zfs_acl_node_t));
}

static void
zfs_acl_release_nodes(zfs_acl_t *aclp)
{
	zfs_acl_node_t *n;

	while ((n = list_head(&aclp->z_acl)) != NULL) {
		list_remove(&aclp->z_acl, n);
		zfs_acl_node_free(n);
	}
	aclp->z_acl_count = 0;
	aclp->z_acl_bytes = 0;
}

void
zfs_acl_free(zfs_acl_t *aclp)
{
	if (aclp == NULL)
		return;
	zfs_acl_release_nodes(aclp);
	list_destroy(&aclp->z_acl);
	kmem_free(aclp, sizeof (zfs_acl_t));
}

void
zfs_acl_ids_free(zfs_acl_ids_t *acl_ids)
{
	if (acl_ids == NULL)
		return;
	if (acl_ids->z_aclp) {
		zfs_acl_free(acl_ids->z_aclp);
		acl_ids->z_aclp = NULL;
	}
	if (acl_ids->z_fuidp) {
		zfs_fuid_info_free(acl_ids->z_fuidp);
		acl_ids->z_fuidp = NULL;
	}
}

static boolean_t
zfs_acl_valid_ace_type(uint_t type, uint_t flags)
{
	uint16_t entry_type;

	switch (type) {
	case ALLOW:
	case DENY:
	case ACE_SYSTEM_AUDIT_ACE_TYPE:
	case ACE_SYSTEM_ALARM_ACE_TYPE:
		entry_type = flags & ACE_TYPE_FLAGS;
		return (entry_type == ACE_OWNER ||
		    entry_type == OWNING_GROUP ||
		    entry_type == ACE_EVERYONE || entry_type == 0 ||
		    entry_type == ACE_IDENTIFIER_GROUP);
	default:
		if (type <= MAX_ACE_TYPE)
			return (B_TRUE);
	}
	return (B_FALSE);
}

static void *
zfs_acl_next_ace(zfs_acl_t *aclp, void *start, uint64_t *who,
    uint32_t *access_mask, uint16_t *iflags, uint16_t *type)
{
	zfs_acl_node_t *aclnode;

	if (aclp == NULL || aclp->z_ops == NULL)
		return (NULL);
	if (start == NULL) {
		aclnode = list_head(&aclp->z_acl);
		if (aclnode == NULL)
			return (NULL);
		aclp->z_next_ace = aclnode->z_acldata;
		aclp->z_curr_node = aclnode;
		aclnode->z_ace_idx = 0;
	}
	aclnode = aclp->z_curr_node;
	if (aclnode == NULL)
		return (NULL);
	if (aclnode->z_ace_idx >= aclnode->z_ace_count) {
		aclnode = list_next(&aclp->z_acl, aclnode);
		if (aclnode == NULL)
			return (NULL);
		aclp->z_curr_node = aclnode;
		aclnode->z_ace_idx = 0;
		aclp->z_next_ace = aclnode->z_acldata;
	}
	if (aclnode->z_ace_idx < aclnode->z_ace_count) {
		void *acep = aclp->z_next_ace;
		size_t ace_size;

		ace_size = aclp->z_ops->ace_size(acep);
		if (((caddr_t)acep + ace_size) >
		    ((caddr_t)aclnode->z_acldata + aclnode->z_size))
			return (NULL);
		*iflags = aclp->z_ops->ace_flags_get(acep);
		*type = aclp->z_ops->ace_type_get(acep);
		*access_mask = aclp->z_ops->ace_mask_get(acep);
		*who = aclp->z_ops->ace_who_get(acep);
		aclp->z_next_ace = (caddr_t)aclp->z_next_ace + ace_size;
		aclnode->z_ace_idx++;
		return (acep);
	}
	return (NULL);
}

static uintptr_t
zfs_ace_walk(void *datap, uintptr_t cookie, int aclcnt,
    uint16_t *flags, uint16_t *type, uint32_t *mask)
{
	zfs_acl_t *aclp = datap;
	zfs_ace_hdr_t *acep = (zfs_ace_hdr_t *)cookie;
	uint64_t who;

	(void) aclcnt;
	acep = zfs_acl_next_ace(aclp, acep, &who, mask, flags, type);
	return ((uintptr_t)acep);
}

static void
zfs_set_ace(zfs_acl_t *aclp, void *acep, uint32_t access_mask,
    uint16_t access_type, uint64_t fuid, uint16_t entry_type)
{
	uint16_t type = entry_type & ACE_TYPE_FLAGS;

	aclp->z_ops->ace_mask_set(acep, access_mask);
	aclp->z_ops->ace_type_set(acep, access_type);
	aclp->z_ops->ace_flags_set(acep, entry_type);
	if (type != ACE_OWNER && type != OWNING_GROUP && type != ACE_EVERYONE)
		aclp->z_ops->ace_who_set(acep, fuid);
}

static void
acl_trivial_access_masks(mode_t mode, boolean_t isdir, trivial_acl_t *masks)
{
	uint32_t read_mask = ACE_READ_DATA;
	uint32_t write_mask = ACE_WRITE_DATA | ACE_APPEND_DATA;
	uint32_t execute_mask = ACE_EXECUTE;

	if (isdir)
		write_mask |= ACE_DELETE_CHILD;

	masks->deny1 = 0;
	if (!(mode & S_IRUSR) && (mode & (S_IRGRP | S_IROTH)))
		masks->deny1 |= read_mask;
	if (!(mode & S_IWUSR) && (mode & (S_IWGRP | S_IWOTH)))
		masks->deny1 |= write_mask;
	if (!(mode & S_IXUSR) && (mode & (S_IXGRP | S_IXOTH)))
		masks->deny1 |= execute_mask;

	masks->deny2 = 0;
	if (!(mode & S_IRGRP) && (mode & S_IROTH))
		masks->deny2 |= read_mask;
	if (!(mode & S_IWGRP) && (mode & S_IWOTH))
		masks->deny2 |= write_mask;
	if (!(mode & S_IXGRP) && (mode & S_IXOTH))
		masks->deny2 |= execute_mask;

	masks->allow0 = 0;
	if ((mode & S_IRUSR) && (!(mode & S_IRGRP) && (mode & S_IROTH)))
		masks->allow0 |= read_mask;
	if ((mode & S_IWUSR) && (!(mode & S_IWGRP) && (mode & S_IWOTH)))
		masks->allow0 |= write_mask;
	if ((mode & S_IXUSR) && (!(mode & S_IXGRP) && (mode & S_IXOTH)))
		masks->allow0 |= execute_mask;

	masks->owner = ACE_WRITE_ATTRIBUTES | ACE_WRITE_OWNER | ACE_WRITE_ACL |
	    ACE_WRITE_NAMED_ATTRS | ACE_READ_ACL | ACE_READ_ATTRIBUTES |
	    ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;
	if (mode & S_IRUSR)
		masks->owner |= read_mask;
	if (mode & S_IWUSR)
		masks->owner |= write_mask;
	if (mode & S_IXUSR)
		masks->owner |= execute_mask;

	masks->group = ACE_READ_ACL | ACE_READ_ATTRIBUTES |
	    ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;
	if (mode & S_IRGRP)
		masks->group |= read_mask;
	if (mode & S_IWGRP)
		masks->group |= write_mask;
	if (mode & S_IXGRP)
		masks->group |= execute_mask;

	masks->everyone = ACE_READ_ACL | ACE_READ_ATTRIBUTES |
	    ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;
	if (mode & S_IROTH)
		masks->everyone |= read_mask;
	if (mode & S_IWOTH)
		masks->everyone |= write_mask;
	if (mode & S_IXOTH)
		masks->everyone |= execute_mask;
}

static int
ace_trivial_common(void *acep, int aclcnt,
    uintptr_t (*walk)(void *, uintptr_t, int,
    uint16_t *, uint16_t *, uint32_t *))
{
	uint16_t flags;
	uint32_t mask;
	uint16_t type;
	uint64_t cookie = 0;

	while ((cookie = walk(acep, cookie, aclcnt, &flags, &type, &mask))) {
		switch (flags & ACE_TYPE_FLAGS) {
		case ACE_OWNER:
		case ACE_GROUP | ACE_IDENTIFIER_GROUP:
		case ACE_EVERYONE:
			break;
		default:
			return (1);
		}
		if (flags & (ACE_FILE_INHERIT_ACE |
		    ACE_DIRECTORY_INHERIT_ACE | ACE_NO_PROPAGATE_INHERIT_ACE |
		    ACE_INHERIT_ONLY_ACE))
			return (1);
		if ((mask & (ACE_READ_ACL | ACE_READ_ATTRIBUTES)) &&
		    type == ACE_ACCESS_DENIED_ACE_TYPE)
			return (1);
		if (mask & ACE_DELETE)
			return (1);
		if ((mask & ACE_DELETE_CHILD) && !(mask & ACE_WRITE_DATA))
			return (1);
		if (type == ACE_ACCESS_ALLOWED_ACE_TYPE &&
		    (!(flags & ACE_OWNER) && (mask &
		    (ACE_WRITE_OWNER | ACE_WRITE_ACL | ACE_WRITE_ATTRIBUTES |
		    ACE_WRITE_NAMED_ATTRS))))
			return (1);
	}
	return (0);
}

static zfs_acl_t *
trivial_acl(mode_t mode, boolean_t isdir)
{
	zfs_acl_t *aclp = zfs_acl_alloc(ZFS_ACL_VERSION);
	size_t abstract_size = aclp->z_ops->ace_abstract_size();
	zfs_acl_node_t *n = zfs_acl_node_alloc(abstract_size * 6);
	trivial_acl_t masks;
	void *zacep;
	int count = 0;
	size_t bytes = 0;

	acl_trivial_access_masks(mode, isdir, &masks);
	zacep = n->z_acldata;
	if (masks.allow0) {
		zfs_set_ace(aclp, zacep, masks.allow0, ALLOW, -1, ACE_OWNER);
		zacep = (void *)((uintptr_t)zacep + abstract_size);
		count++;
		bytes += abstract_size;
	}
	if (masks.deny1) {
		zfs_set_ace(aclp, zacep, masks.deny1, DENY, -1, ACE_OWNER);
		zacep = (void *)((uintptr_t)zacep + abstract_size);
		count++;
		bytes += abstract_size;
	}
	if (masks.deny2) {
		zfs_set_ace(aclp, zacep, masks.deny2, DENY, -1, OWNING_GROUP);
		zacep = (void *)((uintptr_t)zacep + abstract_size);
		count++;
		bytes += abstract_size;
	}
	zfs_set_ace(aclp, zacep, masks.owner, ALLOW, -1, ACE_OWNER);
	zacep = (void *)((uintptr_t)zacep + abstract_size);
	zfs_set_ace(aclp, zacep, masks.group, ALLOW, -1, OWNING_GROUP);
	zacep = (void *)((uintptr_t)zacep + abstract_size);
	zfs_set_ace(aclp, zacep, masks.everyone, ALLOW, -1, ACE_EVERYONE);
	count += 3;
	bytes += abstract_size * 3;
	n->z_ace_count = count;
	n->z_size = bytes;
	aclp->z_acl_count = count;
	aclp->z_acl_bytes = bytes;
	aclp->z_hints = ZFS_ACL_TRIVIAL;
	list_insert_tail(&aclp->z_acl, n);
	return (aclp);
}

int
zfs_acl_ids_create(znode_t *dzp, int flag, vattr_t *vap, cred_t *cr,
    vsecattr_t *vsecp, zfs_acl_ids_t *acl_ids, zidmap_t *idmap)
{
	(void) vsecp;
	(void) idmap;
	memset(acl_ids, 0, sizeof (*acl_ids));
	acl_ids->z_mode = vap->va_mode;
	acl_ids->z_fuid = (vap->va_mask & ATTR_UID) ? vap->va_uid :
	    crgetuid(cr);
	acl_ids->z_fgid = (vap->va_mask & ATTR_GID) ? vap->va_gid :
	    crgetgid(cr);
	if (!(flag & IS_ROOT_NODE) && dzp != NULL &&
	    (dzp->z_mode & S_ISGID)) {
		acl_ids->z_fgid = dzp->z_gid;
		if (S_ISDIR(vap->va_mode))
			acl_ids->z_mode |= S_ISGID;
	}
	acl_ids->z_aclp = trivial_acl(acl_ids->z_mode, S_ISDIR(vap->va_mode));
	acl_ids->z_fuidp = NULL;
	return (0);
}

boolean_t
zfs_acl_ids_overquota(zfsvfs_t *zv, zfs_acl_ids_t *acl_ids, uint64_t projid)
{
	return (zfs_id_overquota(zv, DMU_USERUSED_OBJECT, acl_ids->z_fuid) ||
	    zfs_id_overquota(zv, DMU_GROUPUSED_OBJECT, acl_ids->z_fgid) ||
	    (projid != ZFS_DEFAULT_PROJID && projid != ZFS_INVALID_PROJID &&
	    zfs_id_overquota(zv, DMU_PROJECTUSED_OBJECT, projid)));
}

void
zfs_acl_data_locator(void **dataptr, uint32_t *length, uint32_t buflen,
    boolean_t start, void *userdata)
{
	zfs_acl_locator_cb_t *cb = userdata;

	(void) buflen;
	if (start) {
		cb->cb_acl_node = list_head(&cb->cb_aclp->z_acl);
	} else {
		cb->cb_acl_node = list_next(&cb->cb_aclp->z_acl,
		    cb->cb_acl_node);
	}
	ASSERT3P(cb->cb_acl_node, !=, NULL);
	*dataptr = cb->cb_acl_node->z_acldata;
	*length = cb->cb_acl_node->z_size;
}

uint64_t
zfs_mode_compute(uint64_t fmode, zfs_acl_t *aclp, uint64_t *pflags,
    uint64_t fuid, uint64_t fgid)
{
	int		entry_type;
	mode_t		mode;
	mode_t		seen = 0;
	zfs_ace_hdr_t	*acep = NULL;
	uint64_t	who;
	uint16_t	iflags, type;
	uint32_t	access_mask;
	boolean_t	an_exec_denied = B_FALSE;

	mode = (fmode & (S_IFMT | S_ISUID | S_ISGID | S_ISVTX));

	while ((acep = zfs_acl_next_ace(aclp, acep, &who,
	    &access_mask, &iflags, &type))) {
		if (!zfs_acl_valid_ace_type(type, iflags))
			continue;
		entry_type = (iflags & ACE_TYPE_FLAGS);
		if (iflags & ACE_INHERIT_ONLY_ACE)
			continue;
		if (entry_type == ACE_OWNER || (entry_type == 0 &&
		    who == fuid)) {
			if ((access_mask & ACE_READ_DATA) && !(seen & S_IRUSR)) {
				seen |= S_IRUSR;
				if (type == ALLOW)
					mode |= S_IRUSR;
			}
			if ((access_mask & ACE_WRITE_DATA) &&
			    !(seen & S_IWUSR)) {
				seen |= S_IWUSR;
				if (type == ALLOW)
					mode |= S_IWUSR;
			}
			if ((access_mask & ACE_EXECUTE) && !(seen & S_IXUSR)) {
				seen |= S_IXUSR;
				if (type == ALLOW)
					mode |= S_IXUSR;
			}
		} else if (entry_type == OWNING_GROUP ||
		    (entry_type == ACE_IDENTIFIER_GROUP && who == fgid)) {
			if ((access_mask & ACE_READ_DATA) && !(seen & S_IRGRP)) {
				seen |= S_IRGRP;
				if (type == ALLOW)
					mode |= S_IRGRP;
			}
			if ((access_mask & ACE_WRITE_DATA) &&
			    !(seen & S_IWGRP)) {
				seen |= S_IWGRP;
				if (type == ALLOW)
					mode |= S_IWGRP;
			}
			if ((access_mask & ACE_EXECUTE) && !(seen & S_IXGRP)) {
				seen |= S_IXGRP;
				if (type == ALLOW)
					mode |= S_IXGRP;
			}
		} else if (entry_type == ACE_EVERYONE) {
			if (access_mask & ACE_READ_DATA) {
				if (!(seen & S_IRUSR)) {
					seen |= S_IRUSR;
					if (type == ALLOW)
						mode |= S_IRUSR;
				}
				if (!(seen & S_IRGRP)) {
					seen |= S_IRGRP;
					if (type == ALLOW)
						mode |= S_IRGRP;
				}
				if (!(seen & S_IROTH)) {
					seen |= S_IROTH;
					if (type == ALLOW)
						mode |= S_IROTH;
				}
			}
			if (access_mask & ACE_WRITE_DATA) {
				if (!(seen & S_IWUSR)) {
					seen |= S_IWUSR;
					if (type == ALLOW)
						mode |= S_IWUSR;
				}
				if (!(seen & S_IWGRP)) {
					seen |= S_IWGRP;
					if (type == ALLOW)
						mode |= S_IWGRP;
				}
				if (!(seen & S_IWOTH)) {
					seen |= S_IWOTH;
					if (type == ALLOW)
						mode |= S_IWOTH;
				}
			}
			if (access_mask & ACE_EXECUTE) {
				if (!(seen & S_IXUSR)) {
					seen |= S_IXUSR;
					if (type == ALLOW)
						mode |= S_IXUSR;
				}
				if (!(seen & S_IXGRP)) {
					seen |= S_IXGRP;
					if (type == ALLOW)
						mode |= S_IXGRP;
				}
				if (!(seen & S_IXOTH)) {
					seen |= S_IXOTH;
					if (type == ALLOW)
						mode |= S_IXOTH;
				}
			}
		} else if ((access_mask & ACE_EXECUTE) && type == DENY) {
			an_exec_denied = B_TRUE;
		}
	}

	if (!an_exec_denied &&
	    ((seen & ALL_MODE_EXECS) != ALL_MODE_EXECS ||
	    (mode & ALL_MODE_EXECS) != ALL_MODE_EXECS))
		an_exec_denied = B_TRUE;
	if (an_exec_denied)
		*pflags &= ~ZFS_NO_EXECS_DENIED;
	else
		*pflags |= ZFS_NO_EXECS_DENIED;
	return (mode);
}

uint64_t
zfs_external_acl(znode_t *zp)
{
	zfs_acl_phys_t acl_phys;
	int error;

	if (zp->z_is_sa)
		return (0);
	if ((error = sa_lookup(zp->z_sa_hdl, SA_ZPL_ZNODE_ACL(ZTOZSB(zp)),
	    &acl_phys, sizeof (acl_phys))) == 0)
		return (acl_phys.z_acl_extern_obj);
	if (zp->z_is_sa && error == ENOENT)
		return (0);
	return (0);
}

int
zfs_znode_acl_version(znode_t *zp)
{
	zfs_acl_phys_t acl_phys;
	int error;

	if (zp->z_is_sa)
		return (ZFS_ACL_VERSION_FUID);
	if ((error = sa_lookup(zp->z_sa_hdl, SA_ZPL_ZNODE_ACL(ZTOZSB(zp)),
	    &acl_phys, sizeof (acl_phys))) == 0)
		return (acl_phys.z_acl_version);
	return (ZFS_ACL_VERSION_FUID);
}

static int
zfs_acl_version(int version)
{
	if (version < ZPL_VERSION_FUID)
		return (ZFS_ACL_VERSION_INITIAL);
	return (ZFS_ACL_VERSION_FUID);
}

static int
zfs_acl_version_zp(znode_t *zp)
{
	return (zfs_acl_version(ZTOZSB(zp)->z_version));
}

static int
zfs_acl_znode_info(znode_t *zp, int *aclsize, int *aclcount,
    zfs_acl_phys_t *aclphys)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	uint64_t acl_count;
	int size;
	int error;

	if (zp->z_is_sa) {
		if ((error = sa_size(zp->z_sa_hdl, SA_ZPL_DACL_ACES(zfsvfs),
		    &size)) != 0)
			return (error);
		*aclsize = size;
		if ((error = sa_lookup(zp->z_sa_hdl, SA_ZPL_DACL_COUNT(zfsvfs),
		    &acl_count, sizeof (acl_count))) != 0)
			return (error);
		*aclcount = (int)acl_count;
	} else {
		if ((error = sa_lookup(zp->z_sa_hdl, SA_ZPL_ZNODE_ACL(zfsvfs),
		    aclphys, sizeof (*aclphys))) != 0)
			return (error);
		if (aclphys->z_acl_version == ZFS_ACL_VERSION_INITIAL) {
			*aclsize = ZFS_ACL_SIZE(aclphys->z_acl_size);
			*aclcount = aclphys->z_acl_size;
		} else {
			*aclsize = aclphys->z_acl_size;
			*aclcount = aclphys->z_acl_count;
		}
	}
	return (0);
}

int
zfs_acl_node_read(struct znode *zp, boolean_t have_lock, zfs_acl_t **aclpp,
    boolean_t will_modify)
{
	zfs_acl_t	*aclp;
	int		aclsize = 0;
	int		acl_count = 0;
	zfs_acl_node_t	*aclnode;
	zfs_acl_phys_t	znode_acl;
	int		version;
	int		error;
	boolean_t	drop_lock = B_FALSE;

	ASSERT(MUTEX_HELD(&zp->z_acl_lock));

	if (zp->z_acl_cached && !will_modify) {
		*aclpp = zp->z_acl_cached;
		return (0);
	}

	if (!zp->z_is_sa && !have_lock) {
		mutex_enter(&zp->z_lock);
		drop_lock = B_TRUE;
	}
	version = zfs_znode_acl_version(zp);

	if ((error = zfs_acl_znode_info(zp, &aclsize,
	    &acl_count, &znode_acl)) != 0)
		goto done;

	aclp = zfs_acl_alloc(version);
	aclp->z_acl_count = acl_count;
	aclp->z_acl_bytes = aclsize;
	aclnode = zfs_acl_node_alloc(aclsize);
	aclnode->z_ace_count = aclp->z_acl_count;
	aclnode->z_size = aclsize;

	if (!zp->z_is_sa) {
		if (znode_acl.z_acl_extern_obj) {
			error = dmu_read(ZTOZSB(zp)->z_os,
			    znode_acl.z_acl_extern_obj, 0, aclnode->z_size,
			    aclnode->z_acldata, DMU_READ_PREFETCH);
		} else {
			memcpy(aclnode->z_acldata, znode_acl.z_ace_data,
			    aclnode->z_size);
		}
	} else {
		error = sa_lookup(zp->z_sa_hdl, SA_ZPL_DACL_ACES(ZTOZSB(zp)),
		    aclnode->z_acldata, aclnode->z_size);
	}

	if (error != 0) {
		zfs_acl_free(aclp);
		zfs_acl_node_free(aclnode);
		if (error == ECKSUM)
			error = SET_ERROR(EIO);
		goto done;
	}

	list_insert_head(&aclp->z_acl, aclnode);
	*aclpp = aclp;
	if (!will_modify)
		zp->z_acl_cached = aclp;
done:
	if (drop_lock)
		mutex_exit(&zp->z_lock);
	return (error);
}

int
zfs_aclset_common(znode_t *zp, zfs_acl_t *aclp, cred_t *cr, dmu_tx_t *tx)
{
	int			error;
	zfsvfs_t		*zfsvfs = ZTOZSB(zp);
	dmu_object_type_t	otype;
	zfs_acl_locator_cb_t	locate = { 0 };
	uint64_t		mode;
	sa_bulk_attr_t		bulk[6];
	uint64_t		ctime[2];
	int			count = 0;
	zfs_acl_phys_t		acl_phys;

	(void) cr;
	mode = zp->z_mode;
	mode = zfs_mode_compute(mode, aclp, &zp->z_pflags,
	    zp->z_uid, zp->z_gid);
	zp->z_mode = mode;
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MODE(zfsvfs), NULL,
	    &mode, sizeof (mode));
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
	    &zp->z_pflags, sizeof (zp->z_pflags));
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL,
	    &ctime, sizeof (ctime));

	if (zp->z_acl_cached && zp->z_acl_cached != aclp) {
		zfs_acl_free(zp->z_acl_cached);
		zp->z_acl_cached = NULL;
	}

	if (!zfsvfs->z_use_fuids)
		otype = DMU_OT_OLDACL;
	else
		otype = DMU_OT_ACL;

	if (zp->z_is_sa) {
		locate.cb_aclp = aclp;
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_DACL_ACES(zfsvfs),
		    zfs_acl_data_locator, &locate, aclp->z_acl_bytes);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_DACL_COUNT(zfsvfs),
		    NULL, &aclp->z_acl_count, sizeof (uint64_t));
	} else {
		zfs_acl_node_t *aclnode;
		uint64_t off = 0;
		uint64_t aoid;

		if ((error = sa_lookup(zp->z_sa_hdl, SA_ZPL_ZNODE_ACL(zfsvfs),
		    &acl_phys, sizeof (acl_phys))) != 0)
			return (error);
		aoid = acl_phys.z_acl_extern_obj;
		if (aclp->z_acl_bytes > ZFS_ACE_SPACE) {
			if (aoid && aclp->z_version != acl_phys.z_acl_version) {
				error = dmu_object_free(zfsvfs->z_os, aoid, tx);
				if (error)
					return (error);
				aoid = 0;
			}
			if (aoid == 0) {
				aoid = dmu_object_alloc(zfsvfs->z_os,
				    otype, aclp->z_acl_bytes,
				    otype == DMU_OT_ACL ?
				    DMU_OT_SYSACL : DMU_OT_NONE,
				    otype == DMU_OT_ACL ?
				    DN_OLD_MAX_BONUSLEN : 0, tx);
			} else {
				(void) dmu_object_set_blocksize(zfsvfs->z_os,
				    aoid, aclp->z_acl_bytes, 0, tx);
			}
			acl_phys.z_acl_extern_obj = aoid;
			for (aclnode = list_head(&aclp->z_acl); aclnode;
			    aclnode = list_next(&aclp->z_acl, aclnode)) {
				if (aclnode->z_ace_count == 0)
					continue;
				dmu_write(zfsvfs->z_os, aoid, off,
				    aclnode->z_size, aclnode->z_acldata, tx,
				    DMU_READ_NO_PREFETCH);
				off += aclnode->z_size;
			}
		} else {
			void *start = acl_phys.z_ace_data;

			if (acl_phys.z_acl_extern_obj) {
				error = dmu_object_free(zfsvfs->z_os,
				    acl_phys.z_acl_extern_obj, tx);
				if (error)
					return (error);
				acl_phys.z_acl_extern_obj = 0;
			}
			for (aclnode = list_head(&aclp->z_acl); aclnode;
			    aclnode = list_next(&aclp->z_acl, aclnode)) {
				if (aclnode->z_ace_count == 0)
					continue;
				memcpy(start, aclnode->z_acldata,
				    aclnode->z_size);
				start = (caddr_t)start + aclnode->z_size;
			}
		}
		if (aclp->z_version == ZFS_ACL_VERSION_INITIAL) {
			acl_phys.z_acl_size = aclp->z_acl_count;
			acl_phys.z_acl_count = aclp->z_acl_bytes;
		} else {
			acl_phys.z_acl_size = aclp->z_acl_bytes;
			acl_phys.z_acl_count = aclp->z_acl_count;
		}
		acl_phys.z_acl_version = aclp->z_version;
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_ZNODE_ACL(zfsvfs), NULL,
		    &acl_phys, sizeof (acl_phys));
	}

	zp->z_pflags &= ~ZFS_ACL_WIDE_FLAGS;
	zp->z_pflags |= aclp->z_hints;
	if (ace_trivial_common(aclp, 0, zfs_ace_walk) == 0)
		zp->z_pflags |= ZFS_ACL_TRIVIAL;
	zfs_tstamp_update_setup(zp, STATE_CHANGED, NULL, ctime);
	ZFS_PERSIST_SEQ(zp, bulk, count);
	return (sa_bulk_update(zp->z_sa_hdl, bulk, count, tx));
}

static void
zfs_acl_chmod(boolean_t isdir, uint64_t mode, zfs_acl_t *aclp)
{
	void		*acep = NULL;
	uint64_t	who;
	int		new_count, new_bytes;
	int		ace_size;
	int		entry_type;
	uint16_t	iflags, type;
	uint32_t	access_mask;
	zfs_acl_node_t	*newnode;
	size_t		abstract_size = aclp->z_ops->ace_abstract_size();
	void		*zacep;
	trivial_acl_t	masks;

	new_count = new_bytes = 0;
	acl_trivial_access_masks((mode_t)mode, isdir, &masks);
	newnode = zfs_acl_node_alloc((abstract_size * 6) + aclp->z_acl_bytes);
	zacep = newnode->z_acldata;
	if (masks.allow0) {
		zfs_set_ace(aclp, zacep, masks.allow0, ALLOW, -1, ACE_OWNER);
		zacep = (void *)((uintptr_t)zacep + abstract_size);
		new_count++;
		new_bytes += abstract_size;
	}
	if (masks.deny1) {
		zfs_set_ace(aclp, zacep, masks.deny1, DENY, -1, ACE_OWNER);
		zacep = (void *)((uintptr_t)zacep + abstract_size);
		new_count++;
		new_bytes += abstract_size;
	}
	if (masks.deny2) {
		zfs_set_ace(aclp, zacep, masks.deny2, DENY, -1, OWNING_GROUP);
		zacep = (void *)((uintptr_t)zacep + abstract_size);
		new_count++;
		new_bytes += abstract_size;
	}

	while ((acep = zfs_acl_next_ace(aclp, acep, &who, &access_mask,
	    &iflags, &type))) {
		entry_type = (iflags & ACE_TYPE_FLAGS);
		if (entry_type == ACE_OWNER ||
		    entry_type == OWNING_GROUP ||
		    entry_type == ACE_EVERYONE) {
			if (!isdir || !(iflags &
			    (ACE_FILE_INHERIT_ACE | ACE_DIRECTORY_INHERIT_ACE)))
				continue;
			iflags |= ACE_INHERIT_ONLY_ACE;
		}
		if (isdir && (iflags &
		    (ACE_FILE_INHERIT_ACE | ACE_DIRECTORY_INHERIT_ACE)))
			aclp->z_hints |= ZFS_INHERIT_ACE;
		ace_size = aclp->z_ops->ace_size(acep);
		memcpy(zacep, acep, ace_size);
		aclp->z_ops->ace_flags_set(zacep, iflags);
		zacep = (void *)((uintptr_t)zacep + ace_size);
		new_count++;
		new_bytes += ace_size;
	}
	zfs_set_ace(aclp, zacep, masks.owner, ALLOW, -1, ACE_OWNER);
	zacep = (void *)((uintptr_t)zacep + abstract_size);
	zfs_set_ace(aclp, zacep, masks.group, ALLOW, -1, OWNING_GROUP);
	zacep = (void *)((uintptr_t)zacep + abstract_size);
	zfs_set_ace(aclp, zacep, masks.everyone, ALLOW, -1, ACE_EVERYONE);
	new_count += 3;
	new_bytes += abstract_size * 3;
	zfs_acl_release_nodes(aclp);
	aclp->z_acl_count = new_count;
	aclp->z_acl_bytes = new_bytes;
	newnode->z_ace_count = new_count;
	newnode->z_size = new_bytes;
	list_insert_tail(&aclp->z_acl, newnode);
}

int
zfs_acl_chmod_setattr(znode_t *zp, zfs_acl_t **aclpp, uint64_t mode)
{
	int error = 0;

	mutex_enter(&zp->z_acl_lock);
	mutex_enter(&zp->z_lock);
	if (ZTOZSB(zp)->z_acl_mode == ZFS_ACL_DISCARD)
		*aclpp = zfs_acl_alloc(zfs_acl_version_zp(zp));
	else
		error = zfs_acl_node_read(zp, B_TRUE, aclpp, B_TRUE);
	if (error == 0) {
		(*aclpp)->z_hints = zp->z_pflags & V4_ACL_WIDE_FLAGS;
		zfs_acl_chmod(S_ISDIR(zp->z_mode), mode, *aclpp);
	}
	mutex_exit(&zp->z_lock);
	mutex_exit(&zp->z_acl_lock);
	return (error);
}

int
zfs_acl_chown_setattr(znode_t *zp)
{
	int error;
	zfs_acl_t *aclp;
	boolean_t took_acl = B_FALSE;

	if (ZTOZSB(zp)->z_acl_type == ZFS_ACLTYPE_POSIX)
		return (0);
	if (!MUTEX_HELD(&zp->z_acl_lock)) {
		mutex_enter(&zp->z_acl_lock);
		took_acl = B_TRUE;
	}
	error = zfs_acl_node_read(zp, MUTEX_HELD(&zp->z_lock) ? B_TRUE :
	    B_FALSE, &aclp, B_FALSE);
	if (error == 0 && aclp->z_acl_count > 0)
		zp->z_mode = zfs_mode_compute(zp->z_mode, aclp,
		    &zp->z_pflags, zp->z_uid, zp->z_gid);
	if (took_acl)
		mutex_exit(&zp->z_acl_lock);
	if (error == ENOENT)
		return (0);
	return (error);
}

int
zfs_getacl(znode_t *zp, vsecattr_t *vsecp, boolean_t lock, cred_t *cr)
{
	(void) zp;
	(void) vsecp;
	(void) lock;
	(void) cr;
	return (SET_ERROR(ENOTSUP));
}

int
zfs_setacl(znode_t *zp, vsecattr_t *vsecp, boolean_t lock, cred_t *cr)
{
	(void) zp;
	(void) vsecp;
	(void) lock;
	(void) cr;
	return (SET_ERROR(ENOTSUP));
}

void
zfs_acl_xform(znode_t *zp, zfs_acl_t *aclp, cred_t *cr)
{
	(void) zp;
	(void) aclp;
	(void) cr;
}

#define	PAC_USER_OBJ	0x01
#define	PAC_USER	0x02
#define	PAC_GROUP_OBJ	0x04
#define	PAC_GROUP	0x08
#define	PAC_MASK	0x10
#define	PAC_OTHER	0x20
#define	PAC_VERSION	2

struct pac_hdr {
	uint32_t	a_version;
};
struct pac_ent {
	uint16_t	e_tag;
	uint16_t	e_perm;
	uint32_t	e_id;
};

static boolean_t
cr_in_group(cred_t *cr, gid_t gid)
{
	int i, n;

	if (crgetgid(cr) == gid)
		return (B_TRUE);
	n = crgetngroups(cr);
	for (i = 0; i < n; i++) {
		if (crgetgroups(cr)[i] == gid)
			return (B_TRUE);
	}
	return (B_FALSE);
}

int
zfsd_posix_acl_equiv_mode(const void *val, size_t sz, mode_t *modep)
{
	const struct pac_hdr *hdr = val;
	const struct pac_ent *ent;
	int nent, i;
	int has_user_obj = 0, has_group_obj = 0, has_other = 0, has_mask = 0;
	int named = 0;
	int state = PAC_USER_OBJ;
	uint16_t tag, perm, mask = 0, group_obj = 0;
	mode_t mode = 0;

	if (val == NULL || sz < sizeof (*hdr) ||
	    (sz - sizeof (*hdr)) % sizeof (*ent) != 0)
		return (SET_ERROR(EINVAL));
	if (LE_32(hdr->a_version) != PAC_VERSION)
		return (SET_ERROR(EINVAL));
	nent = (int)((sz - sizeof (*hdr)) / sizeof (*ent));
	ent = (const struct pac_ent *)(hdr + 1);
	for (i = 0; i < nent; i++) {
		int j;

		tag = LE_16(ent[i].e_tag);
		perm = LE_16(ent[i].e_perm);
		if (perm & ~7)
			return (SET_ERROR(EINVAL));
		perm &= 7;
		switch (tag) {
		case PAC_USER_OBJ:
			if (state != PAC_USER_OBJ || has_user_obj)
				return (SET_ERROR(EINVAL));
			state = PAC_USER;
			has_user_obj = 1;
			mode |= (mode_t)perm << 6;
			break;
		case PAC_OTHER:
			if ((state != PAC_OTHER && state != PAC_GROUP) ||
			    has_other)
				return (SET_ERROR(EINVAL));
			state = 0;
			has_other = 1;
			mode |= (mode_t)perm;
			break;
		case PAC_MASK:
			if (state != PAC_GROUP || has_mask)
				return (SET_ERROR(EINVAL));
			state = PAC_OTHER;
			has_mask = 1;
			mask = perm;
			break;
		case PAC_GROUP_OBJ:
			if (state != PAC_USER || has_group_obj)
				return (SET_ERROR(EINVAL));
			state = PAC_GROUP;
			has_group_obj = 1;
			group_obj = perm;
			break;
		case PAC_USER:
			if (state != PAC_USER)
				return (SET_ERROR(EINVAL));
			named = 1;
			for (j = 0; j < i; j++) {
				if (LE_16(ent[j].e_tag) == tag &&
				    LE_32(ent[j].e_id) == LE_32(ent[i].e_id))
					return (SET_ERROR(EINVAL));
			}
			break;
		case PAC_GROUP:
			if (state != PAC_GROUP)
				return (SET_ERROR(EINVAL));
			named = 1;
			for (j = 0; j < i; j++) {
				if (LE_16(ent[j].e_tag) == tag &&
				    LE_32(ent[j].e_id) == LE_32(ent[i].e_id))
					return (SET_ERROR(EINVAL));
			}
			break;
		default:
			return (SET_ERROR(EINVAL));
		}
	}
	if (!has_user_obj || !has_group_obj || !has_other || state != 0)
		return (SET_ERROR(EINVAL));
	if (named && !has_mask)
		return (SET_ERROR(EINVAL));
	if (has_mask)
		mode |= (mode_t)mask << 3;
	else
		mode |= (mode_t)group_obj << 3;
	*modep = (*modep & ~((mode_t)0777)) | (mode & 0777);
	return (0);
}

int
zfsd_posix_acl_has_named(const void *val, size_t sz)
{
	const struct pac_hdr *hdr = val;
	const struct pac_ent *ent;
	int nent, i;

	if (val == NULL || sz < sizeof (*hdr) ||
	    (sz - sizeof (*hdr)) % sizeof (*ent) != 0)
		return (0);
	nent = (int)((sz - sizeof (*hdr)) / sizeof (*ent));
	ent = (const struct pac_ent *)(hdr + 1);
	for (i = 0; i < nent; i++) {
		uint16_t tag = LE_16(ent[i].e_tag);

		if (tag == PAC_USER || tag == PAC_GROUP)
			return (1);
	}
	return (0);
}

static uint16_t
pac_mask_required(const struct pac_ent *ent, int nent, int *has_mask)
{
	int i;

	*has_mask = 0;
	for (i = 0; i < nent; i++) {
		if (LE_16(ent[i].e_tag) == PAC_MASK) {
			*has_mask = 1;
			return (LE_16(ent[i].e_perm) & 7);
		}
	}
	return (7);
}

static int
posix_acl_perm(const void *val, size_t sz, uid_t fuid, gid_t fgid,
    cred_t *cr, int want)
{
	const struct pac_hdr *hdr = val;
	const struct pac_ent *ent;
	int nent, i, found_group = 0;
	uint16_t tag, perm, mask, group_union = 0;
	uint32_t id;
	uid_t uid;
	mode_t dummy = 0;
	int has_mask = 0;

	if (zfsd_posix_acl_equiv_mode(val, sz, &dummy) != 0)
		return (SET_ERROR(EIO));
	nent = (int)((sz - sizeof (*hdr)) / sizeof (*ent));
	ent = (const struct pac_ent *)(hdr + 1);
	uid = crgetuid(cr);
	mask = pac_mask_required(ent, nent, &has_mask);
	(void) has_mask;
	want &= 7;

	for (i = 0; i < nent; i++) {
		tag = LE_16(ent[i].e_tag);
		perm = LE_16(ent[i].e_perm) & 7;
		id = LE_32(ent[i].e_id);
		switch (tag) {
		case PAC_USER_OBJ:
			if (uid == fuid)
				return (((perm & want) == want) ? 0 :
				    SET_ERROR(EACCES));
			break;
		case PAC_USER:
			if (uid == (uid_t)id)
				return ((((perm & mask) & want) == want) ? 0 :
				    SET_ERROR(EACCES));
			break;
		case PAC_GROUP_OBJ:
			if (cr_in_group(cr, fgid)) {
				found_group = 1;
				group_union |= (perm & mask);
			}
			break;
		case PAC_GROUP:
			if (cr_in_group(cr, (gid_t)id)) {
				found_group = 1;
				group_union |= (perm & mask);
			}
			break;
		default:
			break;
		}
	}
	if (found_group)
		return (((group_union & want) == want) ? 0 :
		    SET_ERROR(EACCES));
	for (i = 0; i < nent; i++) {
		if (LE_16(ent[i].e_tag) == PAC_OTHER) {
			perm = LE_16(ent[i].e_perm) & 7;
			return (((perm & want) == want) ? 0 :
			    SET_ERROR(EACCES));
		}
	}
	return (SET_ERROR(EIO));
}

int
zfsd_posix_acl_access(znode_t *zp, cred_t *cr, int need)
{
	void *buf = NULL;
	size_t alen = 0;
	int n, err;

	if (need == 0)
		return (0);
	if (ZTOZSB(zp)->z_acl_type != ZFS_ACLTYPE_POSIX)
		return (ENOENT);
	n = zfsd_xattr_dup(zp, "system.posix_acl_access", &buf, &alen);
	if (n == -ENODATA || n == -ENOENT || n == 0)
		return (ENOENT);
	if (n < 0)
		return (-n);
	err = posix_acl_perm(buf, (size_t)n, (uid_t)zp->z_uid,
	    (gid_t)zp->z_gid, cr, need);
	kmem_free(buf, alen);
	return (err);
}

static int
unix_ok(mode_t mode, uid_t uid, gid_t gid, cred_t *cr, int need)
{
	mode_t bits;
	uid_t ruid;
	gid_t rgid;
	int i, n;

	if (need == 0)
		return (0);
	ruid = crgetuid(cr);
	rgid = crgetgid(cr);
	if (ruid == uid)
		bits = (mode >> 6) & 7;
	else if (rgid == gid)
		bits = (mode >> 3) & 7;
	else {
		bits = mode & 7;
		n = crgetngroups(cr);
		for (i = 0; i < n; i++) {
			if (crgetgroups(cr)[i] == gid) {
				bits = (mode >> 3) & 7;
				break;
			}
		}
	}
	if (ruid == 0) {
		if ((need & 1) && ((mode & 0111) == 0))
			return (SET_ERROR(EACCES));
		return (0);
	}
	if ((need & 4) && !(bits & 4))
		return (SET_ERROR(EACCES));
	if ((need & 2) && !(bits & 2))
		return (SET_ERROR(EACCES));
	if ((need & 1) && !(bits & 1))
		return (SET_ERROR(EACCES));
	return (0);
}

static uint32_t
zfs_unix_to_v4(uint32_t access_mask)
{
	uint32_t new_mask = 0;

	if (access_mask & S_IXOTH)
		new_mask |= ACE_EXECUTE;
	if (access_mask & S_IWOTH)
		new_mask |= ACE_WRITE_DATA;
	if (access_mask & S_IROTH)
		new_mask |= ACE_READ_DATA;
	return (new_mask);
}

static int
zfs_v4_to_unix(uint32_t access_mask, int *unmapped)
{
	int new_mask = 0;

	*unmapped = access_mask &
	    (ACE_WRITE_OWNER | ACE_WRITE_ACL | ACE_DELETE);
	if (access_mask & WRITE_MASK)
		new_mask |= S_IWOTH;
	if (access_mask & ACE_READ_DATA)
		new_mask |= S_IROTH;
	if (access_mask & ACE_EXECUTE)
		new_mask |= S_IXOTH;
	return (new_mask);
}

static int
zfs_zaccess_dataset_check(znode_t *zp, uint32_t v4_mode)
{
	if ((v4_mode & WRITE_MASK) && zfs_is_readonly(ZTOZSB(zp)) &&
	    (!Z_ISDEV(zp->z_mode) || (v4_mode & WRITE_MASK_ATTRS)))
		return (SET_ERROR(EROFS));
	if ((v4_mode & WRITE_MASK_DATA) && (zp->z_pflags & ZFS_IMMUTABLE))
		return (SET_ERROR(EPERM));
	if ((v4_mode & (ACE_DELETE | ACE_DELETE_CHILD)) &&
	    (zp->z_pflags & ZFS_NOUNLINK))
		return (SET_ERROR(EPERM));
	if ((v4_mode & (ACE_READ_DATA | ACE_EXECUTE)) &&
	    (zp->z_pflags & ZFS_AV_QUARANTINED))
		return (SET_ERROR(EACCES));
	return (0);
}

static int
zfs_zaccess_aces_check(znode_t *zp, uint32_t *working_mode,
    boolean_t anyaccess, cred_t *cr)
{
	zfsvfs_t	*zfsvfs = ZTOZSB(zp);
	zfs_acl_t	*aclp;
	int		error;
	uid_t		uid = crgetuid(cr);
	uint64_t	who;
	uint16_t	type, iflags;
	uint16_t	entry_type;
	uint32_t	access_mask;
	uint32_t	deny_mask = 0;
	zfs_ace_hdr_t	*acep = NULL;
	boolean_t	checkit;
	uid_t		gowner;
	uid_t		fowner;

	zfs_fuid_map_ids(zp, cr, &fowner, &gowner);
	mutex_enter(&zp->z_acl_lock);
	error = zfs_acl_node_read(zp, B_FALSE, &aclp, B_FALSE);
	if (error != 0) {
		mutex_exit(&zp->z_acl_lock);
		return (error);
	}

	while ((acep = zfs_acl_next_ace(aclp, acep, &who, &access_mask,
	    &iflags, &type))) {
		uint32_t mask_matched;

		if (!zfs_acl_valid_ace_type(type, iflags))
			continue;
		if (S_ISDIR(zp->z_mode) && (iflags & ACE_INHERIT_ONLY_ACE))
			continue;
		mask_matched = (access_mask & *working_mode);
		if (!mask_matched)
			continue;
		entry_type = (iflags & ACE_TYPE_FLAGS);
		checkit = B_FALSE;
		switch (entry_type) {
		case ACE_OWNER:
			if (uid == fowner)
				checkit = B_TRUE;
			break;
		case OWNING_GROUP:
			who = gowner;
			zfs_fallthrough;
		case ACE_IDENTIFIER_GROUP:
			checkit = zfs_groupmember(zfsvfs, who, cr);
			break;
		case ACE_EVERYONE:
			checkit = B_TRUE;
			break;
		default:
			if (entry_type == 0) {
				uid_t newid;

				newid = zfs_fuid_map_id(zfsvfs, who, cr,
				    ZFS_ACE_USER);
				if (newid != IDMAP_WK_CREATOR_OWNER_UID &&
				    uid == newid)
					checkit = B_TRUE;
				break;
			}
			mutex_exit(&zp->z_acl_lock);
			return (SET_ERROR(EIO));
		}
		if (checkit) {
			if (type == DENY)
				deny_mask |= mask_matched;
			else if (anyaccess) {
				mutex_exit(&zp->z_acl_lock);
				return (0);
			}
			*working_mode &= ~mask_matched;
		}
		if (*working_mode == 0)
			break;
	}
	mutex_exit(&zp->z_acl_lock);
	if (deny_mask) {
		*working_mode |= deny_mask;
		return (SET_ERROR(EACCES));
	} else if (*working_mode) {
		return (-1);
	}
	return (0);
}

static int
zfs_zaccess_trivial(znode_t *zp, uint32_t *working_mode, cred_t *cr)
{
	int err, mask;
	int unmapped = 0;

	mask = zfs_v4_to_unix(*working_mode, &unmapped);
	if (mask == 0 || unmapped) {
		*working_mode = unmapped;
		return (unmapped ? SET_ERROR(EPERM) : 0);
	}
	err = zfsd_posix_acl_access(zp, cr, mask);
	if (err != ENOENT) {
		if (err == 0)
			*working_mode = unmapped;
		return (err);
	}
	err = unix_ok(zp->z_mode, zp->z_uid, zp->z_gid, cr, mask);
	if (err != 0)
		return (SET_ERROR(EPERM));
	*working_mode = unmapped;
	return (0);
}

static int
zfs_zaccess_common(znode_t *zp, uint32_t v4_mode, uint32_t *working_mode,
    boolean_t *check_privs, boolean_t skipaclchk, cred_t *cr)
{
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	int err;

	*working_mode = v4_mode;
	*check_privs = B_TRUE;
	if (v4_mode == 0 || zfsvfs->z_replay) {
		*working_mode = 0;
		return (0);
	}
	if ((err = zfs_zaccess_dataset_check(zp, v4_mode)) != 0) {
		*check_privs = B_FALSE;
		return (err);
	}
	if (skipaclchk) {
		*working_mode = 0;
		return (0);
	}
	if ((v4_mode & WRITE_MASK_DATA) &&
	    !S_ISDIR(zp->z_mode) &&
	    (zp->z_pflags & ZFS_READONLY))
		return (SET_ERROR(EPERM));
	if (zp->z_pflags & ZFS_ACL_TRIVIAL)
		return (zfs_zaccess_trivial(zp, working_mode, cr));
	return (zfs_zaccess_aces_check(zp, working_mode, B_FALSE, cr));
}

static int
zfs_zaccess_append(znode_t *zp, uint32_t *working_mode, boolean_t *check_privs,
    cred_t *cr)
{
	if (*working_mode != ACE_WRITE_DATA)
		return (SET_ERROR(EACCES));
	return (zfs_zaccess_common(zp, ACE_APPEND_DATA, working_mode,
	    check_privs, B_FALSE, cr));
}

int
zfs_zaccess_idmap(znode_t *zp, int mode, int flags, boolean_t skipaclchk,
    cred_t *cr, zidmap_t *idmap)
{
	uint32_t	working_mode;
	int		error;
	int		is_attr;
	boolean_t	check_privs;
	znode_t		*xzp = NULL;
	znode_t		*check_zp = zp;
	mode_t		needed_bits;
	uid_t		owner;

	(void) idmap;
	is_attr = ((zp->z_pflags & ZFS_XATTR) && S_ISDIR(zp->z_mode));
	if (is_attr) {
		if ((error = zfs_zget(ZTOZSB(zp),
		    zp->z_xattr_parent, &xzp)) != 0)
			return (error);
		check_zp = xzp;
		if (mode & (ACE_WRITE_DATA | ACE_APPEND_DATA)) {
			mode &= ~(ACE_WRITE_DATA | ACE_APPEND_DATA);
			mode |= ACE_WRITE_NAMED_ATTRS;
		}
		if (mode & (ACE_READ_DATA | ACE_EXECUTE)) {
			mode &= ~(ACE_READ_DATA | ACE_EXECUTE);
			mode |= ACE_READ_NAMED_ATTRS;
		}
	}

	owner = zfs_fuid_map_id(ZTOZSB(zp), zp->z_uid, cr, ZFS_OWNER);
	needed_bits = 0;
	working_mode = mode;
	if ((working_mode & (ACE_READ_ACL | ACE_READ_ATTRIBUTES)) &&
	    owner == crgetuid(cr))
		working_mode &= ~(ACE_READ_ACL | ACE_READ_ATTRIBUTES);
	if (working_mode & (ACE_READ_DATA | ACE_READ_NAMED_ATTRS |
	    ACE_READ_ACL | ACE_READ_ATTRIBUTES | ACE_SYNCHRONIZE))
		needed_bits |= S_IRUSR;
	if (working_mode & (ACE_WRITE_DATA | ACE_WRITE_NAMED_ATTRS |
	    ACE_APPEND_DATA | ACE_WRITE_ATTRIBUTES | ACE_SYNCHRONIZE))
		needed_bits |= S_IWUSR;
	if (working_mode & ACE_EXECUTE)
		needed_bits |= S_IXUSR;

	if ((error = zfs_zaccess_common(check_zp, mode, &working_mode,
	    &check_privs, skipaclchk, cr)) == 0) {
		if (is_attr)
			zrele(xzp);
		return (secpolicy_vnode_access2(cr, NULL, owner,
		    needed_bits, needed_bits));
	}
	if (error && !check_privs) {
		if (is_attr)
			zrele(xzp);
		return (error);
	}
	if (error && (flags & V_APPEND))
		error = zfs_zaccess_append(zp, &working_mode, &check_privs, cr);
	if (error && check_privs) {
		mode_t checkmode = 0;

		if ((working_mode & (ACE_READ_ACL | ACE_READ_ATTRIBUTES)) &&
		    owner == crgetuid(cr))
			working_mode &= ~(ACE_READ_ACL | ACE_READ_ATTRIBUTES);
		if (working_mode & (ACE_READ_DATA | ACE_READ_NAMED_ATTRS |
		    ACE_READ_ACL | ACE_READ_ATTRIBUTES | ACE_SYNCHRONIZE))
			checkmode |= S_IRUSR;
		if (working_mode & (ACE_WRITE_DATA | ACE_WRITE_NAMED_ATTRS |
		    ACE_APPEND_DATA | ACE_WRITE_ATTRIBUTES | ACE_SYNCHRONIZE))
			checkmode |= S_IWUSR;
		if (working_mode & ACE_EXECUTE)
			checkmode |= S_IXUSR;
		error = secpolicy_vnode_access2(cr, NULL, owner,
		    needed_bits & ~checkmode, needed_bits);
		if (error == 0 && (working_mode & ACE_WRITE_OWNER))
			error = secpolicy_vnode_chown(cr, owner);
		if (error == 0 && (working_mode & ACE_WRITE_ACL))
			error = secpolicy_vnode_setdac(cr, owner);
		if (error == 0 && (working_mode &
		    (ACE_DELETE | ACE_DELETE_CHILD)))
			error = secpolicy_vnode_remove(cr);
		if (error == 0 && (working_mode & ACE_SYNCHRONIZE))
			error = secpolicy_vnode_chown(cr, owner);
		if (error == 0 && (working_mode & ~(ZFS_CHECKED_MASKS)))
			error = SET_ERROR(EACCES);
	} else if (error == 0) {
		error = secpolicy_vnode_access2(cr, NULL, owner,
		    needed_bits, needed_bits);
	}
	if (is_attr)
		zrele(xzp);
	return (error);
}

int
zfs_zaccess(znode_t *zp, int acc, int flags, boolean_t skipaclchk, cred_t *cr)
{
	return (zfs_zaccess_idmap(zp, acc, flags, skipaclchk, cr,
	    zfs_init_idmap));
}

int
zfs_zaccess_rwx(znode_t *zp, mode_t mode, int flags, cred_t *cr)
{
	return (zfs_zaccess_idmap(zp, zfs_unix_to_v4(mode >> 6), flags,
	    B_FALSE, cr, zfs_init_idmap));
}

int
zfs_zaccess_rwx_idmap(znode_t *zp, mode_t mode, int flags, cred_t *cr,
    zidmap_t *idmap)
{
	return (zfs_zaccess_idmap(zp, zfs_unix_to_v4(mode >> 6), flags,
	    B_FALSE, cr, idmap));
}

int
zfs_zaccess_delete(znode_t *dzp, znode_t *zp, cred_t *cr, zidmap_t *idmap)
{
	uint32_t wanted_dirperms;
	uint32_t dzp_working_mode = 0;
	uint32_t zp_working_mode = 0;
	int dzp_error, zp_error;
	boolean_t dzpcheck_privs;
	boolean_t zpcheck_privs;

	(void) idmap;
	if (zp->z_pflags & (ZFS_IMMUTABLE | ZFS_NOUNLINK))
		return (SET_ERROR(EPERM));
	zp_error = zfs_zaccess_common(zp, ACE_DELETE, &zp_working_mode,
	    &zpcheck_privs, B_FALSE, cr);
	if (zp_error == EACCES) {
		if (!zpcheck_privs)
			return (SET_ERROR(zp_error));
		return (secpolicy_vnode_remove(cr));
	}
	if (zp_error == 0)
		return (0);

	wanted_dirperms = ACE_DELETE_CHILD;
	if (zfs_write_implies_delete_child)
		wanted_dirperms |= ACE_WRITE_DATA;
	dzp_error = zfs_zaccess_common(dzp, wanted_dirperms,
	    &dzp_working_mode, &dzpcheck_privs, B_FALSE, cr);
	if (dzp_error == EACCES) {
		if (!dzpcheck_privs)
			return (SET_ERROR(dzp_error));
		return (secpolicy_vnode_remove(cr));
	}
	if (dzp_working_mode != wanted_dirperms)
		dzp_error = 0;
	if (dzp_error != 0 && dzpcheck_privs) {
		uid_t owner;

		owner = zfs_fuid_map_id(ZTOZSB(dzp), dzp->z_uid, cr, ZFS_OWNER);
		dzp_error = secpolicy_vnode_access2(cr, NULL,
		    owner, S_IXUSR, S_IWUSR | S_IXUSR);
	}
	if (dzp_error != 0)
		return (SET_ERROR(EACCES));
	if ((dzp->z_mode & S_ISVTX) == 0)
		return (0);
	return (zfs_sticky_remove_access(dzp, zp, cr));
}

int
zfs_zaccess_rename(znode_t *sdzp, znode_t *szp, znode_t *tdzp,
    znode_t *tzp, cred_t *cr, zidmap_t *idmap)
{
	int add_perm;
	int error;

	if (szp->z_pflags & ZFS_AV_QUARANTINED)
		return (SET_ERROR(EACCES));
	add_perm = S_ISDIR(szp->z_mode) ?
	    ACE_ADD_SUBDIRECTORY : ACE_ADD_FILE;
	if ((error = zfs_zaccess_delete(sdzp, szp, cr, idmap)))
		return (error);
	if (tzp) {
		if ((error = zfs_zaccess_delete(tdzp, tzp, cr, idmap)))
			return (error);
	}
	return (zfs_zaccess_idmap(tdzp, add_perm, 0, B_FALSE, cr, idmap));
}

int
zfs_fastaccesschk_execute(znode_t *zp, cred_t *cr)
{
	if (zp->z_pflags & ZFS_AV_QUARANTINED)
		return (SET_ERROR(EACCES));
	return (zfs_zaccess(zp, ACE_EXECUTE, 0, B_FALSE, cr));
}

int
zfs_zaccess_unix(void *ip, int mode, cred_t *cr)
{
	return (zfs_zaccess_rwx((znode_t *)ip, mode, 0, cr));
}

int
zfs_vsec_2_aclp(zfsvfs_t *zfsvfs, umode_t mode, vsecattr_t *vsecp,
    cred_t *cr, zfs_fuid_info_t **fuidpp, zfs_acl_t **aclpp)
{
	(void) zfsvfs;
	(void) mode;
	(void) vsecp;
	(void) cr;
	(void) fuidpp;
	(void) aclpp;
	return (SET_ERROR(ENOTSUP));
}

void
zfs_fuid_map_ids(znode_t *zp, cred_t *cr, uid_t *uidp, uid_t *gidp)
{
	(void) cr;
	*uidp = (uid_t)zp->z_uid;
	*gidp = (uid_t)zp->z_gid;
}

uid_t
zfs_fuid_map_id(zfsvfs_t *zfsvfs, uint64_t fuid, cred_t *cr,
    zfs_fuid_type_t type)
{
	(void) zfsvfs;
	(void) cr;
	(void) type;
	return ((uid_t)fuid);
}

void
zfs_fuid_destroy(zfsvfs_t *zfsvfs)
{
	if (zfsvfs == NULL || !zfsvfs->z_fuid_loaded)
		return;
	zfs_fuid_table_destroy(&zfsvfs->z_fuid_idx, &zfsvfs->z_fuid_domain);
	zfsvfs->z_fuid_loaded = B_FALSE;
}

void
zfs_fuid_sync(zfsvfs_t *zfsvfs, dmu_tx_t *tx)
{
	(void) zfsvfs;
	(void) tx;
}

void
zfs_fuid_txhold(zfsvfs_t *zfsvfs, dmu_tx_t *tx)
{
	(void) zfsvfs;
	(void) tx;
}

zfs_fuid_info_t *
zfs_fuid_info_alloc(void)
{
	zfs_fuid_info_t *fuidp;

	fuidp = kmem_zalloc(sizeof (zfs_fuid_info_t), KM_SLEEP);
	list_create(&fuidp->z_fuids, sizeof (zfs_fuid_t),
	    offsetof(zfs_fuid_t, z_next));
	list_create(&fuidp->z_domains, sizeof (zfs_fuid_domain_t),
	    offsetof(zfs_fuid_domain_t, z_next));
	return (fuidp);
}

void
zfs_fuid_info_free(zfs_fuid_info_t *fuidp)
{
	zfs_fuid_t *fuid;
	zfs_fuid_domain_t *dom;

	if (fuidp == NULL)
		return;
	while ((fuid = list_head(&fuidp->z_fuids)) != NULL) {
		list_remove(&fuidp->z_fuids, fuid);
		kmem_free(fuid, sizeof (zfs_fuid_t));
	}
	while ((dom = list_head(&fuidp->z_domains)) != NULL) {
		list_remove(&fuidp->z_domains, dom);
		kmem_free(dom, sizeof (zfs_fuid_domain_t));
	}
	list_destroy(&fuidp->z_fuids);
	list_destroy(&fuidp->z_domains);
	if (fuidp->z_domain_table != NULL)
		kmem_free(fuidp->z_domain_table,
		    fuidp->z_domain_cnt * sizeof (char *));
	kmem_free(fuidp, sizeof (zfs_fuid_info_t));
}

const char *
zfs_fuid_find_by_idx(zfsvfs_t *zfsvfs, uint32_t idx)
{
	(void) zfsvfs;
	(void) idx;
	return (NULL);
}

uint64_t
zfs_fuid_create(zfsvfs_t *zfsvfs, uint64_t id, cred_t *cr, zfs_fuid_type_t type,
    zfs_fuid_info_t **fuidpp)
{
	(void) zfsvfs;
	(void) cr;
	(void) type;
	(void) fuidpp;
	return (id);
}

uint64_t
zfs_fuid_create_cred(zfsvfs_t *zfsvfs, zfs_fuid_type_t type, cred_t *cr,
    zfs_fuid_info_t **fuidpp)
{
	(void) zfsvfs;
	(void) fuidpp;
	if (type == ZFS_GROUP)
		return (crgetgid(cr));
	return (crgetuid(cr));
}

void
zfs_fuid_node_add(zfs_fuid_info_t **fuidpp, const char *domain, uint32_t rid,
    uint64_t idx, uint64_t id, zfs_fuid_type_t type)
{
	(void) fuidpp;
	(void) domain;
	(void) rid;
	(void) idx;
	(void) id;
	(void) type;
}

boolean_t
zfs_groupmember(zfsvfs_t *zfsvfs, uint64_t id, cred_t *cr)
{
	(void) zfsvfs;
	return (groupmember((gid_t)id, cr) ? B_TRUE : B_FALSE);
}

int
zfs_id_to_fuidstr(zfsvfs_t *zfsvfs, const char *domain, uid_t rid,
    char *buf, size_t len, boolean_t addok)
{
	(void) zfsvfs;
	(void) domain;
	(void) addok;
	(void) snprintf(buf, len, "%llx", (longlong_t)rid);
	return (0);
}
