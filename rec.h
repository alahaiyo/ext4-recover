#ifndef __REC_H__
#define __REC_H__

#ifndef __le32  
#define __le32 int
#endif
#ifndef __le16 
#define __le16 short
#endif
#ifndef u8 
#define u8 unsigned char
#endif
#ifndef u16 
#define u16 unsigned short
#endif
#ifndef __u8 
#define __u8 unsigned char
#endif
#ifndef __u16 
#define __u16 unsigned short
#endif

#define EXT4_NAME_LEN 255

struct ext4_dir_entry_2 {
	__le32	inode;			/* Inode number */
	__le16	rec_len;		/* Directory entry length */
	__u8	name_len;		/* Name length */
	__u8	file_type;
	char	name[EXT4_NAME_LEN];	/* File name */
};

struct ext4_extent {
	__le32	ee_block;	/* first logical block extent covers */
	__le16	ee_len;		/* number of blocks covered by extent */
	__le16	ee_start_hi;	/* high 16 bits of physical block */
	__le32	ee_start_lo;	/* low 32 bits of physical block */
};
 
/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
struct ext4_extent_idx {
	__le32	ei_block;	/* index covers logical blocks from 'block' */
	__le32	ei_leaf_lo;	/* pointer to the physical block of the next *
				 * level. leaf or next index could be there */
	__le16	ei_leaf_hi;	/* high 16 bits of physical block */
	__u16	ei_unused;
};
 
/*
 * Each block (leaves and indexes), even inode-stored has header.
 */
struct ext4_extent_header {
	__le16	eh_magic;	/* probably will support different formats */
	__le16	eh_entries;	/* number of valid entries */
	__le16	eh_max;		/* capacity of store in entries */
	__le16	eh_depth;	/* has tree real underlying blocks? */
	__le32	eh_generation;	/* generation of the tree */
};

struct dentry_node {
	struct dentry_node *father;
	struct dentry_node *next;
	struct dentry_node *son;
	int inode_n;
	int i_data[15];
};

struct reco_dentry_node {
	__le32 inode;
	struct reco_dentry_node *next;
	char name[64];
};

struct reco_file {
	int fd;
	int file_len;
};

struct ext4_reco_info {
	int dev_fd;
	int block_size;
	int inode_size;
	int inodes_per_group;
	int blocks_per_group;

	struct reco_dentry_node *reco_dentry_head;//待恢复inode表
	int reco_idex; //表填充序号
	struct reco_file *current_reco_file;//当前正在恢复的文件信息

	struct dentry_node *root_dentry;
	struct dentry_node *current_dentry;

	char *reco_path;//恢复文件的存放路径
};
#endif