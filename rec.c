/*
*  ext4 file revocer
*  daikunhai@163.com
*  2018/3/21
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "rec.h"




#define L2B(buf,offset) buf[offset] + (buf[offset + 1] << 8) \
			+ (buf[offset + 2] << 16) + (buf[offset + 3] << 24)

#define GROUP_DESC_SIZE  64
#define GROUP_DESC_OFFSET 4096 
#define ROOT_INODE_NUMBER 2
#define SUPER_BLOCK_OFFSET 1024
#define I_BLOCK_OFFSET 40

#define MAX_RECO_FILES 100

struct dentry_node* alloc_node(struct ext4_reco_info *ext4_info)
{
	struct dentry_node* node = NULL;

	node = (struct dentry_node*)malloc(sizeof(struct dentry_node));
	if(node == NULL) {
		perror("malloc node");
		return NULL;
	}

	node->father = NULL;
	node->next = NULL;
	node->son = NULL;
	node->inode_n = 0;
	memset(node->i_data, 0, 15);

	return node;
}

void free_node(struct dentry_node* node)
{
	free(node);
}

int read_block(struct ext4_reco_info *ext4_info, unsigned long  block_n, char *buf)
{
	int ret = 0;

	if(buf == NULL)
		return -1;

	if(ext4_info->dev_fd > 0) {
		ret = pread(ext4_info->dev_fd, buf, 4096, block_n * 4096);
		if(ret != 4096) {
			printf("read block failed\n");
			return -1;
		}
	} else
		return -1;
}

/*
* 读取inode内容，注意inode号减一，因为没有0号inode
*/
int read_inode(struct ext4_reco_info *ext4_info, int inode, char *buf)
{
	int ret;
	int group_n;
	int inode_offset;
	int gb_inode_table_lo;
	char desc_buf[GROUP_DESC_SIZE];


	group_n = (inode - 1) / ext4_info->inodes_per_group;

	ret = pread(ext4_info->dev_fd, desc_buf, GROUP_DESC_SIZE, GROUP_DESC_OFFSET + group_n * GROUP_DESC_SIZE);
	if(ret != GROUP_DESC_SIZE) {
		printf("read group desc failed!\n");
		goto out1;
	}

	gb_inode_table_lo = L2B(desc_buf, 8);
	inode_offset = gb_inode_table_lo * ext4_info->block_size + (inode - 1) * ext4_info->inode_size;

	//读取 inode
	ret = pread(ext4_info->dev_fd, buf, ext4_info->inode_size, inode_offset);
	if(ret != ext4_info->inode_size) {
		printf("read inode failed!\n");
		goto out1;
	}

	return 0;

out1:
	return -1;
}

int add_to_tail(struct dentry_node *head, struct dentry_node *node)
{
	struct dentry_node *head_node;

	if(head == NULL || node == NULL) {
		printf("node add to list failed!\n");
		return -1;
	}

	head_node = head;

	for( ;head_node->next; ) {
		head_node = head_node->next;
	}
	head_node->next = node;

	return 0;

}

int read_cur_dentry_inode(struct ext4_reco_info *ext4_info)
{
	int ret = 0;
	char inode_buf[256];
	int inode = ext4_info->current_dentry->inode_n;
	
	ret = read_inode(ext4_info, inode, inode_buf);
	if(ret < 0)
		return -1;
	
	memcpy(ext4_info->current_dentry->i_data, inode_buf + 40, 60);

	return 0;
}

int get_reco_node(struct ext4_reco_info *ext4_info, struct ext4_dir_entry_2 *dentry)
{
	struct reco_dentry_node *node;
	struct reco_dentry_node *t_node;

	node = (struct reco_dentry_node *)malloc(sizeof(struct reco_dentry_node));
	if(node == NULL)
		return -1;

	memset(node, 0, sizeof(struct reco_dentry_node));
	node->inode = dentry->inode;
	strncpy(node->name, dentry->name, dentry->name_len);

	if(!ext4_info->reco_dentry_head) {
		ext4_info->reco_dentry_head = node;
	} else {
		t_node = ext4_info->reco_dentry_head;
		while(t_node->next) {
			t_node = t_node->next;
		};
		t_node->next = node;
	}
	node->next = NULL;

	return 0;
}

void put_reco_node(struct reco_dentry_node *node)
{
	free(node);
}

/*
* 判断一个目录项是否包含删除的目录项
*/
int check_this_dentry(struct ext4_reco_info *ext4_info, struct ext4_dir_entry_2 *dentry)
{
	int ret = 0;
	struct ext4_dir_entry_2 *reco_dentry;

	/*
	*	如何判断一个目录项是否被删除？删除目录项的时候是把目录项合入上一个目录项中。
	*	也就是说上一个目录项的rec_len会变长，dentry结构再磁盘上是要4字节对齐的。
	*   所以dentry->rec_len - dentry->name_len 不大于11就是正常的，否则，一定包含删除的目录项
	 */
	if(dentry->rec_len - dentry->name_len <= 11) { 
		return 0;
	}	
	if(dentry->name_len % 4)
		reco_dentry = (struct ext4_dir_entry_2 *) ((char *)dentry + \
			             dentry->name_len + 8 + (4 - dentry->name_len % 4));
	else
		reco_dentry = (struct ext4_dir_entry_2 *) ((char *)dentry + dentry->name_len + 8);

	//排除一个块中最后一个inode，以及目录文件
	if(reco_dentry->inode == 0 || reco_dentry->file_type == 2) {
		return 0;
	}
	
	if(ext4_info->reco_idex < MAX_RECO_FILES) {
		ret = get_reco_node(ext4_info, reco_dentry);
		if(ret < 0)
			return -1;
		
		ext4_info->reco_idex ++;
	} else {
		printf("Too many recover file..\n");
		return -1;
	}

	return 0;
}

int do_check_block_entry(struct ext4_reco_info *ext4_info, char *buf)
{
	int len = 0;
	struct ext4_dir_entry_2 *dentry;
	struct dentry_node *d_node;
	char d_file_name[40] = {0};

	dentry = (struct ext4_dir_entry_2 *)buf;

	do {	
		//不存在inode号为0.所以这里作为判断是否读完所有目录项
		if(dentry->inode == 0)
			break;

		if(dentry->inode == 11) //lost+found
			goto next;

		//跳过 .和..
		if(dentry->name_len == 1 && dentry->file_type == 2 && dentry->name[0] == '.') {
			goto next;
		}

		//判断是否是目录，目录要加入目录树中
		if(dentry->file_type == 2) {
			if(dentry->name_len == 2 && dentry->name[0] == '.' && dentry->name[1] == '.') {
				; //..目录的情况，不计入目录树，但是要判断是否有临近删除的目录项！
			} else {
				d_node = alloc_node(ext4_info);
				if(!d_node) {
					return -1;
				}
				d_node->inode_n = dentry->inode;

				if(ext4_info->current_dentry->son == NULL) {
					ext4_info->current_dentry->son = d_node;
				} else
					add_to_tail(ext4_info->current_dentry->son, d_node);

				d_node->father = ext4_info->current_dentry;
			}
		}
		check_this_dentry(ext4_info, dentry);

next:		
		len += dentry->rec_len;
		dentry = (struct ext4_dir_entry_2 *)((char *)dentry + dentry->rec_len);				
	} while(len < 4096);

	return 0;
}

int check_block_entry(struct ext4_reco_info *ext4_info, int block)
{
	int ret = 0;
	char *buf;

	buf = (char *)malloc(4096);
	if(buf == NULL) {
		printf("malloc failed!\n");
		return -1;
	}

	ret = read_block(ext4_info, block, buf);
	if(ret < 0)
		goto out;

	ret = do_check_block_entry(ext4_info, buf);
	if(ret < 0)
		goto out;
out:
	free(buf);

	return ret;

}

int extents_search_leaf(struct ext4_reco_info *ext4_info, char *buf, int count, \
								int (*func)(struct ext4_reco_info *, int))
{
	int ret = 0;
	int i = 0;
	int j = 0;
	struct ext4_extent *extents;

while(i < 36) {
	printf("%x ", buf[i]);
	i++;
}
i = 0;
	extents = (struct ext4_extent *)buf;
	do {
		for(j = 0; j < extents[i].ee_len; j++) {
			func(ext4_info, extents[i].ee_start_lo + j);
		}
		i++;
		
	} while( i < count);

	return ret;
}

int extents_search_idx(struct ext4_reco_info *ext4_info, struct ext4_extent_idx *idx)
{
	int ret;
	char *buf = NULL;
	struct ext4_extent_header *ex_header;
	int i = 0;

	buf = (char *)malloc(4096);
	if(buf == NULL) {
		printf("malloc failed!\n");
		return -1;
	}

	ret = read_block(ext4_info, idx->ei_leaf_lo, buf);
	if(ret < 0)
		goto out;

	ex_header = (struct ext4_extent_header *)buf;
	
	if(ex_header->eh_depth == 0) { 
		extents_search_leaf(ext4_info, buf + sizeof(struct ext4_extent_header), ex_header->eh_entries, check_block_entry);
	} else {
		for(i = 0; i < ex_header->eh_entries; i++) {
			idx = (struct ext4_extent_idx *)(buf + (i + 1) * 3);//指向data的偏移，获取ext4_extent_idx
			ret = extents_search_idx(ext4_info, idx);
			if(ret < 0)
				goto out;
		}
	}

out:
	free(buf);

}

/*
* 解析目录项inode ，历遍目录中所有项
* 
 */
int search_dir_entry(struct ext4_reco_info *ext4_info)
{
	int ret = 0;
	struct ext4_extent_header *ex_header;
	struct ext4_extent_idx *idx = NULL;
	int i = 0;
	int j = 0;

	ex_header = (struct ext4_extent_header *)ext4_info->current_dentry->i_data;

	if(ex_header->eh_depth == 0) { //叶子节点
		extents_search_leaf(ext4_info, (char *)ext4_info->current_dentry->i_data + sizeof(struct ext4_extent_header), \
			                  ex_header->eh_entries, check_block_entry);	
	} else {
		//非叶子节点  
		for(i = 0; i < ex_header->eh_entries; i++) {
			idx = (struct ext4_extent_idx *)(ext4_info->current_dentry->i_data + (i + 1) * 3);//指向data的偏移，获取ext4_extent_idx
			ret = extents_search_idx(ext4_info, idx);
			if(ret < 0)
				break;
		}
	}

	return ret;
}


int dump_node(struct ext4_reco_info *ext4_info)
{
	struct dentry_node *head_node;
	printf("Current inode %d\n", ext4_info->current_dentry->inode_n);

	if(!ext4_info->current_dentry->son)
		return 0;
	head_node = ext4_info->current_dentry->son;
	
	for( ;head_node->next; ) {
		printf("next inode %d\n", head_node->inode_n);
		head_node = head_node->next;
	}
	printf("next inode %d\n", head_node->inode_n);

	return 0;
}

int test_bitmap(int offset, char *bitmap)
{
	unsigned char byte_offset = 0;

	byte_offset = offset / 8;
	offset = offset % 8;
	return bitmap[byte_offset] & (1 << offset);
}

int get_block_bitmap(struct ext4_reco_info *ext4_info, int block, char *buf)
{
	int ret = 0;
	int group_n;
	int block_bitmap_lo;

	group_n = block / ext4_info->blocks_per_group;

	ret = pread(ext4_info->dev_fd, buf, GROUP_DESC_SIZE, GROUP_DESC_OFFSET + group_n * GROUP_DESC_SIZE);
	if(ret != GROUP_DESC_SIZE) {
		printf("read group desc failed!\n");
		return -1;
		
	}
	block_bitmap_lo = L2B(buf, 0);

	ret = pread(ext4_info->dev_fd, buf, 4096, block_bitmap_lo * ext4_info->block_size);
	if(ret != 4096) {
		return -1;
	}

	return 0;
}

int check_block_bitmap(struct ext4_reco_info *ext4_info, int block)
{
	int ret = 0;
	char read_buf[4096];

	ret = get_block_bitmap(ext4_info, block, read_buf);
	if(ret < 0)
		return -1;
	
	block %= ext4_info->blocks_per_group;
	
	return test_bitmap(block, read_buf);	
}

int get_inode_bitmap(struct ext4_reco_info *ext4_info, int inode, char *buf)
{
	int ret;
	int group_n;
	int inode_bitmap_lo;
	char desc_buf[GROUP_DESC_SIZE];
	
	group_n = inode / ext4_info->inodes_per_group;
	
	ret = pread(ext4_info->dev_fd, desc_buf, GROUP_DESC_SIZE, GROUP_DESC_OFFSET + group_n * GROUP_DESC_SIZE);
	if(ret != GROUP_DESC_SIZE) {
		perror("read group desc");
		return -1;
	}
	inode_bitmap_lo = L2B(desc_buf, 4);

	ret = pread(ext4_info->dev_fd, buf, 4096, inode_bitmap_lo * ext4_info->block_size);
	if(ret != 4096) {
		return -1;
	}

	return 0;
}

recover_block_for_file(struct ext4_reco_info *ext4_info, int block)
{
	int fd;
	int w_len;
	int ret;
	int filesize;
	char *buf = NULL;

	fd = ext4_info->current_reco_file->fd;
	if(fd < 0)
		return -1;

	filesize = ext4_info->current_reco_file->file_len;
	if(filesize <= 0)
		return -1;

	ret = check_block_bitmap(ext4_info, block);
	if(!ret) {
		printf("This block is invlid!\n");
		return -1;
	}

	buf = (char *)malloc(4096);
	if(buf == NULL) {
		printf("malloc failed!\n");
		return -1;
	}
	
	ret = read_block(ext4_info, block, buf);
	if(ret < 0)
		goto out;

	if(filesize < 4096) 
		w_len = filesize;	
	else 
		w_len = 4096;

	ret = write(fd, buf, w_len);//如果数据块有数据，则恢复数据。存在数据块被其他使用又被释放的可能，此时是错误数据
	if(ret != w_len) 
		perror("write file");
	
	ext4_info->current_reco_file->file_len -= w_len;

out:
	free(buf);
	return ret;
}

int recover_from_extents(struct ext4_reco_info *ext4_info)
{
	int ret;
	char inode_buf[256];
	char reco_file[64];
	int filesize = 0;
	int len = 0;
	int w_len;
	int *i_data;
	struct ext4_extent_header *ex_header = NULL;
	struct ext4_extent_idx *idx = NULL;
	struct reco_file recofile;
	int fd = -1;
	int i = 0;

	sprintf(reco_file, "%s/%s", ext4_info->reco_path, ext4_info->reco_dentry_head->name);
	printf("recover file: %s\n", reco_file);
	fd = open(reco_file, O_RDWR | O_CREAT);
	if(fd < 0) {
		perror("creat recover file");
		return -1;
	}

	ret = read_inode(ext4_info, ext4_info->reco_dentry_head->inode, inode_buf);
	if(ret < 0)
		return -1;

	i_data = (int *)(inode_buf + 40);
	ex_header = (struct ext4_extent_header *)i_data;
	filesize = L2B(inode_buf, 4); //目前仅支持32位长度文件（byte），也就是4GB以内

	recofile.fd = fd;
	recofile.file_len = filesize;
	ext4_info->current_reco_file = &recofile;
	printf("recover file size: %d\n", filesize);

	if(ex_header->eh_depth == 0) { //叶子节点
		extents_search_leaf(ext4_info, (char *)i_data + sizeof(struct ext4_extent_header), \
			                  ex_header->eh_entries, recover_block_for_file);	
	} else {
		//非叶子节点  
		for(i = 0; i < ex_header->eh_entries; i++) {
			idx = (struct ext4_extent_idx *)(i_data + (i + 1) * 3);//指向data的偏移，获取ext4_extent_idx
			ret = extents_search_idx(ext4_info, idx);
			if(ret < 0)
				goto out;
		}
	}

out:
	close(fd);
	
	return 0;
}

int do_recover(struct ext4_reco_info *ext4_info)
{
	int i = 0;
	int ret;
	int inode_num;
	struct reco_dentry_node *tnode;
	char read_buf[4096];
	int inode_bitmap_offset;

	do {
		inode_num = ext4_info->reco_dentry_head->inode;
		ret = get_inode_bitmap(ext4_info, inode_num, read_buf);
		if(ret < 0) {
			printf("get inode bitmap failed\n");
			return -1;
		}
		//注意：没有0号inode，所以位置上是1号inode在偏移0的位置
		inode_bitmap_offset = (inode_num - 1) % ext4_info->inodes_per_group;

	//查询inode位图，是否已经被重新使用
		ret = test_bitmap(inode_bitmap_offset, read_buf);
		if(!ret) {
			recover_from_extents(ext4_info);
		}

		tnode = ext4_info->reco_dentry_head->next;
		put_reco_node(ext4_info->reco_dentry_head);
		ext4_info->reco_dentry_head = tnode; //恢复下一个文件
		i++;

	} while(i < ext4_info->reco_idex);

	return 0;
}

int init_root_dentry(struct ext4_reco_info *ext4_info)
{
	int ret;
	char inode_buf[256];
	
	ext4_info->root_dentry = alloc_node(ext4_info);
	if(!ext4_info->root_dentry ) {
		printf("alloc root node failed!\n");
		return -1;
	}
	ext4_info->current_dentry = ext4_info->root_dentry;
	
	ret = read_inode(ext4_info, ROOT_INODE_NUMBER, inode_buf);
	if(ret < 0)
		return -1;
	memcpy(ext4_info->current_dentry->i_data, inode_buf + 40, 60);
	
	ext4_info->current_dentry->inode_n = ROOT_INODE_NUMBER;
	
	return 0;
}

/*
*	向上级目录返回，找到一个可以继续往下搜索的目录项
*	找到则返回0，否则返回负数
*/
int go_up(struct ext4_reco_info  *ext4_info)
{
	struct dentry_node *t_node;
	while(ext4_info->current_dentry->father != ext4_info->root_dentry) {
		t_node = ext4_info->current_dentry;
		if(ext4_info->current_dentry->father->next) {	
			ext4_info->current_dentry = ext4_info->current_dentry->father->next;
			free_node(t_node);
			return 0;
		} else {
			ext4_info->current_dentry = ext4_info->current_dentry->father;
			free_node(t_node);
		}
	}

	return -1;
}
int main(int argc, char **argv)
{
	int ret = 0;
	char *buf = NULL;
	struct ext4_reco_info  *ext4_info = NULL;
	struct dentry_node *temp_node;
	char file_path[128];
	char recover_path[128];
	struct reco_dentry_node *tnode;
	int i;

	if(argc < 2){
		printf("Select the device you want to recover.\n");
		exit(0);
	} else
		sprintf(file_path, "%s", argv[1]);

	if(argv[2])
		sprintf(recover_path, "%s", argv[2]);
	else {
		printf("set a path to store recover file.\n");
		exit(0);
	}

	ext4_info = (struct ext4_reco_info*)malloc(sizeof(struct ext4_reco_info));
	if(NULL == ext4_info) {
		printf("malloc ext4_info failed!\n");
		return 0;
	}
	memset(ext4_info, 0, sizeof(struct ext4_reco_info));

//设置恢复的文件存放路径
	ext4_info->reco_path = recover_path;

//打开目标设备节点
	ext4_info->dev_fd = open(file_path, O_RDONLY);
	if(ext4_info->dev_fd < 0) {
		perror("Open device");
		free(ext4_info);
		exit(0);
	}


	buf = (char *)malloc(4096);
	if(buf == NULL) {
		printf("malloc failed!\n");
		goto out;
	}


//读超级块
	ret =  pread(ext4_info->dev_fd, buf, 4096, SUPER_BLOCK_OFFSET);
	if(ret != 4096) {
		printf("read superblock failed!\n");
		goto out1;
	}
	
	ext4_info->block_size = 4096;//L2B(buf, 24);
	ext4_info->inode_size = L2B(buf, 88);
	ext4_info->inodes_per_group = L2B(buf, 40);
	ext4_info->blocks_per_group = L2B(buf, 32);

	if(!ext4_info->block_size || !ext4_info->inode_size \
		                 || !ext4_info->inodes_per_group) {
		printf("super block is not corect!\n");
		goto out1;
	}

	ret = init_root_dentry(ext4_info);
	if(ret < 0)
		goto out1;


//开始查找删除文件，首先解析根目录下的目录项
	do {
		ret = search_dir_entry(ext4_info);
		if(ret < 0)
			break;
	//	dump_node(ext4_info);

		if(ext4_info->current_dentry->son) { //向下搜索子目录
			ext4_info->current_dentry = ext4_info->current_dentry->son;
		} else if(ext4_info->current_dentry->next) { //没有子目录则搜索下一个同级目录
			temp_node = ext4_info->current_dentry;
			ext4_info->current_dentry = ext4_info->current_dentry->next;
			free_node(temp_node);
		} else if (ext4_info->current_dentry->father == ext4_info->root_dentry) { //没有同级目录，返回父目录
			break; //父目录为根目录，搜索结束
		} else { //本目录历遍结束，回上级目录，将其子目录设置为NULL,释放该子目录
			ret = go_up(ext4_info);	
			if(ret < 0) //如果向上没有找到节点，则搜索结束
				break;	
		}
		//读current_dentry的inode内容
		read_cur_dentry_inode(ext4_info);

	} while(1);// 1 => 0

	printf("%d files to recover\n", ext4_info->reco_idex);
	if(ext4_info->reco_idex) {
		tnode = ext4_info->reco_dentry_head;
		for(i = 0; i < ext4_info->reco_idex; i++) {
			printf("   %s\n", tnode->name);
			if(!tnode->next)
				break;
			tnode = tnode->next;
		}
	} else {
		goto out1;
	}

//开始恢复文件
	do_recover(ext4_info);
	
out1:
	free(buf);

out:
	close(ext4_info->dev_fd);
	free(ext4_info);

	return 0;	
}

