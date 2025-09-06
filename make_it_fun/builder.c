#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <math.h>

//=============================================

#define root_inode_index 1
#define i32 uint32_t
#define i64 uint64_t
#define i8 uint8_t


#define is_a_file 0100000u
#define is_a_directory 0040000u
#define defaultMagic 0x4D565346u
#define makerow dirent64_t

#define ull unsigned long long
#define uc unsigned char
#define ll long long

//=============================================

#pragma pack(push, 1)
typedef struct
{
    i32 magic;
    i32 version;
    i32 block_size;
    i64 total_blocks;
    i64 inode_count;
    i64 inode_bitmap_start;
    i64 inode_bitmap_blocks;
    i64 data_bitmap_start;
    i64 data_bitmap_blocks;
    i64 inode_table_start;
    i64 inode_table_blocks;
    i64 data_region_start;
    i64 data_region_blocks;
    i64 root_inode;
    i64 mtime_epoch;
    i32 flags;
    i32 checksum;
} superblock_t;

#pragma pack(pop)

//=============================================

#pragma pack(push, 1)
typedef struct
{
    uint16_t mode;
    uint16_t links;
    i32 uid;
    i32 gid;
    i64 size_bytes;
    i64 atime;
    i64 mtime;
    i64 ctime;
    i32 direct[12];
    i32 reserved_0;
    i32 reserved_1;
    i32 reserved_2;
    i32 proj_id;
    i32 uid16_gid16;
    i64 xattr_ptr;
    i64 inode_crc;
} inode_t;
#pragma pack(pop)
_Static_assert(sizeof(inode_t) == 128, "inode size mismatch");

//=============================================

#pragma pack(push, 1)
typedef struct
{
    i32 inode_no;
    i8 type;
    char name[58];
    i8 checksum;
} dirent64_t;
#pragma pack(pop)
_Static_assert(sizeof(dirent64_t) == 64, "dirent size mismatch");

//=============================================

i32 CRC32_TAB[256];
void crc32_init()
{
    for (i32 i = 0; i < 256; ++i)
    {
        i32 c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        CRC32_TAB[i] = c;
    }
}

//=============================================

i32 crc32_bytes( void *user_input, size_t n)
{
     i8 *p = ( i8 *)user_input;
    i32 c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i)
        c = CRC32_TAB[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

//=============================================

i32 superblock_crc_finalize(superblock_t *superBlock)
{
    superBlock->checksum = 0;
    i32 s = crc32_bytes((void *)superBlock, 4096 - 4);
    superBlock->checksum = s;
    return s;
}

//=============================================

void inode_crc_finalize(inode_t *ino)
{
    i8 tmp[128];
    memcpy(tmp, ino, 128);
    memset(&tmp[120], 0, 8);
    i32 c = crc32_bytes(tmp, 120);
    ino->inode_crc = (i64)c;
}

//=============================================

void dirent_checksum_finalize(dirent64_t *de)
{
     i8 *p = ( i8 *)de;
    i8 x = 0;
    for (int i = 0; i < 63; ++i)
        x ^= p[i];
    de->checksum = x;
}

//=============================================

int bit_getter( i8 *bm, size_t idx)
{
    size_t byte_index = idx / 8;
    size_t bit_index = idx % 8;
    i8 mask = (i8)pow(2, bit_index);
    return (bm[byte_index] & mask) ? 1 : 0;
}
  void bit_setter(i8 *bm, size_t idx)
{
    size_t byte_index = idx / 8;
    size_t bit_index = idx % 8;
    i8 mask = (i8)pow(2, bit_index);
    bm[byte_index] = bm[byte_index] | mask;
}

//=============================================

i64 myCeil(i64 a, i64 b){  return (i64)ceil((double)a / (double)b);   }

//=============================================

typedef struct
{
     char *image;
    i64 size_kib;
    i64 inodes;
} user_input;

//=============================================

void inputStructure( char *programName)
{
    printf("Usage: %s --image out.disk --size-kib <180..4096,multiple of 4> --inodes <128..512>\n", programName);
}

//=============================================

int splitter(int argc, char *argv[], user_input *data)
{
    data->image = NULL;
    data->size_kib = 0;
    data->inodes = 0;

    for (int i=1;i< argc;++i){
        char*mystring = argv[i];
        if (strcmp(mystring,"--image")== 0)
                data->image = argv[++i];

        else if (strcmp(argv[i], "--size-kib") == 0)
                data->size_kib = strtoull(argv[++i], NULL, 10);

        else if (strcmp(argv[i], "--inodes") == 0)
                data->inodes = strtoull(argv[++i], NULL, 10);

        else{ printf("You Have an Error! Please: \n"); inputStructure(argv[0]);
            return -1;
        }
    }
    if (data->size_kib < 180 || data->size_kib > 4096 || (data->size_kib % 4) != 0){
        printf("Error: Follow <size> range (180 and 4096) inclusive! and must be divisible by 4\n");
        return -1;
    }

    if (data->inodes < 128 || data->inodes > 512){
        printf("Error: Follow <inodes> range (128 and 512)\n");
        return -1;
    }
    return 5;
}

//=============================================

void error_message(char *msg)
{
    printf("Error happened: %s\n", msg);
    exit(1);
}

//---------------------------------------------------------
//---------------------------------------------------------
//---------------------------------------------------------
//---------------------------------------------------------


int main(int argc, char *argv[])
{
    crc32_init();

    user_input input_commands;
    if (splitter(argc, argv, &input_commands) != 5){
        error_message("Splitter failed!");
    }

//................................................

    i64 number_blocks_total = (input_commands.size_kib * 1024) / 4096;
    i64 inodetable_block_count = myCeil(input_commands.inodes * 128, 4096);
    i64 superBlockIndex = 0;
    i64 ibm_block = 1;
    i64 user_inputBlockIndex = 2;
    i64 inode_table_index = 3;
    i64 user_input_table_index = inode_table_index + inodetable_block_count;

//................................................

    if (user_input_table_index >= number_blocks_total) error_message("Not enough space!");

//................................................
    i64 user_input_blocks = number_blocks_total - user_input_table_index;
    i64 disk_total_size = number_blocks_total * 4096;
    i8 *disk = (i8 *) calloc (1, disk_total_size);

//................................................

    if (disk==NULL)  error_message("Failed to create the disk image!");

//................................................

    superblock_t *superBlock = (superblock_t *)(disk + superBlockIndex * 4096);
    memset(superBlock, 0, sizeof(*superBlock));

//................................................

    superBlock->magic = defaultMagic;
    superBlock->version = 1;
    superBlock->block_size = 4096;
    superBlock->total_blocks = number_blocks_total;
    superBlock->inode_count = input_commands.inodes;
    superBlock->inode_bitmap_start = ibm_block;
    superBlock->inode_bitmap_blocks = 1;
    superBlock->data_bitmap_start = user_inputBlockIndex;
    superBlock->data_bitmap_blocks = 1;
    superBlock->inode_table_start = inode_table_index;
    superBlock->inode_table_blocks = inodetable_block_count;
    superBlock->data_region_start = user_input_table_index;
    superBlock->data_region_blocks = user_input_blocks;
    superBlock->root_inode = root_inode_index;
    superBlock->mtime_epoch = (i64)time(NULL);
    superBlock->flags = 0;

//................................................

    i8 *inode_bitmap_base_address = disk + ibm_block * 4096;
    i8 *user_input_bitmap_base_address = disk + user_inputBlockIndex * 4096;

//................................................

    bit_setter(inode_bitmap_base_address, 0);
    bit_setter(user_input_bitmap_base_address, 0);

//................................................

    i64 inode_table_len = inodetable_block_count * 4096;
    inode_t *itab = (inode_t *)(disk + inode_table_index * 4096);
    memset(itab, 0, inode_table_len);

//................................................

    inode_t *add_root = &itab[0];
    memset(add_root, 0, sizeof(*add_root));

//................................................

    for (int i = 0; i < 12; ++i)  add_root->direct[i] = 0;
    add_root->direct[0] = (i32)user_input_table_index;
    add_root->mode = (uint16_t)is_a_directory;
    add_root->links = 2;
    add_root->uid = 0;
    add_root->gid = 0;
    add_root->atime = add_root->mtime = add_root->ctime = superBlock->mtime_epoch;
    add_root->size_bytes = 0;
    add_root->proj_id = 0;
    add_root->xattr_ptr = 0;
    add_root->uid16_gid16 = 0;

//................................................

    i64 root_user_input_block_offset= add_root->direct[0] * 4096;
    i8 *roots_user_input_block = disk + root_user_input_block_offset;
    memset(roots_user_input_block, 0, 4096);

//................................................

    makerow row;
    memset(&row, 0, sizeof(row));
    row.inode_no = root_inode_index;
    row.type = 2;
    memset(row.name, 0, sizeof(row.name));
    row.name[0] = '.';
    dirent_checksum_finalize(&row);

//................................................

    i8* dest = roots_user_input_block + 0 * sizeof(makerow);
    memcpy(dest, &row, sizeof(row));
    memset(&row, 0, sizeof(row));

//................................................

    row.inode_no = root_inode_index;
    row.type = 2;
    memset(row.name, 0, sizeof(row.name));
    row.name[0] = '.';
    row.name[1] = '.';
    dirent_checksum_finalize(&row);

//................................................

    dest = roots_user_input_block + 1 * sizeof(makerow);
    memcpy(dest, &row, sizeof(row));
    memset(&row, 0, sizeof(row));

//................................................

    add_root->size_bytes = 2 * sizeof(makerow);
    inode_crc_finalize(add_root);
    superblock_crc_finalize(superBlock);

//---------------------------------------------------------

    FILE *pointerf = fopen(input_commands.image, "wb");
    if (pointerf==NULL){
        printf("Failed to open the disk image in [binary+write] mode");  free(disk);
        exit(1);
    }

//................................................

    int counter = (int)fwrite(disk, 1, disk_total_size, pointerf);
    if (counter != (int)disk_total_size)
    {
        printf("Failed to completely write in the file! Counter mismatched!\n");
        fclose(pointerf);
        free(disk);
        exit(1);
    }

//................................................

    fclose(pointerf);
    free(disk);

//................................................

    printf("Formation of the disk image is complete: NAME: %s, --> (%llu KiB, %llu blocks, %llu inodes).\n", input_commands.image,(ull)input_commands.size_kib, (ull)number_blocks_total, (ull)input_commands.inodes);


    return 0;
}
