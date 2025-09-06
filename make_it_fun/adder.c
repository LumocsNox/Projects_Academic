#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <math.h>
#include<stdbool.h>

//=============================================

#define ROOT_INO 1u
#define is_a_file 0100000u
#define is_a_directory 0040000u
#define defaultMagic 0x4D565346u


#define ull unsigned long long
#define uc unsigned char
#define i32 uint32_t
#define i64 uint64_t
#define i8 uint8_t


#define makerow dirent64_t

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

_Static_assert(sizeof(superblock_t) == (12 + 96 + 8), "Superblock should stay inside one block!");

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

_Static_assert(sizeof(inode_t) == 128, "inode size is different");

//=============================================

#pragma pack(push, 1)
typedef struct
{
    char *in;
    char *out;
    char *file;

} userInput;
#pragma pack(pop)
_Static_assert(sizeof(userInput) == 24, "inode size is different");

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

_Static_assert(sizeof(dirent64_t) == (58 + (int)(32 / 8) + 1 + 1), "dirent size mismatch");

//=============================================

i32 CRC32_TAB[256];
void crc32_init(void)
{
    for (i32 i = 0; i < 256; ++i){
        i32 c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        CRC32_TAB[i] = c;
    }
}

//=============================================

i32 crc32_bytes(void *data, int n)
{
    i8 *p = (i8 *)data;
    i32 c = 0xFFFFFFFFu;
    for (int i = 0; i < n; ++i)
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
    memset(&tmp[128 - 8], 0, 8);
    i32 c = crc32_bytes(tmp, 128 - 8);
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

int bitmap_getter( i8 *bm, int r)
{
    int byteLocation = r / 8;
    int bitLocation = r % 8;

    i8 mask = (i8)pow(2, bitLocation);

    return (bm[byteLocation] & mask) ? 1 : 0;
}

//=============================================

void bitmap_setter(i8 *bm, int r)
{
    int byteLocation = r / 8;
    int bitLocation = r % 8;

    i8 mask = (i8)pow(2, bitLocation);

    bm[byteLocation] = bm[byteLocation] | mask;
}

//=============================================


long getFileSize(FILE *x){
    long temp = 0; int ch;
    while ((ch = fgetc(x)) != EOF) temp++;
    if (ch!= EOF) return -1;
    return temp;
}

//=============================================

void inputStructure(char *progname){ printf("maintain: %s --input <file> --output <file> --file <name>\n", progname); }

//=============================================

int splitter(int argc, char **argv, userInput *data)
{

    data->in = NULL;
    data->out = NULL;
    data->file = NULL;

    for (int i = 1; i < argc; ++i){
        if (strcmp(argv[i], "--input") == 0)
            data->in = argv[++i];

        else if (strcmp(argv[i], "--output") == 0)
            data->out = argv[++i];

        else if (strcmp(argv[i], "--file") == 0)
            data->file = argv[++i]; // Store file name

        else{
            inputStructure(argv[0]);
            return -1;
        }
    }
    return 5;
}

//=============================================

int fetchFileName( char *path, char out[59]){
    int lineLength = strlen(path);
    int source = 0;

    for (int i = 0; i < lineLength; ++i){
        if (path[i] == '/')  source = i + 1;
    }

    int name_len = lineLength - source;
    if (name_len > 58)  name_len = 58;

    memset(out, 0, 59);
    for (int i = 0; i < name_len; ++i) out[i] = path[source + i];

    return name_len;
}

//=============================================

void error_message(char *text){
    printf("ERROR: %s\n", text);
    exit(1);
}

//=============================================

int main(int argc, char **argv)
{
    crc32_init();

    userInput data;
    if (splitter(argc, argv, &data) != 5)    error_message("Splitter failed!");

//................................................

    FILE *pointerf = fopen(data.in, "rb");
    if (pointerf==NULL) error_message("Failed openning the input file");

//................................................

    long sz =getFileSize(pointerf);

    if (sz <= 0){
        fclose(pointerf);
        error_message("Size value is negative!");
    }

//................................................

    rewind(pointerf);

//................................................

    i8 *disk = (i8 *)malloc((int)sz);
    if (!disk){
        fclose(pointerf);
        error_message("Failed to open the disk!");
    }

//................................................

    long cnt = 0;
    int ch=-1;
    while((ch= fgetc(pointerf))!= EOF){
        if(cnt>sz) break;
        disk[cnt++] = (i8)ch;
    }

//................................................

    if (cnt != sz){
        fclose(pointerf); free(disk);
        error_message("Failed to read the disk properly, fred the disk!");
    }

//................................................

    fclose(pointerf);

//................................................

    if ((sz % 4096) != 0){
        free(disk);
        error_message("Please enter a size which is a multiple of block size<4096>");
    }

//................................................

    superblock_t* superBlock = (superblock_t* )disk;

    if (superBlock->magic!= defaultMagic || superBlock->block_size!= 4096){
        free(disk);
        error_message("CheckSUM didn't match OR Block size should be reconsidered!");
    }

//................................................

    i64 total_block_count = superBlock->total_blocks;
    i64 inode_table_block_count = superBlock->inode_table_blocks;
    i64 inodebitmap_offset =superBlock->inode_bitmap_start * 4096;


    i8 *inode_bitmap_base_address= disk + inodebitmap_offset ;
    i64 databitmap_offset =superBlock->data_bitmap_start * 4096;
    i8 *data_bitmap_base_address= disk + databitmap_offset;


//................................................

    int inode_ofs = (int)superBlock->inode_table_start * 4096;
    void* inode_table_base_address = disk + inode_ofs;
    inode_t *inode_table = (inode_t *)inode_table_base_address;

//................................................

    FILE *fpointer = fopen(data.file, "rb");
    if (!fpointer){
        free(disk);
        error_message("Error opening file");
    }

//................................................

    int len = getFileSize(fpointer);
    if (len== -1){
        fclose(fpointer);
        free(disk);
        error_message("Program failed to read the file in binary mode!");
    }

//................................................

    if (len < 0){
        fclose(fpointer);
        free(disk);
        error_message("ftell failed");
    }

//................................................

    rewind(fpointer);

//................................................

    if (len == 0){
        fclose(fpointer);
        free(disk);
        error_message("Error: The file is empty!");
    }

    printf("The program has successfully read the file! \nFile '%s' \nSize = %lld \nBytes\n", data.file, (ull)len);

//................................................

    i64 new_unset_bit = 0;
    for (int i = 0; i < superBlock->inode_count; ++i){
        if (bitmap_getter(inode_bitmap_base_address, i)==0){
            new_unset_bit = (i64)i; break;
        }
    }

//................................................


    if (new_unset_bit == 0 && bitmap_getter(inode_bitmap_base_address, 0) == 1){
        bool unset = false;
        for (i64 i = 1; i < (i64)superBlock->inode_count; ++i)
            if (bitmap_getter(inode_bitmap_base_address, i)==0){
                new_unset_bit = (i64)i;
                unset = true;
                break;
            }


        if (!unset){
            free(disk);
            error_message("You are out of inode bits in your inode bitmap, every other bit is already set!");
        }
    }

//................................................

    i32 new_ino_no = (i32)(new_unset_bit + 1); // I am maintaining one based index here! But for the actual inode_bit position, I will use and apply the new_unset_bit variable here!
    bitmap_setter(inode_bitmap_base_address, new_unset_bit);
    inode_t *inode_base_address = & inode_table[new_unset_bit];

//................................................

    i64 needed_datablock_count = (len+ 4096- 1)/4096;
    FILE *reader = fopen(data.file, "rb");
    if (reader == NULL){
        printf("Added program failed to open the file named: %s\n", data.file); free(disk);  exit(1);
    }

//................................................

    if (needed_datablock_count > 12){
    fclose(reader); free(disk);
    printf("Fiile too large! You need more than 12 directs!\n");   exit(1);
}

//................................................

    i32 fdirect[12]; //direct pointers of datablocks for the file to be added
    for(int i=0; i< 12;++i) fdirect[i]=(i32)0;

//................................................

    i64 blocks_used = 0;
    int temp= needed_datablock_count;

    for (int current = 0; current <(int)superBlock->data_region_blocks && blocks_used < 12 && temp > 0; current++){

        if (bitmap_getter(data_bitmap_base_address, current)==0){
            bitmap_setter(data_bitmap_base_address, current);
            fdirect[blocks_used++] = (i32)(superBlock->data_region_start + current);
            temp--;
        }
    }

//................................................

    i64 remaining = len;
    i8 buffer[4096];

//................................................

    for (i64 i = 0; i < blocks_used; ++i){
        i64 iteration_unit;
        memset(buffer, 0, sizeof buffer);

        if (remaining > 4096) iteration_unit = (i64)4096;
        else iteration_unit = remaining;

        int jump=1;

        i64 readCount =(i64)fread(buffer, jump, iteration_unit, reader);

        if (readCount != iteration_unit){
            fclose(reader);  free(disk); error_message("Data reading failed! -line 468");
        }

        i64 data_block_base_address = (i64)(fdirect[i] * 4096);

        for (i64 j = 0; j < iteration_unit; ++j)
            disk[data_block_base_address + j] = buffer[j]; // move: 1 byte

        for (i64 j = iteration_unit; j < 4096; ++j)
            disk[data_block_base_address + j] = (i8)0;

        remaining -= iteration_unit;
    }

    fclose(reader);

//................................................

    memset(inode_base_address, 0, sizeof(*inode_base_address));

//................................................

    inode_base_address->mode = is_a_file;
    inode_base_address->links = 1;
    inode_base_address->uid = 0;
    inode_base_address->gid = 0;
    inode_base_address->size_bytes = len;
    i64 current_time = time(NULL);
    inode_base_address->atime = current_time;
    inode_base_address->mtime = current_time;
    inode_base_address->ctime = current_time;

//................................................

    for(int i = 0;i<12;++i) inode_base_address->direct[i] = fdirect[i];

//................................................

    inode_base_address->proj_id = 0;
    inode_base_address->uid16_gid16 = 0;
    inode_base_address->xattr_ptr = 0;

//................................................

    inode_crc_finalize(inode_base_address);

//................................................

    inode_t *rootInode = &inode_table[(int)(superBlock->root_inode - 1)];
    i32 root_dataBlock_index = rootInode->direct[0];

    if (root_dataBlock_index == 0){
    free(disk);  error_message("Root directory has no data block assigned");
}

//................................................

i8 *root_dataBlock = (i8*)(disk + (root_dataBlock_index * 4096));

int n_elems = sizeof(makerow);
int max_row = 4096 / n_elems;

//................................................

int nRows = 0;
if (rootInode->size_bytes % n_elems == 0)  nRows = (rootInode->size_bytes / n_elems);
if (nRows > max_row) nRows = max_row;

//................................................

makerow row;
memset(&row, 0, sizeof(row));


row.inode_no = new_ino_no;
row.type = 1;

//................................................

char nm[59];
memset(nm, 0, sizeof(nm));


fetchFileName(data.file, nm);
memcpy(row.name, nm, 58);


dirent_checksum_finalize(&row);

//................................................

bool flag = false;


for (int r = 0; r < nRows; ++r){
    makerow tempRow;
    memcpy(&tempRow, (root_dataBlock + r * n_elems), n_elems);

    if (tempRow.inode_no == 0){
        memcpy((root_dataBlock + r * n_elems), &row, n_elems);
        flag =true;
        break;
    }
}

if (flag!=true){
    if (nRows >= max_row){
        free(disk);
        error_message("Root directory is full");
    }
    memcpy(root_dataBlock + nRows * n_elems, &row, n_elems);
    nRows++;
    rootInode->size_bytes = (nRows * n_elems);
}

//................................................

rootInode->mtime = current_time;
rootInode->ctime = current_time;

inode_crc_finalize(rootInode);

//................................................

    superBlock->mtime_epoch = current_time;
    superblock_crc_finalize(superBlock);

//................................................

FILE *x = fopen(data.out, "wb");
if (!x){
    printf("Error: Could not open output file '%s'\n", data.out);
    free(disk);    exit(1);
}

//................................................

int writeCount = 0;
while (writeCount< (int)(sz)){
    uc writeUnit = disk[writeCount];
    if (fputc(writeUnit, x) == EOF){
        printf("Failed to write the disk image in the file: '%s'\n", data.out);
        fclose(x); free(disk);  exit(1);
    }
    writeCount++;
}

//................................................

fclose(x); free(disk);

//................................................

printf("Disk loading inside the output file mentioned successful! \nAdded fileName: '%s' as inode: %u\nInput Image: '%s'\nOutput Image: '%s'\n", data.file,new_ino_no, data.in, data.out);

return 0;


}
