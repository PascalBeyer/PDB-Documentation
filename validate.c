#define _CRT_SECURE_NO_WARNINGS

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Some invariants which seem to be _implied_ are not honered by
// PDB's produced by the microsoft toolchain.
// If 'STRICT' is '1', these are still checked, otherwise the 
// corresponding checks are relaxed.
#define STRICT 0

typedef unsigned __int8  u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;

typedef __int8  s8;
typedef __int16 s16;
typedef __int32 s32;
typedef __int64 s64;

#define offset_in_type(type, member) (u64)(&((type *)0)->member)

int print(char *format, ...){
    va_list va;
    va_start(va, format);
    int ret = vprintf(format, va);
    va_end(va);
    
    fflush(0);
    return ret;
}

u32 crc32(u32 initial_crc, u8 *data, u64 amount){
    // crc32 works by using polynomial division over F_2.
    // The i-th bit corresponds to X^i.
    // for simplicity lets assume there are 100 bits:
    //     msg: [b99:b98:...: b0] <-> b99 X^99 + b98 X^98 + ... + b0
    
    // CRC32 uses the 'generating polynomial':
    //    X^32 + X^26 + X^23 + X^22 + X^16 + X^12 + X^11 + X^10 + X^8 + X^7 + X^5 + X^4 + X^2 + X + 1
    // or 100000100110000010001110110110111 = 0x104c11db7, we usually omit the first one.
    // The crc32 of a message is the remainder after long division by the generating polynomial.
    
    // ACTUALLY: Everything uses 'reflected' values. The reflected polynomial is 0xedb88320.
    //           This means the highest value bit is the lowest bit.
    
#if 0
    // 'reflect' the entry i.e swap all bits
    u32 reflect(u32 entry){
        for(u32 i = 0; i < 16; i++){
            u32 j = 31 - i;
            u32 bit1 = ((1 << i) & entry);
            u32 bit2 = ((1 << j) & entry);
            
            entry ^= bit1 | bit2 | ((bit1 >> i) << j) | ((bit2 >> j) << i));
        }
        return entry;
    }
#endif
    
    // This table maps 'byte' -> ('byte' * X^32 mod g(X)).
    static const u32 crc32_table[0x100] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
        0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
        0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
        0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
        0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
        0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
        0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
        0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
        0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
        0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
        0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
        0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
        0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
        0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
        0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
        0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
        0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
        0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
        0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    };
    
    // The crc_table is generated by this code:
    
#if 0
    for(u32 entry_index = 0; entry_index < 0x100; entry_index++){
        u32 entry = entry_index;
        
        for(u32 bit_index = 0; bit_index < 8; bit_index++){
            // Perform polynomial division.
            // If the top bit is set, we subtract (xor) the (reflected) generating polynomial.
            entry = (entry & 1) ? ((entry >> 1) ^ reflect(0x04c11db7)) : (entry >> 1);
        }
        
        // After we are done, 'entry' is the remainder of polynomial division over F_2 of 'i * X^32'
        // store this in the table.
        
        crc_table[entry_index] = entry;
    }
#endif
    
    // Assume we have a message and a last byte
    //      [msg?,...,msg0] | [lb7,...,lb0]
    // and we have calculated the remainder of 'msg * X^32' after division by g(X) to be 'crc'
    //     i.e:  msg * X^32 + crc = 0 mod g(X)
    // Thus we calculate
    //     crc' = (msg||lb) * X^32       mod g(X)
    //          = msg * X^40 + lb * X^32 mod g(X)
    //          = crc * X^8  + lb * X^32 mod g(X)
    //          = (crc[31:8] << 8) + (crc[7:0] + lb) * X^32
    // Note the reflection on crc.
    // Finally the line in the for below is this equation for the crc' using the table above
    //     crc' = (crc[31:8] << 8) + ((crc[7:0] + lb) * X^32 mod g(X))
    
    u32 crc = initial_crc;
    for(u64 i = 0; i < amount; i++){
        crc = (crc >> 8) ^ crc32_table[(crc & 0xff) ^ data[i]];
    }
    
    return crc;
}

// Used to binary search offset arrays.
int compare_u32(const void *a, const void *b){
    u32 a_u32 = *(u32 *)a;
    u32 b_u32 = *(u32 *)b;
    
    if(a_u32 > b_u32) return 1;
    if(a_u32 < b_u32) return -1;
    return 0;
}

__declspec(noreturn) void error(char *format, ...){
    va_list va;
    va_start(va, format);
    vprintf(format, va);
    va_end(va);
    
    print("\n");
    
    fflush(0);
    
    _exit(1);
}

char *format_string(char *format, ...){
    va_list va, copy;
    va_start(va, format);
    va_copy(copy, va);
    
    int length = vsnprintf(0, 0, format, va);
    
    char *ret = malloc(length+1);
    vsnprintf(ret, length+1, format, copy);
    
    va_end(copy);
    va_end(va);
    
    return ret;
}

struct msf_streams{
    u32 amount_of_streams;
    struct msf_stream{
        u8 *data;
        u32 size;
        u32 offset;
    } *streams;
} msf_validate(u8 *msf_base, size_t msf_file_size){
    
    struct msf_header{
        //
        // "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0\0"
        //
        u8 signature[32];
        
        //
        // The msf format allocates data in "pages".
        // This value is usually '0x1000' on x64 systems.
        //
        u32 page_size;
        
        //
        // The free page map has a bit set for every page that is unused.
        // The first free page map covers the first 8 'intervals', i.e the
        // first 0x8000 pages.
        // There are always two free page maps (one on page 1 and one on page 2),
        // but only one is used.
        // The one used is specified by this field.
        //
        u32 active_free_page_map_number;
        
        //
        // The total amount of pages in the file.
        // 'amount_of_pages * page_size' should equal the file size.
        //
        u32 amount_of_pages;
        
        //
        // The size of the stream_table stream. This field is used together with the
        // 'stream_table_stream_number_list' to find the stream_table stream.
        //
        u32 stream_table_stream_size;
        
        //
        // This field comes from a 32 bit pointer, which was written here for an earlier
        // version of the msf format, but never used.
        //
        u32 reserved;
        
        //
        // The page number list of an array of page numbers.
        // Each page number in the array corresponds to a page in the stream_table stream.
        // The amount of entries is determined by 'stream_table_stream_size'.
        //
        u32 page_list_of_stream_table_stream_page_list[0];
    } *msf_header = (void *)msf_base;
    
    if(msf_file_size < sizeof(struct msf_header)){
        error("MSF Error: File to small to contain msf header.");
    }
    
    if(memcmp(msf_header->signature, "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0\0", 32) != 0){
        error("MSF Error: Invalid msf signature (we only handle BigMsf).");
    }
    
    u32 page_size = msf_header->page_size;
    if(!page_size || (page_size & (page_size - 1))){
        error("MSF Error: Page size specified in msf header must be a power of two.");
    }
    
    if(msf_header->active_free_page_map_number != 1 && msf_header->active_free_page_map_number != 2){
        error("MSF Error: The page number of the free page map specified by the msf header must be '1' or '2'.");
    }
    
    if((u64)msf_header->amount_of_pages * (u64)page_size != msf_file_size){
        error("MSF Error: The number of pages specified by the msf header does not equal the amount of pages present.");
    }
    
    if(msf_header->reserved != 0){
        error("MSF Error: Reserved field in the msf header is non-zero.");
    }
    
    u32 amount_of_pages = msf_header->amount_of_pages;
    
    // @cleanup: can msf files have only one page?
    // 
    // Load the free page map. The free page map consists of the pages equal 
    // to 'msf_header->active_free_page_map' modulo the page size.
    // 
    u32 amount_of_pages_in_free_page_map = (amount_of_pages + page_size - msf_header->active_free_page_map_number)/ page_size;
    u8 *active_free_page_map = malloc(amount_of_pages_in_free_page_map * page_size);
    
#define test_and_set_page(page_number) _bittestandset((long *)active_free_page_map, (page_number))
    
    for(u32 page_number = msf_header->active_free_page_map_number, page_index = 0; page_number < amount_of_pages; page_number += page_size, page_index++){
        memcpy(active_free_page_map + page_index * page_size, msf_base + page_number * page_size, page_size);
    }
    
    if(test_and_set_page((u32){0})){ // @cleanup: @hack: this should just be 0, but there is a bug in my compiler :(
        error("MSF Error: The header page (page 0) is marked free in the free page map.");
    }
    
    for(u32 page_number = 1; page_number < amount_of_pages; page_number += page_size){
        if(test_and_set_page(page_number)){
            error("MSF Error: Free page map page at %u is marked as free in the free page map.", page_number);
        }
        if(test_and_set_page(page_number + 1)){
            error("MSF Error: Free page map page at %u is marked as free in the free page map.", page_number + 1);
        }
    }
    
    u32 stream_table_stream_size      = msf_header->stream_table_stream_size;
    u32 stream_table_stream_page_size = (stream_table_stream_size + page_size - 1)/page_size;
    u32 stream_table_stream_page_number_list_page_size = (stream_table_stream_page_size * 4 + page_size - 1)/page_size;
    
    if(stream_table_stream_page_number_list_page_size > (page_size - sizeof(*msf_header))/4){
        error("MSF Error: Stream table stream is too big for stream table stream page number list to fit in the msf header.");
    }
    
    // 
    // Resolve the first layer of indirection, meaning building the stream table stream page number list.
    // 
    u8 *stream_table_stream_page_number_list = malloc(stream_table_stream_page_number_list_page_size * page_size);
    
    for(u32 index = 0; index < stream_table_stream_page_number_list_page_size; index++){
        
        u32 page_number = msf_header->page_list_of_stream_table_stream_page_list[index];
        
        if((page_number == 0) || (page_number >= amount_of_pages) || (page_number & (page_size - 1)) == 1 || (page_number & (page_size - 1)) == 2){
            error("MSF Error: Page number %u (%u) inside the stream table stream page number list page list is invalid.", index, page_number);
        }
        
        if(test_and_set_page(page_number)){
            error("MSF Error: Page number %u (%u) inside the stream table strea page number list page list is marked as free.", index, page_number);
        }
        
        memcpy(stream_table_stream_page_number_list + page_size * index, msf_base + page_number * page_size, page_size); 
    }
    
    // 
    // Resolve the second layer of indirection, building the stream table stream.
    // 
    
    u8 *stream_table_stream = malloc(stream_table_stream_page_size * page_size);
    for(u32 index = 0; index < stream_table_stream_page_size; index++){
        u32 page_number = ((u32 *)stream_table_stream_page_number_list)[index];
        
        if((page_number == 0) || (page_number >= amount_of_pages) || (page_number & (page_size - 1)) == 1 || (page_number & (page_size - 1)) == 2){
            error("MSF Error: Page number %u (%u) inside the stream table stream page number list is invalid.", index, page_number);
        }
        
        if(test_and_set_page(page_number)){
            error("MSF Error: Page number %u (%u) inside the stream table stream page number list is marked as free.", index, page_number);
        }
        
        memcpy(stream_table_stream + page_size * index, msf_base + page_number * page_size, page_size); 
    }
    
    // 
    // Parse the stream table stream:
    //
    // The stream table stream tells us where all the other streams are located.
    // It has the following layout:
    //     u32 amount_of_streams;
    //     u32 stream_sizes[amount_of_streams];
    //     u32 stream_one_pages[];
    //     u32 stream_two_pages[];
    //     ...
    //
    
    if(stream_table_stream_size < 4){
        error("MSF Error: The stream table stream is smaller then 4 bytes.");
    }
    
    u32 amount_of_streams = *(u32 *)stream_table_stream;
    if(stream_table_stream_size < 4 + 4 * amount_of_streams){
        error("MSF Error: The stream table stream is too small to contain the stream sizes of all %u streams.", amount_of_streams);
    }
    
    struct msf_stream *streams = calloc(amount_of_streams, sizeof(struct msf_stream));
    
    u32 *stream_sizes = (u32 *)(stream_table_stream + 4);
    u32 *stream_pages = (u32 *)(stream_table_stream + 4 + 4 * amount_of_streams);
    for(u32 stream_index = 0, stream_page_base = 0; stream_index < amount_of_streams; stream_index++){
        
        u32 stream_size = stream_sizes[stream_index];
        if(stream_size == 0xffffffff) continue;
        
        u32 stream_page_size = (stream_size + page_size - 1)/page_size;
        u8 *stream_data = malloc(stream_page_size * page_size);
        
        streams[stream_index].size = stream_size;
        streams[stream_index].data = stream_data;
        
        if(stream_index == /*Old Stream Table Stream*/0){
            // 
            // The pages in this stream are already freed.
            // 
            stream_page_base += stream_page_size;
            continue;
        }
        
        for(u32 stream_page_index = 0; stream_page_index < stream_page_size; stream_page_index++){
            u32 page_number = stream_pages[stream_page_base + stream_page_index];
            
            if((page_number == 0) || (page_number >= amount_of_pages) || (page_number & (page_size - 1)) == 1 || (page_number & (page_size - 1)) == 2){
                error("MSF Error: Page number %u (%u) inside the page list of stream %u is invalid.", stream_page_index, page_number, stream_index);
            }
            
            if(test_and_set_page(page_number)){
                error("MSF Error: Page number %u (%u) inside the page list of stream %u is marked as free.", stream_page_index, page_number, stream_index);
            }
            
            memcpy(stream_data + stream_page_index * page_size, msf_base + page_number * page_size, page_size);
        }
        
        stream_page_base += stream_page_size;
    }
    
    for(u32 page_index = 0; page_index < 8 * (page_size * amount_of_pages_in_free_page_map); page_index++){
        if(!_bittest((long *)active_free_page_map, page_index)){
            error("MSF Error: Page %u was marked allocated inside the active free page map, but was not referenced by anything.", page_index);
        }
    }
    
    struct msf_streams ret = {
        .streams = streams,
        .amount_of_streams = amount_of_streams,
    };
    
    return ret;
}

// returns 1 on error, 0 on success.
int msf_read_from_stream(struct msf_stream *stream, void *data, u64 size){
    
    if(size + stream->offset > stream->size){
        stream->offset = stream->size;
        return 1;
    }
    
    memcpy(data, stream->data + stream->offset, size);
    stream->offset += size;
    return 0;
}

void *msf_read_by_pointer(struct msf_stream *stream, u64 size){
    
    if(size + stream->offset > stream->size){
        stream->offset = stream->size;
        return 0;
    }
    
    void *ret = (stream->data + stream->offset);
    stream->offset += size;
    return ret;
}

char *msf_read_string(struct msf_stream *stream){
    char *string = (char *)stream->data + stream->offset;
    while(stream->offset < stream->size){
        if(!stream->data[stream->offset++]){
            return string;
        }
    }
    return 0;
}

int msf_substream(struct msf_stream *stream, u64 size, struct msf_stream *substream){
    if(stream->offset + size > stream->size){
        stream->offset = stream->size;
        return 1;
    }
    
    struct msf_stream ret = {
        .data = stream->data + stream->offset,
        .size = size,
    };
    
    stream->offset += size;
    
    *substream = ret;
    
    return 0;
}

int msf_stream_by_index(struct msf_streams *streams, struct msf_stream *stream, u16 stream_index){
    if(stream_index == 0xffff){
        // The stream is not present, return an empty stream.
        *stream = (struct msf_stream){0};
        return 0;
    }
    
    if(stream_index >= streams->amount_of_streams){
        return 1;
    }
    
    *stream = streams->streams[stream_index];
    return 0;
}

u32 pdb_hash_index(u8 *bytes, size_t size, u32 modulus){
    u32 hash = 0;
    
    // Xor the bytes by dword lanes.
    for(u32 index = 0; index < size/sizeof(u32); index++){
        hash ^= ((u32 *)bytes)[index];
    }
    
    // Xor remaining bytes in.
    if(size & 2) hash ^= *(u16 *)(bytes + (size & ~3));
    if(size & 1) hash ^= *(u8 *) (bytes + (size -  1));
    
    // Make sure the hash is case insensitive.
    hash |= 0x20202020;
    
    // Mix the lanes.
    hash ^= (hash >> 11);
    hash ^= (hash >> 16);
    
    // Take the modulus and return the hash.
    return (hash % modulus);
}

// Used by both the '/names' stream and the 'edit_and_continue_substream'.
struct msf_stream validate_string_table_stream(struct msf_stream names_stream, char *stream_name, int dump){
    if(!names_stream.data) return (struct msf_stream){0};
    
    //
    // The /names stream:
    //
    // The /names stream is a global string hash table/string buffer.
    // It has the following layout:
    //     u32 signature;
    //     u32 hash_version;
    //     u32 string_buffer_size;
    //     u8  string_buffer[string_buffer_size];
    //     u32 bucket_count;
    //     u32 buckets[bucket_count];
    //     u32 amount_of_strings;
    //
    // The 'hash_version' specifies which hash function is used for
    // the 'buckets' and the 'buckets' contain an offset into the string buffer.
    // This means the 'string_buffer' has to have a 0-byte (zero-string) up first
    // as 0 is treated as the invalid value for the 'buckets'.
    // We assume a hash version of 1, which is the 'pdb_string_hash'.
    //
    // One important aspect here is that there is no enforced alignment on the 'string_buffer'.
    // In fact usually, the rest of the section after the string buffer is just unaligned.
    //
    
    struct{
        u32 signature;
        u32 hash_version;
        u32 string_buffer_size;
    } names_stream_header;
    
    if(msf_read_from_stream(&names_stream, &names_stream_header, sizeof(names_stream_header))){
        error("Error: %s stream is too small to contain its header.", stream_name);
    }
    
    if(dump){
        print("\n%s Stream:\n", stream_name);
        print("    signature 0x%x\n", names_stream_header.signature);
        print("    hash version %u\n", names_stream_header.hash_version);
        print("    string buffer size 0x%x\n", names_stream_header.string_buffer_size);
    }
    
    if(names_stream_header.signature != 0xEFFEEFFE){
        error("Error: %s stream has wrong signature 0x%x, expected 0xeffeeffe.", stream_name, names_stream_header.signature);
    }
    
    if(names_stream_header.hash_version != 1){
        error("Error: %s stream has unknown hash version %u, expected 1.", stream_name, names_stream_header.hash_version);
    }
    
    if((names_stream.offset + names_stream_header.string_buffer_size > names_stream.size) || (names_stream_header.string_buffer_size == 0)){
        error("Error: %s stream specifies invalid string buffer size.", stream_name);
    }
    
    struct msf_stream string_buffer_stream;
    if(msf_substream(&names_stream, names_stream_header.string_buffer_size, &string_buffer_stream)){
        error("Error: String buffer of the %s stream does not fit.", stream_name);
    }
    
    {
        // 
        // Zero is used as an invalid offset into the string buffer, hence the first string in the 
        // string buffer should be the zero-sized string.
        // 
        if(string_buffer_stream.data[0] != 0){
            error("Error: The string buffer of the %s stream should contain the zero-sized string as the first element.", stream_name);
        }
        
        if(string_buffer_stream.data[string_buffer_stream.size-1] != 0){
            error("Error: The last string inside the string buffer of the %s stream is not zero-terminated.", stream_name);
        }
    }
    
    if(dump){
        for(u32 string_offset = 0; string_offset < string_buffer_stream.size;){
            char *string = (char *)string_buffer_stream.data + string_offset;
            u32   string_length = (u32)strlen(string);
            
            print("        0x%.8x: \"%s\"\n", string_offset, string);
            
            string_offset += string_length + 1;
        }
    }
    
    u32 bucket_count;
    if(msf_read_from_stream(&names_stream, &bucket_count, sizeof(bucket_count))){
        error("Error: The %s stream ends after its string buffer. Expected a hash table to follow.", stream_name);
    }
    
    if(dump) print("    bucket count 0x%x\n", bucket_count);
    
    struct msf_stream bucket_stream;
    if(msf_substream(&names_stream, (u64)bucket_count * 4, &bucket_stream)){
        error("Error: The hash table buckets for the %s stream do not fit.", stream_name);
    }
    
    // We don't need to _build_ a hash table, it is already here.
    u32 *buckets = (u32 *)bucket_stream.data;
    
    for(u32 bucket_index = 0; bucket_index < bucket_count; bucket_index++){
        u32 string_offset = buckets[bucket_index];
        if(!string_offset) continue; // Entry not present.
        
        if(string_offset >= string_buffer_stream.size){
            error("Error: Bucket %u of the %s stream table contains invalid offset 0x%x.\n", bucket_index, stream_name, string_offset);
        }
        
        char *string = (char *)(string_buffer_stream.data + string_offset);
        
        if(dump) print("        [%u] %x (%s)\n", bucket_index, string_offset, string);
    }
    
    u32 specified_amount_of_strings;
    if(msf_read_from_stream(&names_stream, &specified_amount_of_strings, sizeof(specified_amount_of_strings))){
        error("Error: Expected the amount of strings to be at the very end of the %s stream (after the bucket array).", stream_name);
    }
    
    if(dump) print("    amount of source files %u\n", specified_amount_of_strings);
    
    if(names_stream.offset != names_stream.size){
        error("Error: The %s stream is bigger then expected.", stream_name);
    }
    
    // 
    // Count the amount of strings in the string buffer.
    // 
    u32 amount_of_strings = 0;
    for(u32 string_offset = 1; string_offset < string_buffer_stream.size; amount_of_strings += 1){
        char *string = (char *)string_buffer_stream.data + string_offset;
        u32   string_length = (u32)strlen(string);
        
        // 
        // Make sure the 'string' maps to itself.
        // 
        
        u32 string_hash = pdb_hash_index((u8 *)string, string_length, (u32)-1);
        
        for(u32 table_index = 0; table_index < bucket_count; table_index++){
            u32 index = (table_index + string_hash) % bucket_count;
            
            u32 offset = buckets[index];
            if(offset == 0){
                error("Error: The %s stream string buffer contains a string at offset 0x%x which does not hash to itself using the hash buckets.", stream_name, string_offset);
            }
            
            // We have found it.
            if(offset == string_offset) break;
        }
        
        string_offset += string_length + 1;
    }
    
    // 
    // Make sure there is exactly one set bucket per string.
    // 
    u32 bucket_amount_of_strings = 0;
    for(u32 bucket_index = 0; bucket_index < bucket_count; bucket_index++){
        bucket_amount_of_strings += (buckets[bucket_index] != 0);
    }
    
    if(specified_amount_of_strings != amount_of_strings){
        error("Error: The %s stream specifies the wrong number of strings. Expected %u, got %u.", stream_name, amount_of_strings, specified_amount_of_strings);
    }
    
    if(bucket_amount_of_strings != amount_of_strings){
        error("Error: The %s stream specifies the wrong number of strings. Expected %u, got %u.", stream_name, amount_of_strings, specified_amount_of_strings);
    }
    
    return string_buffer_stream;
}

struct pdb_section_contribution{
    s16 section_id;
    u16 padding1;
    s32 offset;
    s32 size;
    u32 characteristics;
    s16 module_index;
    u16 padding2;
    u32 data_crc;
    u32 reloc_crc;
};

struct pdb_section_contribution_v2{
    union{
        struct{
            s16 section_id;
            u16 padding1;
            s32 offset;
            s32 size;
            u32 characteristics;
            s16 module_index;
            u16 padding2;
            u32 data_crc;
            u32 reloc_crc;
        };
        
        struct pdb_section_contribution base;
    };
    
    u32 segment_id_in_object_file;
};

struct pdb_image_section_header{
    u8  name[8];
    u32 virtual_size;
    u32 virtual_address;
    u32 size_of_raw_data;
    u32 pointer_to_raw_data;
    u32 pointer_to_relocations;
    u32 pointer_to_linenumbers;
    u16 number_of_relocations;
    u16 number_of_linenumbers;
    u32 characteristics;
};

struct pdb_section_table{
    struct pdb_image_section_header *data;
    u64 size;
};

char *pdb_check_section_id_offset(struct pdb_section_table *section_table, u16 id, u32 offset, u32 size){
    u16 index = id - 1;
    if(index >= section_table->size){
        return format_string("has an invalid section id %d (section id's are one based indices into the section table)", id);
    }
    
    struct pdb_image_section_header section = section_table->data[index];
    if((u64)offset + (u64)size > (u64)section.virtual_size){
        if(size){
            return format_string("has an invalid range [0x%x, 0x%llx) in section %d which has size 0x%x", offset, (u64)offset + (u64)size, id, section.virtual_size);
        }else{
            return format_string("has an invalid offset 0x%x in section %d which has size %x", offset, id, section.virtual_size);
        }
    }
    
    return 0;
}

// This assumes the symbol record has previously been checked to be correct.
char *pdb_symbol_record__get_name(u8 *symbol_record){
    
    struct codeview_symbol_header{
        u16 length;
        u16 kind;
    } *symbol_header = (void *)symbol_record;
    
    char *symbol_data = (char *)(symbol_header + 1);
    
    switch(symbol_header->kind){
        case /*S_GDATA32*/0x110d:
        case /*S_LDATA32*/0x110c: 
        case /*S_ANNOTATIONREF*/0x1128:
        case /*S_LPROCREF*/0x1127:
        case /*S_DATAREF*/0x1126:
        case /*S_PROCREF*/0x1125:
        case /*S_PUB32*/0x110e: return symbol_data + 10;
        
        case /*S_UDT*/0x1108: return symbol_data + 4;
        
        case /*S_CONSTANT*/0x1107:{
            u16 numeric_leaf = pdb_numeric_leaf_size_or_error(*(u16 *)(symbol_data + 4));
            return symbol_data + 4 + numeric_leaf;
        }break;
    }
    
    error("Internal Error: Invalid symbol kind 0x%hx inside 'pdb_symbol_record__get_name'.", symbol_header->kind);
}

char *pdb_type_record__get_name(u8 *type_record){
    
    struct codeview_type_header{
        u16 length;
        u16 kind;
    } *type_header = (void *)type_record;
    
    char *type_data = (char *)(type_header + 1);
    switch(type_header->kind){
        
        case /*LF_CLASS2*/0x1608:
        case /*LF_INTERFACE2*/0x160b:
        case /*LF_STRUCTURE2*/0x1609:{
            type_data += 0x10;
            type_data += pdb_numeric_leaf_size_or_error(*(u16 *)type_data); // count
            type_data += pdb_numeric_leaf_size_or_error(*(u16 *)type_data); // size
            return type_data;
        }break;
        
        case /*LF_STRUCTURE*/0x1505:
        case /*LF_CLASS*/0x1504:
        case /*LF_INTERFACE*/0x1519:{
            return type_data + 0x10 + pdb_numeric_leaf_size_or_error(*(u16 *)(type_data + 0x10));
        }break;
        
        case /*LF_UNION2*/0x160a:{
            type_data += 8;
            type_data += pdb_numeric_leaf_size_or_error(*(u16 *)type_data); // count
            type_data += pdb_numeric_leaf_size_or_error(*(u16 *)type_data); // size
            return type_data;
        }break;
        
        case /*LF_UNION*/0x1506:{
            return type_data + 8 + pdb_numeric_leaf_size_or_error(*(u16 *)(type_data + 8));
        }break;
        
        case /*LF_ENUM*/0x1507:{
            return type_data + 12;
        }break;
        
        case /*LF_ALIAS*/0x150a:{
            return type_data + 4;
        }break;
        
        default: return "";
    }
}



// returns -1 on failiure.
int pdb_numeric_leaf_size_or_error(u16 numeric_leaf){
    
    if(!(numeric_leaf & 0x8000)) return 2;
    
    //
    // @cleanup: implement this more correctly
    //
    
    switch(numeric_leaf){
        case 0x8000:{ // LF_CHAR
            return 2 + 1;
        }break;
        case 0x8001:  // LF_SHORT
        case 0x8002:{ // LF_USHORT
            return 2 + 2;
        }break;
        case 0x8005: // LF_REAL32
        case 0x8003: // LF_LONG
        case 0x8004:{ // LF_ULONG
            return 2 + 4;
        }break;
        
        case 0x8009: // LF_QUADWORD
        case 0x800a: // LF_UQUADWORD
        case 0x8006:{ // LF_REAL64
            return 2 + 8;
        }break;
        
        case 0x8008: // LF_REAL128
        
        // case 0x8007: // LF_REAL80
        // case 0x800b: // LF_REAL48
        // case 0x800c: // LF_COMPLEX32
        // case 0x800d: // LF_COMPLEX64
        // case 0x800e: // LF_COMPLEX80
        // case 0x800f: // LF_COMPLEX128
        // case 0x8010: // LF_VARSTRING
        
        case 0x8017: // LF_OCTWORD
        case 0x8018:{ // LF_UOCTWORD
            return 2 + 16;
        }break;
        
        // case 0x8019: // LF_DECIMAL
        // case 0x801a: // LF_DATE
        // case 0x801b: // LF_UTF8STRING
        // case 0x801c: // LF_REAL16
        default:{
            return -1;
        }break;
    }
    
    // unreachable!
    return -1;
}

char *pdb_read_numeric_leaf(struct msf_stream *stream){
    
    u16 numeric_leaf;
    
    if(msf_read_from_stream(stream, &numeric_leaf, sizeof(numeric_leaf))){
        return "is too small";
    }
    
    int leaf_size = pdb_numeric_leaf_size_or_error(numeric_leaf);
    if(leaf_size == -1){
        return "has invalid numeric leaf.";
    }
    
    if(!msf_read_by_pointer(stream, leaf_size-2)){
        return "is too small for its numeric leaf.";
    }
    
    return 0;
}

// :pdb_hash_table_empty_and_deleted_slots
// 
// We currently encode an empty slot in the table as 'value == 0'
// and deleted values as 'value == (u32)-1'. 
// This works, as we use this table only for type- and stream indices,
// which are never 0 or (u32)-1.
struct pdb_hash_table{
    u32 amount_of_entries;
    u32 capacity;
    
    struct pdb_hash_table_entry{
        u32 key;
        u32 value;
    } *data;
};

struct pdb_hash_table pdb_deserialize_hash_table(struct msf_stream *stream, char *table_name){
    
    // 
    // Serialized hash table:
    //     u32 amount_of_entries;
    //     u32 capacity;
    //     struct{
    //         u32 word_count;
    //         u32 words[present_bits.word_count];
    //     } present_bits;
    //     struct{
    //         u32 word_count;
    //         u32 words[deleted_bits.word_count];
    //     } deleted_bits;
    //     struct{
    //         u32 key;
    //         u32 value;
    //     } entries[amount_of_entries];
    //     
    
    struct{
        u32 amount_of_entries;
        u32 capacity;
    } serialized_hash_table_header;
    
    if(msf_read_from_stream(stream, &serialized_hash_table_header, sizeof(serialized_hash_table_header))){
        error("Error: The %s does not fit.", table_name);
    }
    
    u32 present_bits_word_count;
    if(msf_read_from_stream(stream, &present_bits_word_count, sizeof(present_bits_word_count))){
        error("Error: The %s does not fit.", table_name);
    }
    
    struct msf_stream present_bits_stream;
    if(msf_substream(stream, (u64)present_bits_word_count * 4, &present_bits_stream)){
        error("Error: The %s does not fit.", table_name);
    }
    
    u32 deleted_bits_word_count;
    if(msf_read_from_stream(stream, &deleted_bits_word_count, sizeof(deleted_bits_word_count))){
        error("Error: The %s does not fit.", table_name);
    }
    
    struct msf_stream deleted_bits_stream;
    if(msf_substream(stream, (u64)deleted_bits_word_count * 4, &deleted_bits_stream)){
        error("Error: The %s does not fit.", table_name);
    }
    
    struct msf_stream entries_stream;
    if(msf_substream(stream, (u64)serialized_hash_table_header.amount_of_entries * 8, &entries_stream)){
        error("Error: The %s does not fit.", table_name);
    }
    
    // 
    // Rebuild the hash table:
    // 
    
    struct pdb_hash_table_entry *hash_table = calloc(serialized_hash_table_header.capacity, sizeof(*hash_table));
    
    for(u32 index = 0; index < serialized_hash_table_header.capacity; index++){
        
        int is_present = index < (32 * present_bits_word_count) ? _bittest((long *)present_bits_stream.data, index) : 0;
        int is_deleted = index < (32 * deleted_bits_word_count) ? _bittest((long *)deleted_bits_stream.data, index) : 0;
        
        if(is_present && is_deleted){
            error("Error: Entry %u in the %s is marked both present and deleted.", index, table_name);
        }
        
        if(is_present){
            if(msf_read_from_stream(&entries_stream, &hash_table[index], sizeof(hash_table[index]))){
                error("Error: The present bit vector of the %s has more bits set than entries are present.", table_name);
            }
        }
        
        if(is_deleted){
            hash_table[index].key = (u32)-1;
            hash_table[index].value  = (u32)-1;
        }
    }
    
    if(entries_stream.offset != entries_stream.size){
        error("Error: The present bit vector of the %s has less bits set than there are entries.", table_name);
    }
    
    struct pdb_hash_table ret = {
        .amount_of_entries = serialized_hash_table_header.amount_of_entries,
        .capacity = serialized_hash_table_header.capacity,
        .data = hash_table,
    };
    
    return ret;
}

void pdb_validate(u8 *pdb_base, size_t pdb_file_size, int dump){
    
    struct msf_streams streams = msf_validate(pdb_base, pdb_file_size);
    
    if(streams.amount_of_streams < 3){
        error("PDB Error: Too little streams in PDB, need at least 3 (PDB, TPI, DBI).");
    }
    
    // 
    // Read out the 3 fixed streams.
    // 
    struct msf_stream pdb_stream = streams.streams[1];
    struct msf_stream tpi_stream = streams.streams[2];
    struct msf_stream dbi_stream = streams.streams[3];
    
    struct msf_stream names_stream = {0};
    
    int is_lazy_pdb     = 0;
    int is_fastlink_pdb = 0;
    int has_ipi_stream  = 0;
    
    {
        //
        // The PDB Information Stream (stream index 1)
        // 
        // This stream contains the 'guid' and 'age' information used to match the .exe to its .pdb.
        // It also contains information about _named streams_ in a serialized hash table.
        // We only really care about the '/names' stream.
        //
        // The general layout is:
        //    
        //    header
        //    string buffer
        //    serialized hash table (string offset -> stream index)
        //    feature flags
        // 
        if(dump) print("\nPDB Information Stream:\n");
        
        struct {
            u32 version;
            u32 timestamp;
            u32 age;
            struct {
                u32 data1;
                u16 data2;
                u16 data3;
                u8 data4[8];
            } guid;
        } pdb_info_stream_header;
        
        if(msf_read_from_stream(&pdb_stream, &pdb_info_stream_header, sizeof(pdb_info_stream_header))){
            error("Error: The PDB Information Stream (stream index 1), is not large enough to hold its header.");
        }
        
        if(dump){
            print("    version: %u\n", pdb_info_stream_header.version);
            print("    timestamp: 0x%x\n", pdb_info_stream_header.timestamp);
            print("    age: %u\n", pdb_info_stream_header.age);
            print("    guid: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n", 
                    pdb_info_stream_header.guid.data1, pdb_info_stream_header.guid.data2, pdb_info_stream_header.guid.data3,
                    pdb_info_stream_header.guid.data4[0], pdb_info_stream_header.guid.data4[1], pdb_info_stream_header.guid.data4[2], pdb_info_stream_header.guid.data4[3], 
                    pdb_info_stream_header.guid.data4[4], pdb_info_stream_header.guid.data4[5], pdb_info_stream_header.guid.data4[6], pdb_info_stream_header.guid.data4[7]);
        }
        
        if(pdb_info_stream_header.version != /*VC70*/20000404){
            error("Error: Unexpected PDB version specified in the PDB Information Stream header. We expected '20000404'.");
        }
        
        // 
        // String buffer:
        //     u32 string_buffer_size;
        //     u8 string_buffer[string_buffer_size];
        // 
        
        u32 string_buffer_size;
        struct msf_stream string_buffer_substream; 
        if(msf_read_from_stream(&pdb_stream, &string_buffer_size, sizeof(string_buffer_size)) || msf_substream(&pdb_stream, string_buffer_size, &string_buffer_substream)){
            error("Error: The string buffer contained in the PDB information stream does not fit inside the stream.");
        }
        
        if(string_buffer_substream.size && string_buffer_substream.data[string_buffer_substream.size-1] != 0){
            error("Error: The last string in the string buffer contained in the PDB Information stream is not zero terminated.");
        }
        
        if(dump){
            print("\nNamed Stream Table String Buffer:\n");
            print("    string_buffer_size 0x%x\n", string_buffer_size);
        }
        
        u32 amount_of_strings = 0;
        for(u32 string_offset = 0; string_offset < string_buffer_substream.size; amount_of_strings++){
            if(dump) print("    [0x%x] %s\n", string_offset, (char *)string_buffer_substream.data + string_offset);
            string_offset += (u32)strlen((char *)string_buffer_substream.data + string_offset) + 1;
        }
        
        struct pdb_hash_table named_stream_table = pdb_deserialize_hash_table(&pdb_stream, "named stream table inside the PDB Information stream");
        
        //
        // The hash table is followed by a single u32 '0'.
        // This is because the hash table implementation used for the string indices is a template.
        // This template allows (optionally), to specify an integer allocation function (which in this
        // case allocates stream indices). Otherwise, the template allocates integers starting at
        // a base index. This base index is this 0.
        //
        u32 ignored;
        if(msf_read_from_stream(&pdb_stream, &ignored, sizeof(ignored))){
            error("Error: The named stream table inside the PDB Information stream does not fit.");
        }
        
        // @cleanup: make sure ignored is 0 and not a feature code.
        
        
        if(dump){
            print("\nNamed Stream Table:\n");
            print("    named_stream_table.capacity 0x%x\n", named_stream_table.capacity);
            print("    named_stream_table.amount_of_entries 0x%x\n", named_stream_table.amount_of_entries);
        }
        
        if(named_stream_table.capacity == 0){
            error("Error: Named stream table capacity cannot be 0. An empty named stream table has capacity = 1, present_bits.word_count = 1 and present_bits.words[0] = 0.");
        }
        
        for(u32 index = 0; index < named_stream_table.capacity; index++){
            u32 offset = named_stream_table.data[index].key;
            u32 stream = named_stream_table.data[index].value;
            
            // :pdb_hash_table_empty_and_deleted_slots
            if(stream == 0 || stream == (u32)-1) continue;
            
            if((offset >= string_buffer_substream.size) || (stream >= streams.amount_of_streams)){
                error("Error: Entry %u of the named stream table is invalid.", index);
            }
            
            if(offset && string_buffer_substream.data[offset-1] != 0){
                error("Error: Entry %u of the named stream table is does not point to the beginning of a string.", index);
            }
            
            if(dump) print("    [%u] 0x%x (%s) -> %u\n", index, offset, (char *)string_buffer_substream.data + offset, stream);
            
            if(strcmp((char *)string_buffer_substream.data + offset, "/names") == 0){
                names_stream = streams.streams[stream];
            }
        }
        
        if(amount_of_strings != named_stream_table.amount_of_entries){
            // error("Error: The serialized hash table inside the PDB Information stream specifies a different amount of entries then there are strings.");
        }
        
        // 
        // Make sure the hash table is in order, by looking up every string in the table.
        // 
        
        for(u32 string_offset = 0; string_offset < string_buffer_substream.size; ){
            u8 *string = string_buffer_substream.data + string_offset;
            
            u32 string_length = (u32)strnlen((char *)string, string_buffer_substream.size - string_offset);
            
            u16 hash_index = ((u16)pdb_hash_index(string, string_length, (u32)-1)) % named_stream_table.capacity;
            
            for(u32 table_index = 0; table_index < named_stream_table.capacity; table_index++){
                
                u32 index = (hash_index + table_index) % named_stream_table.capacity;
                
                struct pdb_hash_table_entry entry = named_stream_table.data[index];
                if(entry.value == 0){
                    // error("Error: The named stream table is corrupted, %s does not map to itself.", string);
                }
                
                if(entry.key == string_offset) break; // We found it.
            }
            
            string_offset += string_length + 1;
        }
        
        //
        // At the very end there is an array of _feature-flags_, which tells us if the pdb was
        // linked using /DEBUG:FASTLINK.
        //
        
        if(dump) print("\nFeature Flags:\n");
        
        while(pdb_stream.offset < pdb_stream.size){
            u32 feature_code;
            if(msf_read_from_stream(&pdb_stream, &feature_code, sizeof(feature_code))){
                error("Error: The PDB Information Stream size has invalid alignment.");
            }
            
            switch(feature_code){
                
                case /*VC110*/20091201:{
                    if(dump) print("    VC110 (%u)\n", feature_code);
                    
                    // "No other signature appended for vc110 PDB"
                    if(pdb_stream.offset != pdb_stream.size){
                        error("Error: The VC110 feature code has be the last feature code.");
                    }
                    
                    has_ipi_stream = 1;
                }break;
                case /*VC140*/20140508:{
                    if(dump) print("    VC140 (%u)\n", feature_code);
                    
                    has_ipi_stream = 1;
                }break;
                case 'NOTM':{ // /DEBUG:LAZY
                    if(dump) print("    NOTM (0x%x)\n", feature_code);
                    
                    is_lazy_pdb = 1;
                }break;
                case 'MINI':{ // MINI
                    if(dump) print("    MINI (0x%x)\n", feature_code);
                    
                    // Minimal Debug Info (/DEBUG:FASTLINK)
                    is_fastlink_pdb = 1;
                }break;
                
                default:{
                    error("Error: Unhandled feature code 0x%x in PDB Information stream.", feature_code);
                }break;
            }
        }
        
        if(has_ipi_stream && streams.amount_of_streams <= 4){
            error("Error: The PDB Information stream indicates the existence of an IPI stream, but stream index 4 is out of range.");
        }
    }
    
    struct msf_stream names_string_buffer_stream = validate_string_table_stream(names_stream, "/names", dump);
    
    struct index_stream_table{
        u32 minimal_type_index;
        u32 one_past_last_type_index;
        u32 *type_index_to_offset_map;
    } tpi_table = {0}, ipi_table = {0};
    
    // 
    // Validate the TPI and IPI stream.
    // 
    for(int index_stream_index = 2; index_stream_index <= 2 + 2 * has_ipi_stream; index_stream_index += 2){
        struct msf_stream index_stream = streams.streams[index_stream_index];
        
        int is_ipi = (index_stream_index == 4);
        char *tpi_or_ipi = is_ipi ? "IPI" : "TPI";
        
        if(dump) print("\n%s Stream:\n", tpi_or_ipi);
        
        if(index_stream.size == 0){
            if(dump) print("   %s Stream is empty\n", tpi_or_ipi);
            continue;
        }
        
        struct index_stream_header{
            // We expect the version to be '20040203'.
            u32 version;
            
            // The size of this header.
            u32 header_size;
            
            //
            // The range of type indices present in this stream.
            //
            u32 minimal_type_index;
            u32 one_past_last_type_index;
            
            u32 byte_count_of_type_record_data_following_the_header;
            
            //
            // The stream index for the TPI/IPI hash stream.
            // The auxiliary stream seems to be unused.
            //
            u16 stream_index_of_hash_stream;
            u16 stream_index_of_auxiliary_hash_stream;
            
            //
            // The hash key size and the number of buckets used for the incremental linking table below.
            //
            u32 hash_key_size;
            u32 number_of_hash_buckets;
            
            //
            // The 'hash key buffer' is contained within the TPI/IPI hash stream.
            // The size of the buffer should be '(maximal_type_index - minimal_type_index) * hash_key_size'.
            // These hash keys are used in the incremental linking hash table below.
            //
            u32 hash_table_index_buffer_offset;
            u32 hash_table_index_buffer_length;
            
            //
            // The 'index offset buffer' is an array of 'struct { u32 type_index; u32 offset_in_stream; }'.
            // The offset of each entry increases by about 8 kb each entry.
            // This buffer is intended for binary searching by type index, to get a rough (8kb accurate) offset
            // to the type, and from there one can search linearly to find the type record.
            //
            u32 index_offset_buffer_offset;
            u32 index_offset_buffer_length;
            
            // 
            // The 'udt_order_adjust_table' is used to adjust the order of entries inside 
            // of a collision chain of the hash table above. This is useful for types
            // which have been altered, but then the change was reverted.
            // 
            u32 udt_order_adjust_table_offset;
            u32 udt_order_adjust_table_length;
        } index_stream_header;
        
        if(msf_read_from_stream(&index_stream, &index_stream_header, sizeof(index_stream_header))){
            error("Error: The %s stream is too small to contain its header.", tpi_or_ipi);
        }
        
        if(dump){
            print("    version %u\n", index_stream_header.version);
            print("    header size 0x%x\n", index_stream_header.header_size);
            print("    minimal type index 0x%x\n", index_stream_header.minimal_type_index);
            print("    one past last type index 0x%x\n", index_stream_header.one_past_last_type_index);
            print("    bytes of type record data 0x%x\n", index_stream_header.byte_count_of_type_record_data_following_the_header);
            print("    hash stream index %hu\n", index_stream_header.stream_index_of_hash_stream);
            print("    aux hash stream index %hu\n", index_stream_header.stream_index_of_auxiliary_hash_stream);
            print("    hash key size 0x%x\n", index_stream_header.hash_key_size);
            print("    number of hash buckets 0x%x\n", index_stream_header.number_of_hash_buckets);
            print("    hash table index buffer offset 0x%x\n", index_stream_header.hash_table_index_buffer_offset);
            print("    hash table index buffer length 0x%x\n", index_stream_header.hash_table_index_buffer_length);
            print("    index offset buffer offset 0x%x\n", index_stream_header.index_offset_buffer_offset);
            print("    index offset buffer length 0x%x\n", index_stream_header.index_offset_buffer_length);
            print("    UDT order adjust table offset 0x%x\n", index_stream_header.udt_order_adjust_table_offset);
            print("    UDT order adjust table length 0x%x\n", index_stream_header.udt_order_adjust_table_length);
        }
        
        if(index_stream_header.version != 20040203){
            error("Error: The %s stream has an unexpected version number. Expected 20040203.", tpi_or_ipi);
        }
        
        if(index_stream_header.header_size != sizeof(index_stream_header)){
            error("Error: The %s stream specifies an unexpected header size. Expected 0x38.", tpi_or_ipi);
        }
        
        if(index_stream.size != (u64)index_stream_header.byte_count_of_type_record_data_following_the_header + (u64)index_stream_header.header_size){
            error("Error: The %s stream size does not match the one specified in its header.", tpi_or_ipi);
        }
        
        if(index_stream_header.minimal_type_index > index_stream_header.one_past_last_type_index){
            error("Error: The last type index (0x%x) is inside the %s stream exceeds the minimal type index (0x%x).", index_stream_header.one_past_last_type_index, tpi_or_ipi, index_stream_header.minimal_type_index);
        }
        
        u32 *type_index_to_offset_map = malloc(sizeof(u32) * index_stream_header.one_past_last_type_index);
        
        struct index_stream_table *index_stream_table = is_ipi ? &ipi_table : &tpi_table;
        index_stream_table->minimal_type_index       = index_stream_header.minimal_type_index;
        index_stream_table->one_past_last_type_index = index_stream_header.one_past_last_type_index;
        index_stream_table->type_index_to_offset_map = type_index_to_offset_map;
        
        char *type_or_id = is_ipi ? "Id" : "Type";
        if(dump) print("\n%s Records:\n", type_or_id);
        for(u32 type_index = index_stream_header.minimal_type_index; type_index < index_stream_header.one_past_last_type_index; type_index++){
            type_index_to_offset_map[type_index] = index_stream.offset;
            
            u16 record_length;
            struct msf_stream record_stream;
            if(msf_read_from_stream(&index_stream, &record_length, sizeof(record_length)) || msf_substream(&index_stream, record_length, &record_stream)){
                error("Error: The %s stream contains less type records than its header specifies.", tpi_or_ipi);
            }
            
#if STRICT
            if((record_length % 4) != 2){
                error("Error: %s record with type index 0x%x inside the %s stream has invalid aligned length (0x%hx).", type_or_id, type_index, tpi_or_ipi, record_length);
            }
#else
            if((record_length & 1) != 0){
                error("Error: %s record with type index 0x%x inside the %s stream has invalid aligned length (0x%hx).", type_or_id, type_index, tpi_or_ipi, record_length);
            }
            
            if(record_length == 0){
                error("Error: %s record with type index 0x%x inside the %s stream length 0.", type_or_id, type_index, tpi_or_ipi);
            }
#endif
            
            u16 record_kind; msf_read_from_stream(&record_stream, &record_kind, sizeof(record_kind));
            
            if(dump) print("    0x%x (0x%x) length:0x%hx kind:0x%hx\n", type_index, type_index_to_offset_map[type_index] - index_stream_header.header_size, record_length, record_kind);
            
            switch(record_kind){
                
                case /*LF_MODIFIER*/0x1001:{
                    char *kind_name = "LF_MODIFIER";
                    struct{
                        u32 modified_type;
                        u32 modifier;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record.modified_type >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a modified type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.modified_type, type_index);
                    }
                }break;
                
                case /*LF_POINTER*/0x1002:{
                    char *kind_name = "LF_POINTER";
                    struct{
                        u32 pointer_type;
                        u32 modifier;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record.pointer_type >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.modifier, type_index);
                    }
                }break;
                
                case /*LF_PROCEDURE*/0x1008:{
                    char *kind_name = "LF_PROCEDURE";
                    struct{
                        u32 return_type;
                        u8 call_type;
                        u8 function_attributes;
                        u16 parameter_count;
                        u32 arglist;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record.return_type >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a return type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.return_type, type_index);
                    }
                    
                    if(record.arglist >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a arglist type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.arglist, type_index);
                    }
                }break;
                
                
                case /*LF_ARGLIST*/0x1201:{
                    char *kind_name = "LF_PROCEDURE";
                    u32 count;
                    
                    if(msf_read_from_stream(&record_stream, &count, sizeof(count))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    u32 *arg_types = msf_read_by_pointer(&record_stream, count * sizeof(u32));
                    
                    if(!arg_types){
                        error("Error: %s %s record with type index 0x%x is too small based on `count`.", kind_name, type_or_id, type_index);
                    }
                    
                    for(u32 index = 0; index < count; index++){
                        if(arg_types[index] >= type_index){
                            error("Error: Argument %u of %s %s record with type index 0x%x specifies type index 0x%x (should be less than 0x%x).", index + 1, kind_name, type_or_id, type_index, arg_types[index], type_index);
                        }
                    }
                }break;
                
                case /*LF_FIELDLIST*/0x1203:{
                    char *kind_name = "LF_FIELDLIST";
                    
                    // Make sure the offset == 0 is correctly 4-byte aligned.
                    record_stream.offset -= 2;
                    record_stream.size   -= 2;
                    record_stream.data   += 2;
                    
                    while(record_stream.offset < record_stream.size){
                        u16 kind = *(u16 *)(record_stream.data + record_stream.offset);
                        
                        char *name = 0;
                        switch(kind){
                            case /*LF_ENUMERATE*/0x1502:{
                                struct {
                                    u16 kind;
                                    u16 attributes;
                                } enumerate;
                                
                                if(msf_read_from_stream(&record_stream, &enumerate, sizeof(enumerate))){
                                    error("Error: LF_ENUMERATE entry of %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                                }
                                
                                char *numeric_leaf_error = pdb_read_numeric_leaf(&record_stream);
                                if(numeric_leaf_error){
                                    error("Error: %s %s record with type index 0x%x %s.", kind_name, type_or_id, type_index, numeric_leaf_error);
                                }
                                
                                name = msf_read_string(&record_stream);
                                if(!name){
                                    error("Error: %s %s record with type index 0x%x contains non-zero terminated name.", kind_name, type_or_id, type_index);
                                }
                                
                                if(dump) print("        %s: %s\n", kind_name, name);
                            }break;
                            case /*LF_MEMBER*/0x150d:{
                                struct {
                                    u16 kind;
                                    u16 attributes;
                                    u32 type_index;
                                } member;
                                
                                if(msf_read_from_stream(&record_stream, &member, sizeof(member))){
                                    error("Error: LF_MEMBER entry of %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                                }
                                
                                if(member.type_index >= type_index){
                                    error("Error: LF_MEMBER of %s %s record with type index 0x%x specifies type index 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, member.type_index, type_index);
                                }
                                
                                char *numeric_leaf_error = pdb_read_numeric_leaf(&record_stream);
                                if(numeric_leaf_error){
                                    error("Error: %s %s record with type index 0x%x %s.", kind_name, type_or_id, type_index, numeric_leaf_error);
                                }
                                
                                name = msf_read_string(&record_stream);
                                if(!name){
                                    error("Error: %s %s record with type index 0x%x contains non-zero terminated name.", kind_name, type_or_id, type_index);
                                }
                                
                                if(dump) print("        LF_MEMBER: %s\n", name);
                            }break;
                            
                            default:{
                                if(dump) print("       Stopping here because of unknown (probably C++) member entry kind 0x%x.\n", kind);
                                record_stream.offset = record_stream.size;
                            }break;
                        }
                        
                        u64 aligned_offset = (record_stream.offset + 3) & ~3;
                        for(u32 offset = record_stream.offset; offset < aligned_offset; offset++){
                            u8 expected = 0xf0 + (aligned_offset - offset);
                            if(record_stream.data[offset] != expected){
                                error("Error: Element %s in LF_FIELDLIST with type index 0x%x has invalid padding byte 0x%.2x (should be 0x%.2x).\n", name, type_index, record_stream.data[offset], expected);
                            }
                        }
                        record_stream.offset = aligned_offset;
                    }
                    
                }break;
                
                case /*LF_BITFIELD*/0x1205:{
                    char *kind_name = "LF_BITFIELD";
                    struct{
                        u32 type;
                        u8 length;
                        u8 position;
                    } bitfield;
                    
                    if(msf_read_from_stream(&record_stream, &bitfield, sizeof(bitfield))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(bitfield.type >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies an underlying type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, bitfield.type, type_index);
                    }
                }break;
                
                case /*LF_ARRAY*/0x1503:{
                    char *kind_name = "LF_ARRAY";
                    struct{
                        u32 element_type;
                        u32 index_type;
                    } array;
                    
                    if(msf_read_from_stream(&record_stream, &array, sizeof(array))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(array.element_type >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies an element type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, array.element_type, type_index);
                    }
                    
                    if(array.index_type >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a index type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, array.index_type, type_index);
                    }
                }break;
                
                
                case /*LF_ALIAS*/0x150a:{
                    u32 underlying_type;
                    
                    if(msf_read_from_stream(&record_stream, &underlying_type, sizeof(underlying_type))){
                        error("Error: LF_ALIAS %s record with type index 0x%x is too small.", type_or_id, type_index);
                    }
                    
                    if(underlying_type >= type_index){
                        error("Error: LF_ALIAS %s record with type index 0x%x specifies an underlying type of 0x%x (should be less than 0x%x).", type_or_id, type_index, underlying_type, type_index);
                    }
                    
                    char *name = msf_read_string(&record_stream);
                    if(!name){
                        error("Error: LF_ALIAS %s record with type index 0x%x contains non-zero terminated name.", type_or_id, type_index);
                    }
                    
                    if(dump) print("        LF_ALIAS: 0x%x, %s\n", underlying_type, name);
                }break;
                
                case /*LF_STRUCTURE*/0x1505:
                case /*LF_CLASS*/0x1504:
                case /*LF_INTERFACE*/0x1519:{
                    
                    char *kind_name = "LF_STRUCTURE";
                    if(record_kind == 0x1504) kind_name = "LF_CLASS";
                    if(record_kind == 0x1519) kind_name = "LF_INTERFACE";
                    
                    struct{
                        u16 count;
                        u16 property;
                        u32 field;
                        u32 derived;
                        u32 vshape;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record.field >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a fieldlist of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.field, type_index);
                    }
                    
                    if(record.derived >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a derived type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.derived, type_index);
                    }
                    
                    if(record.vshape >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a vshape type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.vshape, type_index);
                    }
                    
                    char *numeric_leaf_error = pdb_read_numeric_leaf(&record_stream);
                    if(numeric_leaf_error){
                        error("Error: %s %s record with type index 0x%x %s.", kind_name, type_or_id, type_index, numeric_leaf_error);
                    }
                    
                    char *name = msf_read_string(&record_stream);
                    if(!name){
                        error("Error: %s %s record with type index 0x%x contains non-zero terminated name.", kind_name, type_or_id, type_index);
                    }
                    
                    if(dump) print("        %s: %s\n", kind_name, name);
                }break;
                
                case /*LF_UNION*/0x1506:{
                    char *kind_name = "LF_UNION";
                    
                    struct{
                        u16 count;
                        u16 property;
                        u32 field;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record.field >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a fieldlist of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.field, type_index);
                    }
                    
                    char *numeric_leaf_error = pdb_read_numeric_leaf(&record_stream);
                    if(numeric_leaf_error){
                        error("Error: %s %s record with type index 0x%x %s.", kind_name, type_or_id, type_index, numeric_leaf_error);
                    }
                    
                    char *name = msf_read_string(&record_stream);
                    if(!name){
                        error("Error: %s %s record with type index 0x%x contains non-zero terminated name.", kind_name, type_or_id, type_index);
                    }
                    
                    if(dump) print("        %s: %s\n", kind_name, name);
                }break;
                
                case /*LF_STRUCTURE2*/0x1609:
                case /*LF_CLASS2*/0x1608:
                case /*LF_INTERFACE2*/0x160b:{
                    
                    char *kind_name = "LF_STRUCTURE2";
                    if(record_kind == 0x1608) kind_name = "LF_CLASS2";
                    if(record_kind == 0x160b) kind_name = "LF_INTERFACE2";
                    
                    struct{
                        u32 property;
                        u32 field;
                        u32 derived;
                        u32 vshape;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record.field >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a fieldlist of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.field, type_index);
                    }
                    
                    if(record.derived >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a derived type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.derived, type_index);
                    }
                    
                    if(record.vshape >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a vshape type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.vshape, type_index);
                    }
                    
                    char *count_numeric_leaf_error = pdb_read_numeric_leaf(&record_stream);
                    if(count_numeric_leaf_error){
                        error("Error: %s %s record with type index 0x%x %s.", kind_name, type_or_id, type_index, count_numeric_leaf_error);
                    }
                    
                    char *size_numeric_leaf_error = pdb_read_numeric_leaf(&record_stream);
                    if(size_numeric_leaf_error){
                        error("Error: %s %s record with type index 0x%x %s.", kind_name, type_or_id, type_index, size_numeric_leaf_error);
                    }
                    
                    char *name = msf_read_string(&record_stream);
                    if(!name){
                        error("Error: %s %s record with type index 0x%x contains non-zero terminated name.", kind_name, type_or_id, type_index);
                    }
                    
                    if(dump) print("        %s: %s\n", kind_name, name);
                }break;
                
                case /*LF_UNION2*/0x160a:{
                    
                    char *kind_name = "LF_STRUCTURE2";
                    if(record_kind == 0x1608) kind_name = "LF_CLASS2";
                    if(record_kind == 0x160b) kind_name = "LF_INTERFACE2";
                    
                    struct{
                        u32 property;
                        u32 field;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record.field >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a fieldlist of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.field, type_index);
                    }
                    
                    char *count_numeric_leaf_error = pdb_read_numeric_leaf(&record_stream);
                    if(count_numeric_leaf_error){
                        error("Error: %s %s record with type index 0x%x %s.", kind_name, type_or_id, type_index, count_numeric_leaf_error);
                    }
                    
                    char *size_numeric_leaf_error = pdb_read_numeric_leaf(&record_stream);
                    if(size_numeric_leaf_error){
                        error("Error: %s %s record with type index 0x%x %s.", kind_name, type_or_id, type_index, size_numeric_leaf_error);
                    }
                    
                    char *name = msf_read_string(&record_stream);
                    if(!name){
                        error("Error: %s %s record with type index 0x%x contains non-zero terminated name.", kind_name, type_or_id, type_index);
                    }
                    
                    if(dump) print("        %s: %s\n", kind_name, name);
                }break;
                
                case /*LF_ENUM*/0x1507:{
                    char *kind_name = "LF_ENUM";
                    
                    struct{
                        u16 count;
                        u16 properties;
                        u32 underlying_type;
                        u32 field_type;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record.underlying_type >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a underlying type of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.underlying_type, type_index);
                    }
                    
                    if(record.field_type >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a fieldlist of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.field_type, type_index);
                    }
                    
                    char *name = msf_read_string(&record_stream);
                    if(!name){
                        error("Error: %s %s record with type index 0x%x contains non-zero terminated name.", kind_name, type_or_id, type_index);
                    }
                    
                    if(dump) print("        %s: %s\n", kind_name, name);
                }break;
                
                case /*LF_FUNC_ID*/0x1601:{
                    char *kind_name = "LF_FUNC_ID";
                    struct {
                        u32 scope_id;
                        u32 type_id;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record.scope_id >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a scope id of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, record.scope_id, type_index);
                    }
                    
                    // @cleanup check type_id?
                    
                    char *name = msf_read_string(&record_stream);
                    if(!name){
                        error("Error: %s %s record with type index 0x%x contains non-zero terminated name.", kind_name, type_or_id, type_index);
                    }
                    
                    if(dump) print("        %s: %s\n", kind_name, name);
                }break;
                
                case /*LF_BUILDINFO*/0x1603:{
                    char *kind_name = "LF_BUILDINFO";
                    
                    u16 count;
                    if(msf_read_from_stream(&record_stream, &count, sizeof(count))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    u32 *types = msf_read_by_pointer(&record_stream, count * sizeof(u32));
                    if(!types){
                        error("Error: %s %s record with type index 0x%x is too small for the count (%d) it specifies.", kind_name, type_or_id, type_index, count);
                    }
                    
                    for(u32 index = 0; index < count; index++){
                        if(types[index] >= type_index){
                            error("Error: %s %s record with type index 0x%x specifies a substring id of 0x%x at index %u (should be less than 0x%x).", kind_name, type_or_id, type_index, types[index], index, type_index);
                        }
                    }
                    
                }break;
                case /*LF_SUBSTR_LIST*/0x1604:{
                    char *kind_name = "LF_SUBSTR_LIST";
                    
                    u32 count;
                    if(msf_read_from_stream(&record_stream, &count, sizeof(count))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    u32 *types = msf_read_by_pointer(&record_stream, count * sizeof(u32));
                    if(!types){
                        error("Error: %s %s record with type index 0x%x is too small for the count (%d) it specifies.", kind_name, type_or_id, type_index, count);
                    }
                    
                    for(u32 index = 0; index < count; index++){
                        if(types[index] >= type_index){
                            error("Error: %s %s record with type index 0x%x specifies a substring id of 0x%x at index %u (should be less than 0x%x).", kind_name, type_or_id, type_index, types[index], index, type_index);
                        }
                    }
                    
                }break;
                case /*LF_STRING_ID*/0x1605:{
                    char *kind_name = "LF_STRING_ID";
                    u32 substring_list;
                    if(msf_read_from_stream(&record_stream, &substring_list, sizeof(substring_list))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(substring_list >= type_index){
                        error("Error: %s %s record with type index 0x%x specifies a substring list id of 0x%x (should be less than 0x%x).", kind_name, type_or_id, type_index, substring_list, type_index);
                    }
                }break;
                
                
                case /*LF_UDT_SRC_LINE*/0x1606:
                case /*LF_UDT_MOD_SRC_LINE*/0x1607:{
                    
                    char *kind_name = "LF_UDT_SRC_LINE";
                    if(record_kind == 0x1607) kind_name = "LF_UDT_MOD_SRC_LINE";
                    
                    struct{
                        u32 type_index;
                        u32 string_id;
                        u32 line_number;
                    } record;
                    
                    if(msf_read_from_stream(&record_stream, &record, sizeof(record))){
                        error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                    }
                    
                    if(record_kind == 0x1607){
                        u16 mod;
                        if(msf_read_from_stream(&record_stream, &mod, sizeof(mod))){
                            error("Error: %s %s record with type index 0x%x is too small.", kind_name, type_or_id, type_index);
                        }
                    }
                    
                    if(dump) print("        %s\n", kind_name);
                }break;
                
                default:{
                    print("Warning: Unknown type record kind 0x%x is not checked.\n", record_kind);
                }break;
            }
            
            // @cleanup: Check padding?
        }
        
        if(index_stream.offset != index_stream.size){
            error("Error: The %s stream contains more type records than its header specifies.", tpi_or_ipi);
        }
        
        if(index_stream_header.stream_index_of_hash_stream != 0xffff){
            if(index_stream_header.stream_index_of_hash_stream >= streams.amount_of_streams){
                error("Error: The hash stream of the %s stream has an invalid index.", tpi_or_ipi);
            }
            
            struct msf_stream hash_stream = streams.streams[index_stream_header.stream_index_of_hash_stream];
            
            // 
            // Validate the index offset buffer:
            // 
            // The index offset buffer is a set of 'type_index', 'type_record_offset' pairs.
            // These pairs can be used to binary search for the 'type_record_offset' of a 'type_index'.
            // 
            
            if((u64)index_stream_header.index_offset_buffer_offset + (u64)index_stream_header.index_offset_buffer_length > hash_stream.size){
                error("Error: The index offset buffer of the %s stream does not fit inside its hash stream.", tpi_or_ipi);
            }
            
            if((index_stream_header.index_offset_buffer_offset % 4) != 0){
                error("Error: The index offset buffer offset specified in the %s stream has invalid alignment. Expected 4 byte alignment.", tpi_or_ipi);
            }
            
            if((index_stream_header.index_offset_buffer_length % 8) != 0){
                error("Error: The index offset buffer size specified in the %s stream has invalid alignment. Expected 8 byte alignment.", tpi_or_ipi);
            }
            
            // @cleanup: does the first entry have to be the first type index and offset of 0?
            
            struct index_offset_buffer_entry{
                u32 type_index;
                u32 type_record_offset;
            } *index_offset_buffer = (void *)(hash_stream.data + index_stream_header.index_offset_buffer_offset);
            u32 amount_of_index_offset_buffer_entries = index_stream_header.index_offset_buffer_length/sizeof(*index_offset_buffer);
            
            u32 last_type_index = 0;
            
            if(dump) print("\n%s Index Offset Buffer:\n", tpi_or_ipi);
            
            for(u32 index = 0; index < amount_of_index_offset_buffer_entries; index++){
                struct index_offset_buffer_entry entry = index_offset_buffer[index];
                
                if(dump) print("    [%u] type_index: 0x%x, type_record_offset: 0x%x\n", index, entry.type_index, entry.type_record_offset);
                
                if(!(index_stream_header.minimal_type_index <= entry.type_index && entry.type_index < index_stream_header.one_past_last_type_index)){
                    error("Error: Entry %u of the index offset buffer of the %s stream specifies an invalid type index of 0x%x.", index, tpi_or_ipi, entry.type_index);
                }
                
                if(entry.type_record_offset + index_stream_header.header_size != type_index_to_offset_map[entry.type_index]){
                    error("Error: Entry %u of the index offset buffer of the %s stream specifies an incorrect offset of 0x%x, expected 0x%x.", index, tpi_or_ipi, entry.type_record_offset, type_index_to_offset_map[entry.type_index] - index_stream_header.header_size);
                }
                
                if(entry.type_index <= last_type_index){
                    error("Error: The entries in the index offset buffer of the %s stream are not correctly sorted. Entry %u has type index 0x%x, entry %u has type index 0x%x.", tpi_or_ipi, index, entry.type_index, index - 1, last_type_index);
                }
                
                last_type_index = entry.type_index;
            }
            
            // 
            // Validate the hash key buffer:
            // 
            if((u64)index_stream_header.hash_table_index_buffer_offset + (u64)index_stream_header.hash_table_index_buffer_length > hash_stream.size){
                error("Error: The hash key buffer of the %s stream does not fit inside its hash stream.", tpi_or_ipi);
            }
            
            if((u64)index_stream_header.hash_key_size * (u64)(index_stream_header.one_past_last_type_index - index_stream_header.minimal_type_index) != (u64)index_stream_header.hash_table_index_buffer_length){
                error("Error: Expected 'hash_key_size (%u) * number_of_type_indices (%u) == hash_table_index_buffer_length (%u)' in the header of the %s stream.", index_stream_header.hash_key_size, index_stream_header.one_past_last_type_index - index_stream_header.minimal_type_index, index_stream_header.hash_table_index_buffer_length, tpi_or_ipi);
            }
            
            if(!(0x1000 <= index_stream_header.number_of_hash_buckets && index_stream_header.number_of_hash_buckets < 0x40000)){
                error("Error: Invalid amount (0x%x) of hash buckets for %s stream, must be between 0x1000 and 0x40000.", index_stream_header.number_of_hash_buckets, tpi_or_ipi);
            }
            
            struct hash_bucket{
                struct hash_bucket *next;
                u32 type_index;
            } **buckets = calloc(index_stream_header.number_of_hash_buckets, sizeof(*buckets));
            
            u32 *hash_indices = (u32 *)(hash_stream.data + index_stream_header.hash_table_index_buffer_offset);
            for(u32 type_index = index_stream_header.minimal_type_index; type_index < index_stream_header.one_past_last_type_index; type_index++){
                u32 hash_index = hash_indices[type_index - index_stream_header.minimal_type_index];
                
                // The indices are stored, not the hashes.
                if(hash_index >= index_stream_header.number_of_hash_buckets){
                    error("Error: Inside the tpi hash stream, the hash bucket for type index 0x%x is bigger (0x%x) than the number of buckets for the table (0x%x).\n", type_index, hash_index, index_stream_header.number_of_hash_buckets);
                }
                
                // Insert the record in the front.
                struct hash_bucket *bucket = malloc(sizeof(struct hash_bucket));
                bucket->type_index = type_index;
                bucket->next = buckets[hash_index];
                buckets[hash_index] = bucket;
            }
            
            if((u64)index_stream_header.udt_order_adjust_table_offset + (u64)index_stream_header.udt_order_adjust_table_length > hash_stream.size){
                error("Error: The udt order adjust table of the %s stream does not fit inside its hash stream.", tpi_or_ipi);
            }
            
            if(index_stream_header.udt_order_adjust_table_length){
                // 
                // Order adjust table mapping type names (inside the /names stream) to type indices.
                // 
                struct msf_stream order_adjust_table_stream = (struct msf_stream){
                    .data = hash_stream.data + index_stream_header.udt_order_adjust_table_offset,
                    .size = index_stream_header.udt_order_adjust_table_length,
                    .offset = 0,
                };
                
                char *hash_table_name = is_ipi ? "udt order adjust table inside the IPI stream" : "udt order adjust table inside the TPI stream";
                
                struct pdb_hash_table udt_adjust_table = pdb_deserialize_hash_table(&order_adjust_table_stream, hash_table_name);
                
                if(dump) print("\n%s udt order adjust table\n", tpi_or_ipi);
                
                for(u32 index = 0; index < udt_adjust_table.capacity; index++){
                    u32 offset     = udt_adjust_table.data[index].key;
                    u32 type_index = udt_adjust_table.data[index].value;
                    
                    // :pdb_hash_table_empty_and_deleted_slots
                    if(type_index == 0 || type_index == (u32)-1) continue;
                    
                    if(offset >= names_string_buffer_stream.size){
                        error("Error: Entry %u of the %s has invalid string offset in /names 0x%x.", index, hash_table_name, offset);
                    }
                    
                    if((type_index < index_stream_table->minimal_type_index) || (type_index >= index_stream_table->one_past_last_type_index)){
                        error("Error: Entry %u of the %s has invalid type index 0x%x.", index, hash_table_name, type_index);
                    }
                    
                    if(offset && names_string_buffer_stream.data[offset-1] != 0){
                        error("Error: Entry %u of the %s is does not point to the beginning of a string inside /names.", index, hash_table_name);
                    }
                    
                    if(dump) print("    [%u] 0x%x (%s) -> 0x%x\n", index, offset, (char *)names_string_buffer_stream.data + offset, type_index);
                    
                    {   // Make sure the entry maps to itself.
                        
                        for(u32 table_index = 0; table_index < udt_adjust_table.capacity; table_index++){
                            u16 hash_index = (u16)(offset + table_index) % udt_adjust_table.capacity;
                            
                            struct pdb_hash_table_entry entry = udt_adjust_table.data[hash_index];
                            
                            if(entry.value == 0){
                                error("Error: The %s is corrupt. Entry %u does not map to itself.", hash_table_name, index);
                            }
                            
                            if(entry.key == offset) break; // We found it.
                        }
                    }
                    
                    // 
                    // Adjust the hash table order, removing and reinserting 'type_index'.
                    // 
                    u32 hash_index = hash_indices[type_index - index_stream_header.minimal_type_index];
                    
                    struct hash_bucket **prev = &buckets[hash_index];
                    struct hash_bucket *hash_bucket = buckets[hash_index];
                    
                    for(; hash_bucket; prev = &hash_bucket->next, hash_bucket = hash_bucket->next){
                        if(hash_bucket->type_index == type_index) break;
                    }
                    
                    // Move 'hash_bucket' to the start of the list.
                    *prev = hash_bucket->next;
                    hash_bucket->next = buckets[hash_index];
                    buckets[hash_index] = hash_bucket;
                }
            }
            
            if(dump){
                print("\n%s Hash Table:\n", tpi_or_ipi);
                for(u32 bucket_index = 0; bucket_index < index_stream_header.number_of_hash_buckets; bucket_index++){
                    
                    if(buckets[bucket_index]){
                        print("    [%u]", bucket_index);
                        for(struct hash_bucket *bucket = buckets[bucket_index]; bucket; bucket = bucket->next){
                            
                            u32 type_index  = bucket->type_index;
                            u32 type_record = type_index_to_offset_map[type_index];
                            char *name = pdb_type_record__get_name(index_stream.data + type_record);
                            
                            if(*name){
                                print(" 0x%x (%s),", type_index, name);
                            }else{
                                print(" 0x%x,", type_index);
                            }
                        }
                        print("\n");
                    }
                }
            }
            
            // Calculate the hash for each type record and see that we can get the record back.
            for(u32 type_index = index_stream_header.minimal_type_index; type_index < index_stream_header.one_past_last_type_index; type_index++){
                
                struct codeview_type_record_header{
                    u16 length;
                    u16 kind;
                } *type_record_header = (void *)(index_stream.data + type_index_to_offset_map[type_index]);
                
                u8 *type_data = (u8 *)(type_record_header + 1);
                
                char *name = 0;
                size_t length = 0;
                
                switch(type_record_header->kind){
                    case /*LF_ALIAS*/0x150a:{
                        name = (char *)(type_data + 4);
                    }break;
                    
                    case /*LF_CLASS2*/0x1608:
                    case /*LF_INTERFACE2*/0x160b:
                    case /*LF_STRUCTURE2*/0x1609: // @note: These get rid of the 'count' member to get 32-bits of 'properties' but stay the same size.
                    case /*LF_UNION2*/0x160a: // @note: These get rid of the 'count' member to get 32-bits of 'properties' but stay the same size.
                    
                    case /*LF_UNION*/0x1506:
                    case /*LF_ENUM*/0x1507:
                    case /*LF_CLASS*/0x1504:
                    case /*LF_STRUCTURE*/0x1505:
                    case /*LF_INTERFACE*/0x1519:{
                        
                        u32 properties;
                        if(type_record_header->kind < 0x1600){
                            // @note: All of these have the 'properies' field at the same offset.
                            properties = *(u16 *)(type_data + 2);
                        }else{
                            // @note: These dropped the 'count' for 32-bits more of properties.
                            properties = *(u32 *)type_data;
                        }
                        
                        u16 forward_ref = (properties & (1 << 7));
                        u16 scoped      = (properties & (1 << 8));
                        u16 has_unique_name = (properties & (1 << 9));
                        
                        char *tag_name = pdb_type_record__get_name((u8 *)type_record_header);
                        
                        // @note: This only works for c. for c++ they also search for 'foo::<unnamed-tag>' stuff.
                        int anonymous = (strcmp(tag_name, "<unnamed-tag>") == 0) || (strcmp(tag_name, "__unnamed") == 0);
                        
                        if(!forward_ref && !anonymous){
                            if(!scoped){
                                name = tag_name;
                            }else if(has_unique_name){
                                name = tag_name + strlen(tag_name) + 1;
                            }
                        }
                    }break;
                    
                    case /*LF_UDT_SRC_LINE*/0x1606:
                    case /*LF_UDT_MOD_SRC_LINE*/0x1607:{
                        name   = (char *)type_data;
                        length = sizeof(type_index);
                    }break;
                }
                
                u32 hash_index;
                if(name){
                    if(!length) length = strlen(name);
                    hash_index = pdb_hash_index((u8 *)name, length, index_stream_header.number_of_hash_buckets);
                }else{
                    hash_index = crc32(/*initial_crc*/0, (u8 *)type_record_header, type_record_header->length + sizeof(type_record_header->length)) % index_stream_header.number_of_hash_buckets;
                }
                
                if(hash_index != hash_indices[type_index - index_stream_header.minimal_type_index]){
                    error("Error: The hash index buffer entry for type index 0x%x inside the %s hash stream is incorrect. Expected 0x%x got 0x%x\n", type_index, tpi_or_ipi, hash_index, hash_indices[type_index - index_stream_header.minimal_type_index]);
                }
            }
        }
    }
    
    if(dump) print("\nDBI Stream:\n");
    
    // The DBI stream is always present, but can be empty Type Server PDB's.
    // Type server PDB's only have:
    //      1) PDB Information stream 
    //      2) TPI stream
    //      3) Empty DBI
    //      4) IPI stream
    //      5) TPI symbol index stream
    //      6) IPI symbol index stream
    //      7) /names stream
    // All of which we have validated previously. Hence, we are done.
    if(dbi_stream.size == 0){
        if(dump) print("    DBI Stream is empty\n");
        return;
    }
    
    struct msf_stream global_symbol_index_stream = {0};
    struct msf_stream public_symbol_index_stream = {0};
    struct msf_stream symbol_record_stream       = {0};
    
    struct pdb_section_table section_table = {0};
    
    struct dbi_stream_header{
        u32 version_signature;
        u32 version;
        u32 age;
        u16 stream_index_of_the_global_symbol_index_stream;
        struct{
            u16 minor_version : 8;
            u16 major_version : 7;
            u16 is_new_version_format : 1;
        } toolchain_version;
        u16 stream_index_of_the_public_symbol_index_stream;
        u16 version_number_of_mspdb;
        u16 stream_index_of_the_symbol_record_stream;
        u16 rbld_version_number_of_mspdb;
        
        u32 byte_size_of_the_module_info_substream;           // substream 0
        u32 byte_size_of_the_section_contribution_substream;  // substream 1
        u32 byte_size_of_the_section_map_substream;           // substream 2
        u32 byte_size_of_the_source_info_substream;           // substream 3
        u32 byte_size_of_the_type_server_map_substream;       // substream 4
        
        // (MFC = Microsoft Foundation Class?)
        u32 index_of_the_MFC_type_server_in_the_type_server_map_substream;
        
        u32 byte_size_of_the_optional_debug_header_substream; // substream 6
        u32 byte_size_of_the_edit_and_continue_substream;     // substream 5
        
        struct{
            u16 was_linked_incrementally    : 1;
            u16 private_data_is_stripped    : 1;
            u16 the_pdb_uses_conflict_types : 1; // undocumented /DEBUG:CTYPES flag.
            u16 unused : 13;
        } flags;
        
        u16 machine_type; // (0x8664)
        
        u32 reserved_padding;
    } dbi_stream_header;
    
    if(msf_read_from_stream(&dbi_stream, &dbi_stream_header, sizeof(dbi_stream_header))){
        error("Error: The DBI stream (stream index 3) is too small for its header.");
    }
    
    if(dump){
        print("    version_signature %d\n", (s32)dbi_stream_header.version_signature);
        print("    version %u\n", dbi_stream_header.version);
        print("    age %u\n", dbi_stream_header.age);
        print("    global symbol index stream %hu\n", dbi_stream_header.stream_index_of_the_global_symbol_index_stream);
        print("    public symbol index stream %hu\n", dbi_stream_header.stream_index_of_the_public_symbol_index_stream);
        print("    was linked incrementally %hu\n", dbi_stream_header.flags.was_linked_incrementally);
        print("    private data is stripped %hu\n", dbi_stream_header.flags.private_data_is_stripped);
        print("    contains conflict types  %hu\n", dbi_stream_header.flags.the_pdb_uses_conflict_types);
        print("    machine type  0x%hx\n", dbi_stream_header.machine_type);
        print("    toolchain is new version format %hu\n", dbi_stream_header.toolchain_version.is_new_version_format);
        print("    toolchain major version %hu\n", dbi_stream_header.toolchain_version.major_version);
        print("    toolchain minor version %hu\n", dbi_stream_header.toolchain_version.minor_version);
        print("    version of mspdb %hu\n", dbi_stream_header.version_number_of_mspdb);
        print("    build number of mspdb %hu\n", dbi_stream_header.rbld_version_number_of_mspdb);
    }
    
    if(dbi_stream_header.version_signature != (u32)-1){
        error("Error: DBI stream version signature is not -1.");
    }
    
    if(dbi_stream_header.version != 19990903){
        error("Error: DBI stream wrong version (%u), expected '19990903'.", dbi_stream_header.version);
    }
    
    // @note: We could check here that the age of the DBI stream does not exceed the age of the PDB, 
    //        but I don't think it matters.
    //        We also don't check all the versions for now...
    
    if(!dbi_stream_header.toolchain_version.is_new_version_format){
        error("Internal Error: DBI stream toolchain version does not have the 'is_new_version_format' bit set, this is not supported.");
    }
    
    if(dbi_stream_header.flags.unused){
        print("Warning: The 'unused' portion of the 'flags' inside the DBI stream header is set (0x%x)\n", dbi_stream_header.flags.unused);
    }
    
    if(msf_stream_by_index(&streams, &public_symbol_index_stream, dbi_stream_header.stream_index_of_the_public_symbol_index_stream)){
        error("Error: The DBI stream specifies an invalid stream index for the public symbol hash stream.");
    }
    
    if(msf_stream_by_index(&streams, &global_symbol_index_stream, dbi_stream_header.stream_index_of_the_global_symbol_index_stream)){
        error("Error: The DBI stream specifies an invalid stream index for the global symbol hash stream.");
    }
    
    if(msf_stream_by_index(&streams, &symbol_record_stream, dbi_stream_header.stream_index_of_the_symbol_record_stream)){
        error("Error: The DBI stream specifies an invalid stream index for the symbol record stream.");
    }
    
    // 
    // Extract all of the substreams in order.
    // 
    struct msf_stream module_info_substream          = {0};
    struct msf_stream section_contribution_substream = {0};
    struct msf_stream section_map_substream          = {0};
    struct msf_stream source_info_substream          = {0};
    struct msf_stream type_server_map_substream      = {0};
    struct msf_stream edit_and_continue_substream    = {0};
    struct msf_stream debug_header_substream         = {0};
    
    if(msf_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_module_info_substream, &module_info_substream)){
        error("Error: The module info substream does not fit inside the DBI stream.");
    }
    
    if(msf_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_section_contribution_substream, &section_contribution_substream)){
        error("Error: The section contribution substream does not fit inside the DBI stream.");
    }
    
    if(msf_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_section_map_substream, &section_map_substream)){
        error("Error: The section map substream does not fit inside the DBI stream.");
    }
    
    if(msf_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_source_info_substream, &source_info_substream)){
        error("Error: The source info substream does not fit inside the DBI stream.");
    }
    
    if(msf_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_type_server_map_substream, &type_server_map_substream)){
        error("Error: The type server map substream does not fit inside the DBI stream.");
    }
    
    if(msf_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_edit_and_continue_substream, &edit_and_continue_substream)){
        error("Error: The edit and continue substream does not fit inside the DBI stream.");
    }
    
    if(msf_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_optional_debug_header_substream, &debug_header_substream)){
        error("Error: The optional debug header substream does not fit inside the DBI stream.");
    }
    
    //
    // Validate all the substreams!
    // We do this in a different order then they are layed out on the disk.
    // We start with the 'optional_debug_header_substream' as it gives us
    // the section header dump stream, which in turn specified the amount sections
    // which are present in the .exe.
    // This mapping then defines the section_id used throughout the pdb.
    //
    
    struct{
        // An array of 'FPO_DATA'
        u16 fpo_data_stream_index;
        
        // An array of 'IMAGE_FUNCTION_ENTRY'
        u16 exception_data_stream_index;
        
        // An array of 'XFIXUP_DATA' (see cvinfo.h)
        u16 fixup_data_stream_index;
        
        // Arrays of 'OMAP_DATA'
        u16 omap_to_src_data_stream_index;
        u16 omap_from_src_data_stream_index;
        
        // An array of 'IMAGE_SECTION_HEADER'
        u16 section_header_dump_stream_index;
        
        // An array of 'ULONG'
        u16 clr_token_to_clr_record_id_map_stream_index;
        
        // The contents of the '.xdata' section
        u16 xdata_dump_stream_index;
        
        // The contents of the '.pdata' section
        u16 pdata_dump_stream_index;
        
        // An array of 'FRAMEDATA' (see cvinfo.h)
        u16 new_fpo_data_stream_index;
        
        // An array of 'IMAGE_SECTION_HEADER' (before fixups (?))
        u16 original_section_header_dump_stream_index;
        
        // @note: They might have introduced more optional streams since the repository was released.
    } optional_debug_headers;
    
    // @cleanup: Allow a smaller optional debug header?
    if(msf_read_from_stream(&debug_header_substream, &optional_debug_headers, sizeof(optional_debug_headers))){
        error("Error: The debug header substream of the DBI stream is the incorrect size.");
    }
    
    if(dump){
        print("\nOptional Debug Headers:\n");
        print("    FPO_DATA                      %hd\n", (s16)optional_debug_headers.fpo_data_stream_index);
        print("    IMAGE_FUNCTION_ENTRY          %hd\n", (s16)optional_debug_headers.exception_data_stream_index);
        print("    XFIXUP_DATA                   %hd\n", (s16)optional_debug_headers.fixup_data_stream_index);
        print("    OMAP_DATA to src              %hd\n", (s16)optional_debug_headers.omap_to_src_data_stream_index);
        print("    OMAP_DATA from src            %hd\n", (s16)optional_debug_headers.omap_from_src_data_stream_index);
        print("    IMAGE_SECTION_HEADER          %hd\n", (s16)optional_debug_headers.section_header_dump_stream_index);
        print("    CLR token to CLR record id    %hd\n", (s16)optional_debug_headers.clr_token_to_clr_record_id_map_stream_index);
        print("    xdata                         %hd\n", (s16)optional_debug_headers.xdata_dump_stream_index);
        print("    pdata                         %hd\n", (s16)optional_debug_headers.pdata_dump_stream_index);
        print("    FRAMEDATA                     %hd\n", (s16)optional_debug_headers.new_fpo_data_stream_index);
        print("    Original IMAGE_SECTION_HEADER %hd\n", (s16)optional_debug_headers.original_section_header_dump_stream_index);
    }
    
    struct msf_stream fpo_data = {0};
    struct msf_stream exception_data = {0};
    struct msf_stream fixup_data = {0};
    struct msf_stream omap_to_src_data = {0};
    struct msf_stream omap_from_src_data = {0};
    struct msf_stream section_header_dump = {0};
    struct msf_stream clr_token_to_clr_record_id_map = {0};
    struct msf_stream xdata_dump = {0};
    struct msf_stream pdata_dump = {0};
    struct msf_stream new_fpo_data = {0};
    struct msf_stream original_section_header_dump = {0};
    
    if(msf_stream_by_index(&streams, &fpo_data, optional_debug_headers.fpo_data_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the 'FPO_DATA'.", optional_debug_headers.fpo_data_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &exception_data, optional_debug_headers.exception_data_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the exception data.", optional_debug_headers.exception_data_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &fixup_data, optional_debug_headers.fixup_data_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the 'XFIXUP_DATA'.", optional_debug_headers.fixup_data_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &omap_to_src_data, optional_debug_headers.omap_to_src_data_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the omap to src data.", optional_debug_headers.omap_to_src_data_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &omap_from_src_data, optional_debug_headers.omap_from_src_data_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the omap from src data.", optional_debug_headers.omap_from_src_data_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &section_header_dump, optional_debug_headers.section_header_dump_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the section table copy.", optional_debug_headers.section_header_dump_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &clr_token_to_clr_record_id_map, optional_debug_headers.clr_token_to_clr_record_id_map_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the clr token to clr record id map.", optional_debug_headers.clr_token_to_clr_record_id_map_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &xdata_dump, optional_debug_headers.xdata_dump_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the .xdata copy.", optional_debug_headers.xdata_dump_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &pdata_dump, optional_debug_headers.pdata_dump_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the .pdata copy.", optional_debug_headers.pdata_dump_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &new_fpo_data, optional_debug_headers.new_fpo_data_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the 'FRAMEDATA'.", optional_debug_headers.new_fpo_data_stream_index);
    }
    
    if(msf_stream_by_index(&streams, &original_section_header_dump, optional_debug_headers.original_section_header_dump_stream_index)){
        error("Error: The debug header stream specifies an invalid stream index 0x%hx for the original section table stream.", optional_debug_headers.original_section_header_dump_stream_index);
    }
    
    if(section_header_dump.size == 0){
        error(
                "Error: The debug header stream does not specify a section table dump stream.\n"
                "       This stream is technically optional, but always present and required\n"
                "       for the PDB to translate \"section_id+offset\" to \"relative virtual address\".\n"
                );
    }
    
    if(section_header_dump.size % sizeof(struct pdb_image_section_header)){
        error("Error: The size of the section header dump stream is not a multiple of the size of an 'IMAGE_SECTION_HEADER'.");
    }
    
    section_table.data = (void *)section_header_dump.data;
    section_table.size = section_header_dump.size / sizeof(struct pdb_image_section_header);
    
    if(optional_debug_headers.fpo_data_stream_index != 0xffff) print("Warning: FPO_DATA debug header stream present, but validation not implemented.\n");
    if(optional_debug_headers.exception_data_stream_index != 0xffff) print("Warning: Deprecated \"Exception Data\" (IMAGE_RUNTIME_FUNCTION) debug header stream present, but validation not implemented.\n");
    if(optional_debug_headers.fixup_data_stream_index != 0xffff) print("Warning: XFIXUP_DATA debug header stream present, but validation not implemented.\n");
    if(optional_debug_headers.omap_to_src_data_stream_index != 0xffff) print("Warning: OMAP to src debug header stream present, but validation not implemented.\n");
    if(optional_debug_headers.omap_from_src_data_stream_index != 0xffff) print("Warning: OMAP from src debug header stream present, but validation not implemented.\n");
    
    if(optional_debug_headers.clr_token_to_clr_record_id_map_stream_index != 0xffff) print("Warning: CLR token to CLR record id debug header stream present, but validation not implemented.\n");
    
    // @cleanup: Maybe implement validation for these? They are used somewhat often. (/DEBUGTYPE:PDATA)
    if(optional_debug_headers.xdata_dump_stream_index != 0xffff) print("Warning: .xdata debug header stream present, but validation not implemented.\n");
    if(optional_debug_headers.pdata_dump_stream_index != 0xffff) print("Warning: .pdata debug header stream present, but validation not implemented.\n");
    
    if(optional_debug_headers.new_fpo_data_stream_index != 0xffff) print("Warning: FRAMEDATA debug header stream present, but validation not implemented.\n");
    if(optional_debug_headers.original_section_header_dump_stream_index != 0xffff) print("Warning: Original IMAGE_SECTION_HEADER debug header stream present, but validation not implemented.\n");
    
    
    // Source information substream:
    // 
    // The source information substream contains the file names of the files used by each module.
    // It has the following layout:
    // 
    //    u16 amount_of_modules;
    //    u16 truncated_amount_of_source_files;
    //    u16 truncated_amount_of_file_base_per_module[amount_of_modules];
    //    u16 amount_of_source_files_per_module[amount_of_modules];
    //    u32 source_file_name_offset_in_the_name_buffer[amount_of_source_files];
    //    char name_buffer[];
    //    
    // The 'truncated_amount_of_source_files' is not used anymore as this would limit a program to
    // only use 65536 of source files. Instead the real 'amount_of_source_files' should be calculated
    // by iterating the 'amount_of_source_files_per_module' array.
    // Similarly, the 'truncated_amount_of_file_base_per_module' array was supposed to speed up searching
    // the 'source_file_name_offset_in_name_buffer' array, by allowing for 'base + file_name_index in module'
    // lookup, but if the file name count is bigger than 65536 this mapping does not work anymore.
    // 
    // The 'amount_of_modules' is still valid and will remain until module indices used throughout the file
    // are switched to being 32-bits.
    // 
    
    if(dump) print("\nSource Information Substream:\n");
    
    u16 amount_of_modules;
    u16 truncated_amount_of_source_files;
    if(msf_read_from_stream(&source_info_substream, &amount_of_modules, sizeof(amount_of_modules)) || msf_read_from_stream(&source_info_substream, &truncated_amount_of_source_files, sizeof(truncated_amount_of_source_files))){
        error("Error: The source info substream of the DBI stream is smaller than 4 bytes.");
    }
    
    if(dump) print("    amount of modules: %hu\n", amount_of_modules);
    if(dump) print("    amount of source files: %hu (truncated to u16)\n", truncated_amount_of_source_files);
    
    u16 *truncated_file_base_per_module    = msf_read_by_pointer(&source_info_substream, amount_of_modules * sizeof(u16));
    u16 *amount_of_source_files_per_module = msf_read_by_pointer(&source_info_substream, amount_of_modules * sizeof(u16));
    if(!truncated_file_base_per_module || !amount_of_source_files_per_module){
        error("Error: The source info substream of the DBI stream is too small based of the 'amount_of_modules' (%hu) specified.", amount_of_modules);
    }
    
    if(dump) print("    Source information per module:\n");
    
    // @note: There is a maximum of '0xffff' modules. Each module has at most '0xffff' source files, 
    //        hence there are at most '0xfffe0001 < 0xffffffff' source files.
    u32 amount_of_source_files = 0;
    for(u16 module_index = 0; module_index < amount_of_modules; module_index++){
        
        if(truncated_file_base_per_module[module_index] != (u16)amount_of_source_files){
            error("Error: The first array contained in the source info substream should contain a truncated accumulated amount of source files. This is untrue for module %hu: Array specifies %hu, but (u16)source_file_base = %hu.", module_index, truncated_file_base_per_module[module_index], (u16)amount_of_source_files);
        }
        
        if(dump) print("        [%hu] \"base\" %hu (%u truncated to u16), file count %hu\n", module_index, truncated_file_base_per_module[module_index], amount_of_source_files, amount_of_source_files_per_module[module_index]);
        
        amount_of_source_files += amount_of_source_files_per_module[module_index];
    }
    
    if(dump) print("    Calculated amount of source files: %u\n", amount_of_source_files);
    
    if((u16)amount_of_source_files != truncated_amount_of_source_files){
        error("Error: The truncated amount of source files inside the source info substream of the DBI stream is incorrect. Have %hu but expected %hu.\n", truncated_amount_of_source_files, (u16)amount_of_source_files);
    }
    
    u32 *source_file_name_offset_in_the_name_buffer = msf_read_by_pointer(&source_info_substream, (u64)amount_of_source_files * sizeof(u32));
    if(!source_file_name_offset_in_the_name_buffer){
        error("Error: The source info substream is too small to contain the array specifying the file name offset for each file.");
    }
    
    if(dump) print("    Source files:\n");
    
    // @cleanup: Maybe make this less manual?
    struct msf_stream source_file_name_buffer = {.data = source_info_substream.data + source_info_substream.offset, .size = source_info_substream.size - source_info_substream.offset };
    
    for(u32 source_file_index = 0; source_file_index < amount_of_source_files; source_file_index++){
        u32 file_name_offset = source_file_name_offset_in_the_name_buffer[source_file_index];
        
        if(file_name_offset >= source_file_name_buffer.size){
            error("Entry %u in the source file offset array inside the soure info substream of the DBI stream is invalid. Entry 0x%x, name buffer size 0x%x.\n", source_file_index, file_name_offset, source_file_name_buffer.size);
        }
        
        char *string_buffer_end = (char *)(source_file_name_buffer.data + source_file_name_buffer.size);
        
        char *string = (char *)(source_file_name_buffer.data + file_name_offset);
        char *end    = string;
        
        while((end < string_buffer_end) && *end) end++;
        
        if(end == string_buffer_end){
            error("Entry %u (%.*s) of the file name offset array inside the source info substream points to non-zero-terminated string at the end of the file name buffer.", source_file_index, end - string, string);
        }
        
        // Check that the byte before is actually a NULL-byte.
        if(file_name_offset > 0 && source_file_name_buffer.data[file_name_offset-1] != 0){
            error("Entry %u (%s) in the source file offset array inside the soure info substream of the DBI stream does not point to the start of a string inside the name buffer.\n", source_file_index, string);
        }
        
        if(dump) print("        [%u] 0x%x (%s)\n", source_file_index, file_name_offset, string);
    }
    
    // Section Contribution Substream:
    //
    // The section contribution substream contains a u32-version followed by
    // an array of either 'pdb_section_contribution' or 'pdb_section_contribution_v2'.
    // These section_contributions define a link between modules and sections.
    //
    
    u32 section_contribution_version;
    if(msf_read_from_stream(&section_contribution_substream, &section_contribution_version, sizeof(section_contribution_version))){
        error("Error: The section contribution substream inside the DBI stream is too small to contain its version number.");
    }
    
    u32 section_contribution_entry_size = 0;
    if(section_contribution_version == /* V1 */(0xeffe0000 + 19970605)){
        section_contribution_entry_size = sizeof(struct pdb_section_contribution);
    }else if(section_contribution_version == /* V2 */0xeffe0000 + 20140516){
        section_contribution_entry_size = sizeof(struct pdb_section_contribution_v2);
    }else{
        error("Error: Unknown version of the section contribution substream of the DBI stream. Expected V1 (0xeffe0000 + 19970605) or V2 (0xeffe0000 + 20140516), but got (0xeffe0000 + %u).", section_contribution_version - 0xeffe0000);
    }
    
    int section_contribution_is_v2 = (section_contribution_version == /* V2 */0xeffe0000 + 20140516);
    if(section_contribution_is_v2 != is_fastlink_pdb){
        print("Warning: The section contribution substream inside the DBI stream uses Version %d but the PDB is %sa /DEBUG:FASTLINK PDB.\n", 1 + section_contribution_is_v2, is_fastlink_pdb ? "" : "NOT ");
    }
    
    u32 bytes_of_section_contribution_entries = (dbi_stream_header.byte_size_of_the_section_contribution_substream - 4);
    if(bytes_of_section_contribution_entries % section_contribution_entry_size){
        error("Error: The size of the section contribution substream minus 4 bytes for the version number (0x%x) inside of the DBI stream is not a multiple of the size of a section contribution structure (0x%x) (version %d).", bytes_of_section_contribution_entries, section_contribution_entry_size, 1 + section_contribution_is_v2);
    }
    
    u32 amount_of_section_contributions = bytes_of_section_contribution_entries / section_contribution_entry_size;
    
    // 
    // Iterate all of the section contributions to make sure they make sense based on the section table
    // and to make sure they are sorted correctly.
    // 
    
    struct pdb_section_contribution_v2 last_section_contribution = {
        .section_id = -1,
        .size = -1,
        .module_index = -1,
    };
    
    struct pdb_section_contribution *first_code_contributions = calloc(sizeof(struct pdb_section_contribution), amount_of_modules);
    for(u32 module_index = 0; module_index < amount_of_modules; module_index++){
        first_code_contributions[module_index].section_id = -1;
        first_code_contributions[module_index].size = -1;
        first_code_contributions[module_index].module_index = -1;
    }
    
    if(dump) print("\nSection Contribution Version 0xeffe0000 + %u (V%d):\n", section_contribution_version - 0xeffe0000, 1 + section_contribution_is_v2);
    for(u32 section_contribution_index = 0; section_contribution_index < amount_of_section_contributions; section_contribution_index++){
        
        // @Warning: The 'segment_id_in_object_file' is uninitialized, if the contribution is v1.
        // @cleanup: Care about this value?
        struct pdb_section_contribution_v2 contribution; 
        msf_read_from_stream(&section_contribution_substream, &contribution, section_contribution_entry_size);
        
        char *section_id_offset_error = pdb_check_section_id_offset(&section_table, contribution.section_id, contribution.offset, contribution.size);
        if(section_id_offset_error){
            error("Error: Section Contribution Entry %u inside the DBI stream %s.", section_contribution_index, section_id_offset_error);
        }
        
        if(last_section_contribution.section_id > contribution.section_id){
            error("Error: The section contributions inside the DBI stream are not sorted by section:offest. Entry %u has section_id %hd while entry %u has section_id %hd.\n", section_contribution_index-1, last_section_contribution.section_id, section_contribution_index, contribution.section_id);
        }
        
        if(last_section_contribution.section_id == contribution.section_id){
            // If there was not a change in the section_id, make sure they are in ascending order in terms of offset and are not overlapping.
            
            if(last_section_contribution.offset > contribution.offset){
                error("Error: The section contributions are not sorted in terms of section:offset. Entry %u has offset 0x%x while entry %u has offset 0x%x", section_contribution_index-1, last_section_contribution.offset, section_contribution_index, contribution.offset);
            }
            
            if(last_section_contribution.offset + last_section_contribution.size > contribution.offset){
                error("Error: The section contributions are overlapping. Entry %u has range [0x%x, 0x%x) while entry %u has offset 0x%x", section_contribution_index-1, last_section_contribution.offset, last_section_contribution.size, section_contribution_index, contribution.offset);
            }
        }
        
        if(contribution.module_index >= amount_of_modules){
            error("Error: Section contribution entry %u inside of the DBI stream specifies invalid module index %hd.", section_contribution_index, contribution.module_index);
        }
        
        if((contribution.characteristics & /*IMAGE_SCN_CNT_CODE*/0x20) && first_code_contributions[contribution.module_index].section_id == -1){
            first_code_contributions[contribution.module_index] = contribution.base;
        }
        
        if(dump){
            print("    [%u] = 0x%hx (%.8s), 0x%x, 0x%x, 0x%x, 0x%hx, 0x%x, 0x%x\n", section_contribution_index, contribution.section_id, section_table.data[contribution.section_id-1].name, contribution.offset, contribution.size, contribution.characteristics, contribution.module_index, contribution.data_crc, contribution.reloc_crc);
        }
        
        last_section_contribution = contribution;
    }
    
    {
        // Section Map Substream:
        // 
        // This substream is sort of useless, it starts with:
        //     u16 number_of_section_descriptors;
        //     u16 number_of_logical_section_descriptors;
        // Followed by an array of 'pdb_section_map_entry'.
        // In practice, both u16 are always 'number_of_sections + 1'.
        // And the array also has that many entries.
        
        struct pdb_section_map_stream_header{
            u16 number_of_section_descriptors;
            u16 number_of_logical_section_descriptors;
        } header;
        
        if(msf_read_from_stream(&section_map_substream, &header, sizeof(header))){
            error("Error: The section map substream of the DBI stream is smaller than 4 bytes.");
        }
        
#if STRICT
        u64 table_size = section_table.size + 1;
        
        if(header.number_of_section_descriptors != table_size){
            error("Error: Section map substream has unexpected section description count. Expected amount_of_sections + 1 = %u.", table_size);
        }
        
        if(header.number_of_logical_section_descriptors != table_size){
            error("Error: Section map substream has unexpected logical section description count. Expected amount_of_sections + 1 = %u.", table_size);
        }
        
        struct pdb_section_map_entry{
            u16 flags;
            u16 logical_overlay_number;
            u16 group;
            u16 frame;
            u16 section_name;
            u16 class_name;
            u32 offset;
            u32 section_size;
        } *map = msf_read_by_pointer(&section_map_substream, sizeof(struct pdb_section_map_entry) * table_size);
        
        if(!map || section_map_substream.offset != section_map_substream.size){
            error("Error: Section map substream has unexpected size.");
        }
        
        // Test all but the last entry of the map.
        for(u64 section_index = 0; section_index < table_size-1; section_index++){
            struct pdb_section_map_entry entry = map[section_index];
            
            if(entry.frame != section_index + 1){
                error("Error: Expected section map entry %d to have frame index %d, but has %d.", section_index, section_index + 1, entry.frame);
            }
            
            if(section_table.data[section_index].virtual_size != entry.section_size){
                error("Error: Section map entry %d has invalid section size. Got 0x%x but section is 0x%x.", section_index, entry.section_size, section_table.data[section_index].virtual_size); 
            }
        }
#endif
    }
    
    // Edit and Continue substream:
    // 
    // The edit and continue substream is a copy of the /names stream, 
    // but instead of being a "universal" string table, it is only used 
    // to contain the strings for 'edit_and_continue_source_file_string_index'
    // and 'edit_and_continue_pdb_file_string_index' inside the 'pdb_module_information'
    // structure of the module information substream.
    // 
    
    struct msf_stream edit_and_continue_string_buffer = validate_string_table_stream(edit_and_continue_substream, "edit and continue", dump);
    
    if(type_server_map_substream.size){
        print("Warning: The type server substream inside the DBI stream is not empty, but validation is not supported.\n");
    }else if(dbi_stream_header.index_of_the_MFC_type_server_in_the_type_server_map_substream){
        print("Warning: The type server substream inside of the DBI stream is empty, but the MFC (Microsoft Foundation Class?) type server index is set.\n");
    }
    
    //
    // Parse the module information substream.
    //
    // It contains a 'pdb_module_information' structure for each module.
    // Most importantly, this specifies the 'module_symbol_stream_index' for each module.
    // A module is just a compilation unit/an .obj.
    //
    
    if((module_info_substream.size & 3) != 0){
        error("Error: The size (0x%x) of the module information substream has invalid alignment, expected 4-byte alignment.", module_info_substream.size);
    }
    
    struct module{
        char *name;
        struct msf_stream global_reference_substream;
        struct msf_stream module_symbol_stream;
        struct{
            u32 *data;
            u64 size;
        } symbol_offsets;
    } *modules = calloc(sizeof(*modules), amount_of_modules);
    
    for(u32 module_index = 0; module_info_substream.offset < module_info_substream.size; module_index++){
        
        if(module_index >= amount_of_modules){
            error("Error: The module information substream contains more modules than specified in the source information substream.");
        }
        
        struct pdb_module_information{
            
            u32 ignored1;
            
            // A module can have multiple section contributions so it is not clear why the first one is in here.
            struct pdb_section_contribution first_code_contribution;
            
            struct{
                u16 was_written : 1;
                u16 edit_and_continue_enabled : 1;
                u16 : 6;
                u16 TSM_index : 8;
            } flags;
            
            u16 module_symbol_stream_index;
            
            u32 byte_size_of_symbol_information;
            u32 byte_size_of_c11_line_information;
            u32 byte_size_of_c13_line_information;
            u16 amount_of_source_files;
            
            u16 padding;
            u32 ignored2;
            
            u32 edit_and_continue_source_file_string_index;
            u32 edit_and_continue_pdb_file_string_index;
            
            // char module_name[];
            // char object_file_name[];
        } module_information;
        
        if(msf_read_from_stream(&module_info_substream, &module_information, sizeof(module_information))){
            error("Error: The module info substream inside of the DBI stream is malformed.");
        }
        
        char *module_name      = msf_read_string(&module_info_substream);
        char *object_file_name = msf_read_string(&module_info_substream);
        if(!module_name || !object_file_name){
            error("Error: Module %u inside the module information substream has an invalid module- or object file name.", module_index);
        }
        
        if(dump){
            print("\nModule %u (%s):\n", module_index, module_name);
            print("    flags: {written: %hu, EnC: %hu, TSM: %hu}\n", module_information.flags.was_written, module_information.flags.edit_and_continue_enabled, module_information.flags.TSM_index);
            print("    module symbol stream index: %hu\n", module_information.module_symbol_stream_index);
            print("    symbol information size: 0x%x\n", module_information.byte_size_of_symbol_information);
            print("    c11 line information size: 0x%x\n", module_information.byte_size_of_c11_line_information);
            print("    c13 line information size: 0x%x\n", module_information.byte_size_of_c13_line_information);
            print("    amount of source files: %hu\n", module_information.amount_of_source_files);
            print("    edit and continue source file string index: %u\n", module_information.edit_and_continue_source_file_string_index);
            print("    edit and continue pdb file string index: %u\n", module_information.edit_and_continue_pdb_file_string_index);
            print("    module name: %s\n", module_name);
            print("    object file name: %s\n", object_file_name);
        }
        
        modules[module_index].name = module_name;
        
#if STRICT
        if(memcmp(&first_code_contributions[module_index], &module_information.first_code_contribution, sizeof(struct pdb_section_contribution)) != 0){
            error("Error: Module '%s' (index %u) inside the module information substream has incorrect first section contribution entry in its module information structure. Got {0x%hx, 0x%x, 0x%x, 0x%x, 0x%hx, 0x%x, 0x%x} expected {0x%hx, 0x%x, 0x%x, 0x%x, 0x%hx, 0x%x, 0x%x}.", module_name, module_index, module_information.first_code_contribution.section_id, module_information.first_code_contribution.offset, module_information.first_code_contribution.size, module_information.first_code_contribution.characteristics, module_information.first_code_contribution.module_index, module_information.first_code_contribution.data_crc, module_information.first_code_contribution.reloc_crc, first_code_contributions[module_index].section_id, first_code_contributions[module_index].offset, first_code_contributions[module_index].size, first_code_contributions[module_index].characteristics, first_code_contributions[module_index].module_index, first_code_contributions[module_index].data_crc, first_code_contributions[module_index].reloc_crc);
        }
#endif
        
        if(module_information.amount_of_source_files != amount_of_source_files_per_module[module_index]){
            error("Error: Module '%s' (index %u) inside the module information substream has incorrect amount of source files entry in its module information structure. Based on structure %hu vs. based on file information substream %hu.", module_name, module_index, module_information.amount_of_source_files, amount_of_source_files_per_module[module_index]);
        }
        
        if(module_information.edit_and_continue_source_file_string_index){
            if(module_information.edit_and_continue_source_file_string_index >= edit_and_continue_string_buffer.size || edit_and_continue_string_buffer.data[module_information.edit_and_continue_source_file_string_index-1] != 0){
                error("Error: Module '%s' (index %u) inside the module information substream specifies invalid 'edit_and_continue_source_file_index' (0x%x) .", module_name, module_index, module_information.edit_and_continue_source_file_string_index);
            }
        }
        
        if(module_information.edit_and_continue_pdb_file_string_index){
            if(module_information.edit_and_continue_pdb_file_string_index >= edit_and_continue_string_buffer.size || edit_and_continue_string_buffer.data[module_information.edit_and_continue_pdb_file_string_index-1] != 0){
                error("Error: Module '%s' (index %u) inside the module information substream specifies invalid 'edit_and_continue_pdb_file_string_index' (0x%x) .", module_name, module_index, module_information.edit_and_continue_pdb_file_string_index);
            }
        }
        
        // Align the stream.
        module_info_substream.offset = (module_info_substream.offset + 3) & ~3;
        
        if(module_info_substream.offset >= module_info_substream.size && (module_index + 1) != amount_of_modules){
            error("Error: The module information substream contains less modules (%u) than specified in the source information substream (%hu).", module_index + 1, amount_of_modules);
        }
        
        if(module_information.module_symbol_stream_index == 0xffff) continue;
        
        // Module symbol stream:
        // 
        // The module symbol stream contains the _private_ symbols for the module.
        // It has 4 sections:
        // 
        //    1) The symbol information   (size given by header)
        //    2) The c11 line information (size given by header)
        //    3) The c13 line information (size given by header)
        //    4) The global references    (size given by first u32; for more information on this see the validation of the far below).
        //    
        // We currently do not support c11 line information as it is not used anymore.
        
        struct msf_stream module_symbol_stream = {0};
        if(msf_stream_by_index(&streams, &module_symbol_stream, module_information.module_symbol_stream_index)){
            error("Error: Module '%s' (index %u) has an invalid module symbol stream index.", module_name, module_index);
        }
        
        struct msf_stream symbol_information   = {0};
        struct msf_stream c11_line_information = {0};
        struct msf_stream c13_line_information = {0};
        
        if(msf_substream(&module_symbol_stream, module_information.byte_size_of_symbol_information, &symbol_information)){
            error("Error: Symbol stream of module %s (index %u), is too small to contain the symbol information specified by its header.", module_name, module_index);
        }
        
        if(msf_substream(&module_symbol_stream, module_information.byte_size_of_c11_line_information, &c11_line_information)){
            error("Error: Symbol stream of module %s (index %u), is too small to contain the c11 line information specified by its header.", module_name, module_index);
        }
        
        if(msf_substream(&module_symbol_stream, module_information.byte_size_of_c13_line_information, &c13_line_information)){
            error("Error: Symbol stream of module %s (index %u), is too small to contain the c13 line information specified by its header.", module_name, module_index);
        }
        
        u32 global_reference_byte_size = 0;
        if(msf_read_from_stream(&module_symbol_stream, &global_reference_byte_size, sizeof(global_reference_byte_size))){
            error("Error: The module stream for module %s (index %u) ends after the C13 line information, we expect global references to follow. (At least a u32-0 to indicate no global references are present).", module_name, module_index);
        }
        
        if((global_reference_byte_size & 3) != 0){
            error("Error: The byte size (0x%x) for the global references of the module stream of module %s (index %u) is unaligned, expected 4-byte alignment.", global_reference_byte_size, module_name, module_index);
        }
        
        struct msf_stream global_ref_substream;
        if(msf_substream(&module_symbol_stream, global_reference_byte_size, &global_ref_substream)){
            error("Error: Symbol stream of module %s (index %u), is too small to contain the global references.", module_name, module_index);
        }
        
        // @note: We have to process the 'global_ref_substream' later, as we have not inspected the symbol record- and global symbol index stream yet.
        modules[module_index].global_reference_substream = global_ref_substream;
        modules[module_index].module_symbol_stream       = module_symbol_stream;
        
        if(symbol_information.size & 3){
            error("Error: The symbol information size for module %s (index %u) is not 4 byte aligned.", module_name, module_index);
        }
        
        if(c11_line_information.size & 3){
            error("Error: The c11 line information size for module %s (index %u) is not 4 byte aligned.", module_name, module_index);
        }
        
        if(c13_line_information.size & 3){
            error("Error: The c13 line informatio size for module %s (index %u) is not 4 byte aligned.", module_name, module_index);
        }
        
        // 
        // Validate alignment for all symbols in the symbol substream.
        // 
        
        u32 signature;
        if(msf_read_from_stream(&symbol_information, &signature, sizeof(signature))){
            error("Error: The size of the module symbol stream of module %s (index %u) is to small to contain its signature.", module_name, module_index);
        }
        
        if(signature != /*CV_SIGNATURE_C13*/4){
            error("Error: The module symbol stream of module %s (index %u) contains unexpected signature %u. Expected '4' (CV_SIGNATURE_C13 see cvinfo.h).", module_name, module_index, signature);
        }
        
        // To understand the symbol record stream, I have to understand the module symbol streams 
        // (or at least know the symbol offset).
        // 
        // I want to check two things here:
        //     1) All entries in the symbol record stream are correct.
        //     2) There is an entry for each symbol.
        // 
        // Hence, I will first iterate the module symbol streams purely to get the offsets.
        // Then afterwards, I will check all the symobls, after I have checked the symbol records.
        
        if(dump) print("\nModule Symbols for module %s (index %u):\n", module_name, module_index);
        
        u32 amount_of_symbols = 0;
        for(u64 symbol_index = 0; symbol_information.offset < symbol_information.size; symbol_index++, amount_of_symbols++){
            
            u64 symbol_start_offset = symbol_information.offset;
            
            u16 symbol_length;
            struct msf_stream symbol_memory = {0};
            
            if(msf_read_from_stream(&symbol_information, &symbol_length, sizeof(symbol_length)) || msf_substream(&symbol_information, symbol_length, &symbol_memory)){
                error("Error: Symbol %llu (offset 0x%llx) of module %s (index %u) specifies invalid symbol_length 0x%hx.", symbol_index, symbol_start_offset, module_name, module_index, symbol_length);
            }
            
            if((symbol_length & 3) != 2){
                error("Error: Length (0x%hx) of symbol %llu (offset 0x%llx) of module %s (index %u) has invalid alignment. Expected '(symbol_length %% 4) == 2'.", symbol_length, symbol_index, symbol_start_offset, module_name, module_index);
            }
            
            if(dump) print("    Symbol %llu (0x%llx): length: 0x%hx, kind 0x%hx\n", symbol_index, symbol_start_offset, symbol_length, *(u16 *)(symbol_memory.data));
        }
        
        u32 *symbol_offsets = malloc(amount_of_symbols * sizeof(u32));
        for(u32 symbol_index = 0, current_offset = /*after the signature*/4; symbol_index < amount_of_symbols; symbol_index++){
            symbol_offsets[symbol_index] = current_offset;
            current_offset += 2 + *(u16 *)(symbol_information.data + current_offset);
        }
        
        modules[module_index].symbol_offsets.data = symbol_offsets;
        modules[module_index].symbol_offsets.size = amount_of_symbols;
        
        if(c11_line_information.size){
            print("Warning: C11 line information is present, but validation is unsupported.\n");
        }
        
        // 
        // @note: Apparently, the 'DEBUG_S_FILECHKSMS' section can be after the first 'DEBUG_S_LINES' section.
        //        Thus, we first search for the 'DEBUG_S_FILECHKSMS' and then start over and validate the 'DEBUG_S_LINES' sections.
        // 
        
        int have_lines = 0;
        struct msf_stream file_checksums = {0};
        
        if(dump) print("\nC13 Line Information:\n");
        
        for(u64 subsection_index = 0; c13_line_information.offset < c13_line_information.size; subsection_index++){
            u64 subsection_start_offset = c13_line_information.offset;
            
            struct codeview_line_subsection_header{
                u32 type;
                u32 length;
            } subsection_header;
            
            if(msf_read_from_stream(&c13_line_information, &subsection_header, sizeof(subsection_header))){
                error("Error: Subsection %llu (offest 0x%llx) of C13 line information of module %s (index %u) has invalid header.", subsection_index, subsection_start_offset, module_name, module_index);
            }
            
            struct msf_stream subsection;
            if(msf_substream(&c13_line_information, subsection_header.length, &subsection)){
                error("Error: Subsection %llu (offest 0x%llx) of C13 line information of module %s (index %u) has invalid length.", subsection_index, subsection_start_offset, module_name, module_index);
            }
            
            if(subsection_header.type & /*DEBUG_S_IGNORE*/0x80000000) continue;
            
            if(!file_checksums.data){
                if(subsection_header.type == /*DEBUG_S_LINES*/0xf2) have_lines = 1;
                if(subsection_header.type != /*DEBUG_S_FILECHKSMS*/0xf4) continue;
            }
            
            switch(subsection_header.type){
                
                case /*DEBUG_S_FILECHKSMS*/0xf4:{
                    
                    // If we are checking the DEBUG_S_LINES skip the DEBUG_S_FILECHKSMS we have found in the first time around.
                    if(file_checksums.data == subsection.data) continue;
                    
                    if(file_checksums.data){
                        error("Error: C13 line information of module %s (index %u) contains more than one DEBUG_S_FILECHKSMS section.", module_name, module_index);
                    }
                    
                    // Save the subsection so we can use it later when validating the DEBUG_S_LINES sections.
                    file_checksums = subsection;
                    
                    // 
                    // Validate the subsection, the loop will then reset.
                    // 
                    
                    if(subsection.size & 3){
                        error("Error: The size of the DEBUG_S_FILECHKSMS section (offset 0x%llx) of module %s (index %u) has invalid alignment. Expected 4-byte alignment.", subsection_start_offset, module_name, module_index);
                    }
                    
                    if(dump) print("\n    [%llu] DEBUG_S_FILECHKSMS (size 0x%x):\n", subsection_index, subsection.size);
                    
                    for(u64 entry_index = 0; subsection.offset < subsection.size; entry_index++){
                        
                        u64 entry_offset = subsection.offset;
                        
                        struct{
                            u32 offset_in_names;
                            u8  checksum_size;
                            u8  checksum_kind;
                            u8  checksum[];
                        } file_checksum_header;
                        
                        if(msf_read_from_stream(&subsection, &file_checksum_header, sizeof(file_checksum_header) - /* remove padding */2)){
                            error("Error: Entry %llu of DEBUG_S_FILECHKSMS (offest 0x%llx) of C13 line information of module %s (index %u) has invalid header.", entry_index, subsection_start_offset, module_name, module_index);
                        }
                        
                        if((file_checksum_header.offset_in_names == 0) || (file_checksum_header.offset_in_names >= names_string_buffer_stream.size) || names_string_buffer_stream.data[file_checksum_header.offset_in_names-1] != 0){
                            error("Error: Entry %llu of DEBUG_S_FILECHKSMS (offest 0x%llx) of C13 line information of module %s (index %u) specifies invalid offset (0x%x) into /names.", entry_index, subsection_start_offset, module_name, module_index, file_checksum_header.offset_in_names);
                        }
                        
                        if(file_checksum_header.checksum_kind > 3){
                            error("Error: Entry %llu of DEBUG_S_FILECHKSMS (offest 0x%llx) of C13 line information of module %s (index %u) specifies unknown checksum kind %hhu. (0 = none, 1 = MD5, 2 = SHA1, 3 = SHA256).", entry_index, subsection_start_offset, module_name, module_index, file_checksum_header.checksum_kind);
                        }
                        
                        struct msf_stream checksum;
                        if(msf_substream(&subsection, file_checksum_header.checksum_size, &checksum)){
                            error("Error: Entry %llu of DEBUG_S_FILECHKSMS (offest 0x%llx) of C13 line information of module %s (index %u) specifies invalid checksum size 0x%hhx.", entry_index, subsection_start_offset, module_name, module_index, file_checksum_header.checksum_size);
                        }
                        
                        static char *checksum_kind_string[] = {
                            [0] = "none",
                            [1] = "MD5",
                            [2] = "SHA1", 
                            [3] = "SHA256",
                        };
                        
                        if(dump){
                            print("        [%llx] offset 0x%x %s\n", entry_offset, file_checksum_header.offset_in_names, names_string_buffer_stream.data + file_checksum_header.offset_in_names);
                            print("               %s: ", checksum_kind_string[file_checksum_header.checksum_kind]);
                            for(u32 index = 0; index < file_checksum_header.checksum_size; index++) print("%.2hhx ", checksum.data[index]);
                            print("\n");
                        }
                        
                        subsection.offset = (subsection.offset + 3) & ~3;
                    }
                    
                    // Reset the loop now that we have found the DEBUG_S_FILECHKSMS section.
                    subsection_index = (u64)-1; 
                    c13_line_information.offset = 0;
                }break;
                
                case /*DEBUG_S_LINES*/0xf2:{
                    
                    struct codeview_line_header{
                        u32 contribution_offset;
                        u16 contribution_section_id;
                        u16 flags;
                        u32 contribution_size;
                    } line_header;
                    
                    
                    if(msf_read_from_stream(&subsection, &line_header, sizeof(line_header))){
                        error("Error: The DEBUG_S_LINES at (index %llu/offset 0x%llx) of module %s (index %u) is too small for its header.", subsection_index, subsection_start_offset, module_name, module_index);
                    }
                    
                    char *section = ((u64)(line_header.contribution_section_id-1) < section_table.size) ? (char *)section_table.data[line_header.contribution_section_id-1].name : "???";
                    
                    if(dump){
                        print("    [%llu] DEBUG_S_LINES:\n", subsection_index);
                        print("        contribution offset: 0x%x\n", line_header.contribution_offset);
                        print("        contribution section id: %hu (%.8s)\n", line_header.contribution_section_id, section);
                        print("        flags: 0x%hx\n", line_header.flags);
                        print("        contribution size: %u\n", line_header.contribution_size);
                    }
                    
                    if(line_header.flags & ~1){
                        error("Error: The DEBUG_S_LINES at (index %llu/offset 0x%llx) of module %s (index %u) has an unknown flags (0x%hx) set (only know 1 = CV_LINES_HAVE_COLUMNS).", subsection_index, subsection_start_offset, module_name, module_index, line_header.flags);
                    }
                    
                    char *section_id_offset_error = pdb_check_section_id_offset(&section_table, line_header.contribution_section_id, line_header.contribution_offset, line_header.contribution_size);
                    if(section_id_offset_error){
                        error("Error: The DEBUG_S_LINES at (index %llu/offset 0x%llx) of module %s (index %u) %s.", subsection_index, subsection_start_offset, module_name, module_index, section_id_offset_error);
                    }
                    
                    int have_columns = line_header.flags & /*CV_LINES_HAVE_COLUMNS*/1;
                    
                    if(have_columns){
                        print("Warning: The DEBUG_S_LINES header at (index %llu/offset 0x%llx) of module %s (index %u) indicates that columns are present. The column validation code is untested, as there are never columnes present for microsoft pdbs.\n", subsection_index, subsection_start_offset, module_name, module_index);
                    }
                    
                    //
                    // After the line_header there come "blocks" (CV_DebugSLinesFileBlockHeader_t) of lines.
                    // This construct seems to be fairly useless, there only ever seems to be one block.
                    // In theory this would allow you to specify different files, which contribute to a
                    // specific section of code.
                    //
                    // It seems to me one could just specify the whole .text-section for the 'line_header'
                    // and then put the line information in there for all the functions, but
                    // that is not what they do. They have one 'line_header + block_header' per function.
                    //
                    
                    while(subsection.offset < subsection.size){
                        u64 block_offset = subsection.offset;
                        
                        struct codeview_line_block_header{
                            u32 offset_in_file_checksums;
                            u32 amount_of_lines;
                            u32 block_size;
                        } block_header;
                        
                        if(msf_read_from_stream(&subsection, &block_header, sizeof(block_header))){
                            error("Error: The block at offset 0x%llx inside the DEBUG_S_LINES at (index %llu/offset 0x%llx) in the module symbol stream of module %s (index %u) is not large enough to contain the block header.", block_offset, subsection_index, subsection_start_offset, module_name, module_index);
                        }
                        
                        if(dump){
                            print("        Block Header (offset 0x%llx):\n", block_offset);
                            print("            offset in file checksums: 0x%x\n", block_header.offset_in_file_checksums);
                            print("            amount of lines %u\n", block_header.amount_of_lines);
                            print("            block size 0x%x\n", block_header.block_size);
                        }
                        
                        u32 line_size   = block_header.amount_of_lines * 8;
                        u32 column_size = have_columns ? block_header.amount_of_lines * 4 : 0; // @note: not tested, there are never any columns present
                        
                        if((block_header.block_size & 3) != 0){
                            error("Error: The block at offset 0x%llx inside the DEBUG_S_LINES at (index %llu/offset 0x%llx) in the module symbol stream of module %s (index %u) has incorrectly aligned size. Expected 4-byte alignment.", block_offset, subsection_index, subsection_start_offset, module_name, module_index);
                        }
                        
                        u64 expected_block_size = sizeof(block_header) + (u64)line_size + (u64)column_size;
                        if(block_header.block_size != expected_block_size){
                            error("Error: The block at offset 0x%llx inside the DEBUG_S_LINES at (index %llu/offset 0x%llx) in the module symbol stream of module %s (index %u) specifies an unexpected block size 0x%x, expected a block size of 0x%llx.", block_offset, subsection_index, subsection_start_offset, module_name, module_index, block_header.block_size, expected_block_size);
                        }
                        
                        // 
                        // Linearly scan the DEBUG_S_FILECHKSMS section to check that the offset_in_checksums is correct.
                        // 
                        
                        char *found = 0;
                        for(u64 offset = 0; offset < file_checksums.size; ){
                            if(offset == block_header.offset_in_file_checksums){
                                found = (char *)(names_string_buffer_stream.data + *(u32 *)(file_checksums.data + offset));
                                break;
                            }
                            
                            offset += 6 + /*checksum size*/file_checksums.data[offset + 4];
                            offset = (offset + 3) & ~3;
                        }
                        
                        if(!found){
                            error("Error: The block at offset 0x%llx inside the DEBUG_S_LINES at (index %llu, offset 0x%llx) of module %s (index %u) specifies a file offset (0x%x) which is not a valid offset into the DEBUG_S_FILECHKSMS.", block_offset, subsection_index, subsection_start_offset, module_name, module_index, block_header.offset_in_file_checksums);
                        }
                        
                        struct msf_stream lines_stream;
                        if(msf_substream(&subsection, block_header.block_size - sizeof(block_header), &lines_stream)){
                            error("Error: The block at offset 0x%llx inside the DEBUG_S_LINES at (index %llu, offset 0x%llx) of module %s (index %u) specifies an invalid block size (0x%x) (the block size counts the header).", block_offset, subsection_index, subsection_start_offset, module_name, module_index, block_header.block_size);
                        }
                        
                        struct codeview_line{
                            u32 offset;
                            u32 start_line_number     : 24;
                            u32 optional_delta_to_end :  7;
                            u32 is_a_statement        :  1;
                        } *lines = (void *)lines_stream.data;
                        
                        if(dump) print("        -> file: %s\n", found);
                        
                        for(u32 line_index = 0, last_offset = 0; line_index < block_header.amount_of_lines; line_index++){
                            struct codeview_line *line = lines + line_index;
                            
                            if(dump) print("            line: %u, delta: 0x%x, stmt: %u, offset: 0x%x (%s + 0x%x)\n", line->start_line_number, line->optional_delta_to_end, line->is_a_statement, line->offset, section, line_header.contribution_offset + line->offset);
                            
                            if(line->start_line_number > 500000){
                                error("Error: A line number > 500,000 (%u) was detected in the block at offset 0x%llx inside the DEBUG_S_LINES at (index %llu/offset 0x%llx) in the module symbol stream of module %s (index %u). This is considered invalid for the purposes of detecting bugs.", line->start_line_number, block_offset, subsection_index, subsection_start_offset, module_name, module_index);
                            }
                            
                            if(line->offset > line_header.contribution_size){
                                error("Error: The block at offset 0x%llx inside DEBUG_S_LINES at (index %llu / offset 0x%llx) of module %s (index %u) contains a line with an offset (0x%x) which execeeds the contribution size (0x%x) specified by the DEBUG_S_LINES header.", block_offset, subsection_index, subsection_start_offset, module_name, module_index, line->offset, line_header.contribution_size);
                            }
                            
                            if(last_offset > line->offset){
                                error("Error: The lines inside the DEBUG_S_LINE blocks have to be sorted by offset. This was not true for the block at offset 0x%llx of the DEBUG_S_LINES at (index %llu/offset 0x%llx) in the module symbol stream of module %s (index %u).", block_offset, subsection_index, subsection_start_offset, module_name, module_index);
                            }
                            
                            last_offset = line->offset;
                        }
                    }
                    
                    // @cleanup: if columns are present, maybe make sure they do not exceed 10k?
                    
                }break;
                
                case /*DEBUG_S_INLINEELINES*/0xf6:{
                    
                    // @incomplete:
                    
                    // @cleanup: figure out how these work.
                    // u32 kind;
                    // u32 inlinee;
                    // u32 file_checksum_offset;
                    // u32 line_number;
                    // u32 extra_lines;                    (ex)
                    // u32 extra_file_checksum_offsets[];  (ex)
                    
                    // print("\n\nEntry:\n");
                    // print_stream_range(context, &entry_stream, 0, entry_stream.stream_size);
                    
                    // u32 kind = pdb_read_type_from_stream(context, &entry_stream, u32);
                    // u32 inlinee = pdb_read_type_from_stream(context, &entry_stream, u32);
                    // u32 file_checksum_offset = pdb_read_type_from_stream(context, &entry_stream, u32);
                    // u32 line_number = pdb_read_type_from_stream(context, &entry_stream, u32);
                    
                    // print("kind 0x%x, inlinee 0x%x, file_checksum_offset 0x%x, line_number %d\n", kind, inlinee, file_checksum_offset, line_number);
                    
                }break;
                
                case /*DEBUG_S_MERGED_ASSEMBLYINPUT*/0xfd:{
                    // @incomplete:
                    // print("[DEBUG_S_MERGED_ASSEMBLYINPUT]\n");
                }break;
                
                default:{
                    print("Error: Subsection %llu (offest %llx) of C13 line information of module %s (index %u) has unknown subsection type 0x%x.", subsection_index, subsection_start_offset, module_name, module_index, subsection_header.type);
                }break;
            }
        }
        
        if(have_lines && !file_checksums.data){
            error("Error: The C13 line information inside the module stream of module %s (index %u) does not contain a DEBUG_S_FILECHKSMS, but contains a DEBUG_S_LINES.", module_name, module_index);
        }
    }
    
    // Symbol record stream:
    // 
    // The symbol record stream consists of codeview records.
    // Each of these records is either a 'S_PUB32' or a reference record,
    // which references a _private_ symbol in one of the module symbol record streams.
    // 
    
    if((symbol_record_stream.size & 3) != 0){
        error("Error: The size (0x%x) of the symbol record stream has invalid alignment. Must be 4-byte aligned.", symbol_record_stream.size);
    }
    
    u32 amount_of_public_symbols = 0;
    u32 amount_of_global_symbols = 0;
    
    if(dump) print("\nSymbol record stream (size 0x%x):\n", symbol_record_stream.size);
    
    for(u32 symbol_index = 0; symbol_record_stream.offset < symbol_record_stream.size; symbol_index++){
        u64 symbol_offset = symbol_record_stream.offset;
        
        // @note: Because of the alignment the header always fits.
        struct codeview_symbol_header{
            u16 length;
            u16 kind;
        } symbol_header; msf_read_from_stream(&symbol_record_stream, &symbol_header, sizeof(symbol_header));
        
        if((symbol_header.length & 3) != 2){
            error("Error: Symbol %u (kind 0x%x) (offset 0x%llx) in the symbol record stream has invalid length (0x%hx). Entry must be 4-byte aligned.", symbol_index, symbol_header.kind, symbol_offset, symbol_header.length);
        }
        
        struct msf_stream symbol_data;
        if(msf_substream(&symbol_record_stream, symbol_header.length-2, &symbol_data)){
            error("Error: Symbol %u (kind 0x%x) (offset 0x%llx) in the symbol record stream has invalid length (0x%hx) which is too large to fit in the stream.", symbol_index, symbol_header.kind, symbol_offset, symbol_header.length);
        }
        
        if(symbol_header.kind == /*S_PUB32*/0x110e){
            amount_of_public_symbols += 1;
        }else{
            amount_of_global_symbols += 1;
        }
        
        switch(symbol_header.kind){
            case /*S_PUB32*/0x110e:{
                struct codeview_public_symbol{
                    u32 flags;
                    u32 offset;
                    u16 section_id;
                    u8 name[];
                } *public_symbol = (void *)symbol_data.data;
                
                if(sizeof(*public_symbol) > symbol_data.size){
                    error("Error: S_PUB32 (symbol index %u / offset 0x%llx) symbol in the symbol record stream is too small.", symbol_index, symbol_offset);
                }
                
                // @cleanup: flags?
                
                symbol_data.offset = offset_in_type(struct codeview_public_symbol, name);
                
                char *name = msf_read_string(&symbol_data);
                if(!name){
                    error("Error: S_PUB32 '%.*s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream ends in non-zero-terminated string.", (char *)(symbol_data.data + symbol_data.size) - name, name, symbol_index, symbol_offset);
                }
                
                char *check_offset_error = pdb_check_section_id_offset(&section_table, public_symbol->section_id, public_symbol->offset, /*size*/0);
                if(check_offset_error){
                    print("Warning: S_PUB32 '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream %s.\n", name, symbol_index, symbol_offset, check_offset_error);
                }
                
                if(dump) print("    Symbol %u (0x%llx): S_PUB32 0x%x [%hu:0x%x] %s\n", symbol_index, symbol_offset, public_symbol->flags, public_symbol->section_id, public_symbol->offset, public_symbol->name);
            }break;
            
            case /*S_ANNOTATIONREF*/0x1128:
            case /*S_LPROCREF*/0x1127:
            case /*S_DATAREF*/0x1126: // Unused.
            case /*S_PROCREF*/0x1125:{
                struct codeview_symbol_reference{
                    u32 SUC_of_the_name; // (?)
                    u32 symbol_offset_in_module_symbol_stream;
                    u16 module_id; // one based for some reason.
                    u8  name[]; // they say "hidden name made a first class member" which is maybe supposed to tell me something?
                } *symbol_reference = (void *)symbol_data.data;
                
                char *symbol_string = "S_LPROCREF";
                if(symbol_header.kind == 0x1126) symbol_string = "S_DATAREF";
                if(symbol_header.kind == 0x1125) symbol_string = "S_PROCREF";
                if(symbol_header.kind == 0x1128) symbol_string = "S_ANNOTATIONREF";
                
                if(sizeof(*symbol_reference) > symbol_data.size){
                    error("Error: %s (symbol index %u / offset 0x%llx) symbol in the symbol record stream is too small.", symbol_string, symbol_index, symbol_offset);
                }
                
                symbol_data.offset = offset_in_type(struct codeview_symbol_reference, name);
                
                char *name = msf_read_string(&symbol_data);
                if(!name){
                    error("Error: %s '%.*s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream ends in non-zero-terminated string.", symbol_string, (char *)(symbol_data.data + symbol_data.size) - name, name, symbol_index, symbol_offset);
                }
                
                u32 module_index = symbol_reference->module_id - 1;
                
                // module id is one based for some reason
                if(module_index >= (u32)amount_of_modules){
                    error("Error: %s '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream has invalid module id %hu (amount of modules is %hu) (these module ids are one based).", symbol_string, name, symbol_index, symbol_offset, symbol_reference->module_id, amount_of_modules);
                }
                
                u32 offset = symbol_reference->symbol_offset_in_module_symbol_stream;
                
#if 0
                // @incomplete: We cannot actually perform this check here, as the private symbol 
                //              might be an old symbol and the module symbol stream was replaced.
                
                u32 *symbol_offsets = modules[module_index].symbol_offsets.data;
                u64 amount_of_offsets = modules[module_index].symbol_offsets.size;
                
                if(bsearch(&offset, symbol_offsets, amount_of_offsets, sizeof(offset), compare_u32) == 0){
                    error("Error: %s '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream specifies an offset (0x%x) which does not point to a symbol in the symbol record stream of module with id %hu (one based id).", symbol_string, name, symbol_index, symbol_offset, offset, symbol_reference->module_id);
                }
                
                // @note: We could check the name here as well, but I think I will leave it here.
                struct codeview_symbol_header *private_symbol = (void *)(modules[module_index].module_symbol_stream.data + offset);
                
                if(symbol_header.kind == /*S_PROCREF*/0x1125 && private_symbol->kind != /* S_GPROC32*/0x1110){
                    error("Error: %s '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream is not a reference to a S_GPROC32 (it is %hx).\n", symbol_string, name, symbol_index, symbol_offset, private_symbol->kind);
                }else if(symbol_header.kind == /*S_LPROCREF*/0x1127 && private_symbol->kind != /* S_GPROC32*/0x110f){
                    error("Error: %s '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream is not a reference to a S_LPROC32 (it is %hx).\n", symbol_string, name, symbol_index, symbol_offset, private_symbol->kind);
                }else if(symbol_header.kind == /*S_ANNOTATIONREF*/0x1128 && private_symbol->kind != /* S_ANNOTATION*/0x1019){
                    error("Error: %s '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream is not a reference to a S_LPROC32 (it is %hx).\n", symbol_string, name, symbol_index, symbol_offset, private_symbol->kind);
                }
#endif
                
                if(dump) print("    Symbol %u (0x%llx): %s [%hu:0x%x] %s\n", symbol_index, symbol_offset, symbol_string, symbol_reference->module_id, offset, name);
            }break;
            
            case /*S_CONSTANT*/0x1107:{
                if(sizeof(u32) + sizeof(u16) > symbol_data.size){
                    error("Error: S_CONSTANT (symbol index %u / offset 0x%llx) symbol in the symbol record stream is too small.", symbol_index, symbol_offset);
                }
                
                u32 type_index   = *(u32 *)(symbol_data.data + 0);
                u16 numeric_leaf = *(u16 *)(symbol_data.data + 4);
                int numeric_leaf_size = pdb_numeric_leaf_size_or_error(numeric_leaf);
                if(numeric_leaf_size == -1){
                    error("Error: S_CONSTANT (symbol index %u / offset 0x%llx) symbol in the symbol record stream has unknown numeric leaf 0x%hx.", symbol_index, symbol_offset, numeric_leaf);
                }
                
                if(symbol_data.size < sizeof(u32) + numeric_leaf_size){
                    error("Error: S_CONSTANT (symbol index %u / offset 0x%llx) symbol in the symbol record stream is too small for its numeric leaf of size 0x%x.", symbol_index, symbol_offset, numeric_leaf_size);
                }
                
                symbol_data.offset = sizeof(u32) + numeric_leaf_size;
                
                char *name = msf_read_string(&symbol_data);
                if(!name){
                    error("Error: S_CONSTANT '%.*s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream ends in non-zero-terminated string.", (char *)(symbol_data.data + symbol_data.size) - name, name, symbol_index, symbol_offset);
                }
                
                if(type_index >= tpi_table.one_past_last_type_index){
                    // @cleanup: Can these be anything but primitive types?
                    //           Probably enums?
                    error("Error: S_CONSTANT '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream has invalid type index 0x%x.", name, symbol_index, symbol_offset, type_index);
                }
                
                if(type_index >= tpi_table.minimal_type_index){
                    struct codeview_type_record_header{
                        u16 length;
                        u16 kind;
                    } *type = (void *)(tpi_stream.data + tpi_table.type_index_to_offset_map[type_index]);
                    
                    if(type->kind != /*LF_ENUM*/0x1507){
                        print("Warning: S_CONSTANT '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream has type index 0x%x which does not correspond to an LF_ENUM. It is of kind 0x%hx.\n", name, symbol_index, symbol_offset, type_index, type->kind);
                    }
                }
                
                // @cleanup: Validate more, print more.
                if(dump) print("    Symbol %u (0x%llx): S_CONSTANT type:0x%x leaf:0x%hx %s\n", symbol_index, symbol_offset, type_index, numeric_leaf, name);
            }break;
            
            case /*S_UDT*/0x1108:{
                
                if(sizeof(u32) > symbol_data.size){
                    error("Error: S_UDT (symbol index %u / offset 0x%llx) symbol in the symbol record stream is too small.", symbol_index, symbol_offset);
                }
                
                u32 type_index = *(u32 *)symbol_data.data; // @cleanup: validate
                
                symbol_data.offset = sizeof(u32);
                char *name = msf_read_string(&symbol_data);
                if(!name){
                    error("Error: S_UDT '%.*s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream ends in non-zero-terminated string.", (char *)(symbol_data.data + symbol_data.size) - name, name, symbol_index, symbol_offset);
                }
                
                if(type_index >= tpi_table.one_past_last_type_index){
                    error("Error: S_UDT '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream has invalid type index 0x%x.", name, symbol_index, symbol_offset, type_index);
                }
                
                if(dump) print("    Symbol %u (0x%llx): S_UDT type:0x%x %s\n", symbol_index, symbol_offset, type_index, name);
            }break;
            
            case /*S_GDATA32*/0x110d:
            case /*S_LDATA32*/0x110c:{
                struct codeview_data32{
                    u32 type_index;
                    u32 offset_in_section;
                    u16 section_id;
                    u8 name[];
                } *data32 = (void *)symbol_data.data;
                
                char *gdata32_ldata32 = (symbol_header.kind == 0x110c) ? "S_LDATA32" : "S_GDATA32";
                
                if(sizeof(*data32) > symbol_header.length){
                    error("Error: %s (symbol index %u / offset 0x%llx) symbol in the symbol record stream is too small.", gdata32_ldata32, symbol_index, symbol_offset);
                }
                
                u32 type_index = data32->type_index;
                
                symbol_data.offset = offset_in_type(struct codeview_data32, name);
                char *name = msf_read_string(&symbol_data);
                if(!name){
                    error("Error: %s '%.*s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream ends in non-zero-terminated string.", gdata32_ldata32, (char *)(symbol_data.data + symbol_data.size) - name, name, symbol_index, symbol_offset);
                }
                
                if(type_index >= tpi_table.one_past_last_type_index){
                    error("Error: %s '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream has invalid type index 0x%x.", gdata32_ldata32, name, symbol_index, symbol_offset, type_index);
                }
                
                // @cleanup: Maybe validate the 'type_index' in some way.
                
                char *section_offset_error = pdb_check_section_id_offset(&section_table, data32->section_id, data32->offset_in_section, /*size*/0); // @cleanup: We could get the size from the type I guess.
                if(section_offset_error){
                    print("Warning: %s '%s' (symbol index %u / offset 0x%llx) symbol in the symbol record stream %s.\n", gdata32_ldata32, name, symbol_index, symbol_offset, section_offset_error);
                }
                
                if(dump) print("    Symbol %u (0x%llx): %s type:0x%x [%hu:0x%x] %s\n", symbol_index, symbol_offset, gdata32_ldata32, type_index, data32->section_id, data32->offset_in_section, name);
            }break;
            
            default:{
                error("Internal Error: Unknown symbol kind 0x%hx in the symbol record stream.", symbol_header.kind);
            }break;
        }
    }
    
    u32 *public_symbol_offsets = malloc(amount_of_public_symbols * sizeof(u32));
    u32 *global_symbol_offsets = malloc(amount_of_global_symbols * sizeof(u32));
    
    for(u32 offset = 0, public_symbol_index = 0, global_symbol_index = 0; offset < symbol_record_stream.size; ){
        u16 length = *(u16 *)(symbol_record_stream.data + offset + 0);
        u16 kind   = *(u16 *)(symbol_record_stream.data + offset + 2);
        
        if(kind == /*S_PUB32*/0x110e){
            public_symbol_offsets[public_symbol_index++] = offset;
        }else{
            global_symbol_offsets[global_symbol_index++] = offset;
        }
        
        offset += 2 + length;
    }
    
    struct msf_stream public_symbol_index_substream = {0}; 
    struct msf_stream address_map_substream = {0};
    struct msf_stream thunk_map_substream = {0};
    struct msf_stream thunk_section_map_substream = {0};
    
    if(dbi_stream_header.stream_index_of_the_public_symbol_index_stream == (u16)-1){
        print("Warning: The stream index of the public symbol index indicates that the public symbol index stream is not present.\n");
        print("         The public symbol index stream is required for some functionality.\n");
    }else{
        // Public symbol index stream:
        // 
        // The public symbol index stream contains a version of the global symbol index stream,
        // which is intended to speed-up looking up public symbols (S_PUB32).
        // It also contains information about thunks in the executable and an address map,
        // which allows looking up public symbols by relative virtual address.
        // 
        // The layout of this stream is as follows:
        //      * header
        //      * version of global symbol index stream for S_PUB32
        //      * address map (mapping section:offset to S_PUB32)
        //      * thunk map (mapping an index into the thunk table to the RVA of the "thunked" function)
        //      * thunk section map (mapping section id's to relative virtual addresses)
        // 
        
        struct public_symbol_index_stream_header{
            
            u32 symbol_index_byte_size;
            u32 address_map_byte_size;
            
            u32 number_of_thunks;
            u32 thunk_byte_size;
            u16 thunk_table_section_id;
            u32 thunk_table_offset_in_section;
            
            u32 number_of_sections_in_thunk_section_map;
        } public_symbol_index_stream_header;
        
        if(msf_read_from_stream(&public_symbol_index_stream, &public_symbol_index_stream_header, sizeof(public_symbol_index_stream_header))){
            error("Error: The public symbol index stream is too small to contain its header.\n");
        }
        
        if(dump){
            print("\nPublic symbol index stream:\n");
            print("    symbol index size: 0x%x\n", public_symbol_index_stream_header.symbol_index_byte_size);
            print("    address map size: 0x%x\n", public_symbol_index_stream_header.address_map_byte_size);
            print("    number of thunks: %u\n", public_symbol_index_stream_header.number_of_thunks);
            print("    thunk table section id: %hu\n", public_symbol_index_stream_header.thunk_table_section_id);
            print("    thunk table offset: 0x%x\n", public_symbol_index_stream_header.thunk_table_offset_in_section);
            print("    thunk section map length: %u\n", public_symbol_index_stream_header.number_of_sections_in_thunk_section_map);
        }
        
        {
            u64 index_stream_size = (u64)public_symbol_index_stream_header.symbol_index_byte_size;
            u64 address_map_size  = (u64)public_symbol_index_stream_header.address_map_byte_size;
            u64 thunk_map_size    = 4 * (u64)public_symbol_index_stream_header.number_of_thunks;
            u64 section_map_size  = 8 * (u64)public_symbol_index_stream_header.number_of_sections_in_thunk_section_map;
            
            u64 expected_size = sizeof(public_symbol_index_stream_header) + index_stream_size + address_map_size + thunk_map_size + section_map_size;
            
            if(public_symbol_index_stream.size != expected_size){
                error("Error: The size of the public symbol index stream is incorrect based off it header. Expected 0x%llx (/*index_stream*/0x%llx + /*address_map*/0x%llx + /*thunk_map*/0x%llx + /*thunk_section_map*/0x%llx). Got 0x%x.", expected_size, index_stream_size, address_map_size, thunk_map_size, section_map_size, public_symbol_index_stream.size);
            }
            
            msf_substream(&public_symbol_index_stream, index_stream_size,  &public_symbol_index_substream);
            msf_substream(&public_symbol_index_stream, address_map_size,   &address_map_substream);
            msf_substream(&public_symbol_index_stream, thunk_map_size,     &thunk_map_substream);
            msf_substream(&public_symbol_index_stream, section_map_size,   &thunk_section_map_substream);
        }
        
        // 
        // Validate the address map.
        // The address map is an array of u32's which are offset in the the symbol record
        // stream of all S_PUB32, ordered first by section, then by offset and lastly by name.
        // 
        // We make sure, that they are valid offsets and correctly sorted, and there is the 
        // correct number of them. This implicitly checks that there is a 1:1 correspondence
        // between offsets in the map and `S_PUB32` records.
        // 
        
        u32 amount_of_address_map_entries = public_symbol_index_stream_header.address_map_byte_size / sizeof(u32);
        if(amount_of_address_map_entries != amount_of_public_symbols){
            char *less_more = (amount_of_address_map_entries < amount_of_public_symbols) ? "less" : "more";
            error("Error: The address map inside public symbol index stream contains %s entries (%u) than there are public symbols (%u).", less_more, amount_of_address_map_entries, amount_of_public_symbols);
        }
        
        {
            s16 last_section_id = -1;
            s32 last_offset     = 0;
            u8 *last_name       = 0;
            
            if(dump) print("\nAddress Map:\n");
            
            for(u32 address_map_entry_index = 0; address_map_entry_index < amount_of_address_map_entries; address_map_entry_index++){
                u32 symbol_offset = ((u32 *)address_map_substream.data)[address_map_entry_index];
                if((symbol_offset & 3) != 0){
                    error("Error: Entry %u of the address map inside the public symbol index stream is an offset into the symbol record stream which has incorrect alignment. Expected 4 byte alignment.", address_map_entry_index);
                }
                
                if(bsearch(&symbol_offset, public_symbol_offsets, amount_of_public_symbols, sizeof(symbol_offset), compare_u32) == 0){
                    error("Error: Entry %u of the address map inside the public symbol index stream specifies an invalid offset (0x%x) into the symbol record stream.", address_map_entry_index, symbol_offset);
                }
                
                struct codeview_public_symbol{
                    u32 flags;
                    s32 offset;
                    u16 section_id;
                    u8 name[];
                } *public_symbol = (void *)(symbol_record_stream.data + symbol_offset + 4);
                
                if(dump) print("    [%u] 0x%8.8x -> (%.3hu 0x%8.8x %s)\n", address_map_entry_index, symbol_offset, public_symbol->section_id, public_symbol->offset, public_symbol->name);
                
                if(last_section_id >= public_symbol->section_id){
                    
                    if(last_section_id > public_symbol->section_id){
                        error("Error: The address map inside the public symbol index stream is not sorted by section id. Entry %u has section id %hd, Entry %u has section id %hu.", address_map_entry_index-1, last_section_id, address_map_entry_index, public_symbol->section_id);
                    }
                    
                    if(last_offset >= public_symbol->offset){
                        
                        if(last_offset > public_symbol->offset){
                            error("Error: The address map inside the public symbol index stream is not sorted by section_id:offset. Entry %u has offset 0x%x, Entry %u has offset 0x%x.", address_map_entry_index-1, last_offset, address_map_entry_index, public_symbol->offset);
                        }
                        
                        int difference = strcmp((char *)last_name, (char *)public_symbol->name);
                        
                        if(difference >= 0){
                            
                            if(difference > 0){
                                error("Error: The address map inside the public symbol index stream is not sorted by section_id:offset:name. Entry %u has name %s, Entry %u has name %s (which is incorrect order).", address_map_entry_index-1, last_name, address_map_entry_index, public_symbol->name);
                            }
                        }
                    }
                }
                
                last_section_id = public_symbol->section_id;
                last_offset     = public_symbol->offset;
                last_name       = public_symbol->name;
            }
        }
        
        if(public_symbol_index_stream_header.number_of_thunks){
            if(public_symbol_index_stream_header.thunk_byte_size == 0){
                error("Error: The thunk map inside the public symbol index stream is non-zero, but the size of a thunk is zero.");
            }
            
            u32 thunk_byte_size     = public_symbol_index_stream_header.thunk_byte_size;
            u32 thunk_table_section = public_symbol_index_stream_header.thunk_table_section_id;
            u32 thunk_table_size    = thunk_byte_size * public_symbol_index_stream_header.number_of_thunks; // @cleanup: overflow?
            u32 thunk_table_offset  = public_symbol_index_stream_header.thunk_table_offset_in_section;
            
            char *section_id_offset_error = pdb_check_section_id_offset(&section_table, thunk_table_section, thunk_table_offset, thunk_table_size);
            if(section_id_offset_error){
                error("Error: The thunk map inside the public symbol index stream %s.", section_id_offset_error);
            }
            
            // 
            // The thunk map is used to map thunks to the rva of the non-thunk function.
            // One can calculate as follows:
            //     thunk_map[(thunk_rva - thunk_map_rva)/thunk_byte_size] = function_rva.
            // 
            if(dump) print("\nThunk map:\n");
            
            for(u32 thunk_index = 0; thunk_index < public_symbol_index_stream_header.number_of_thunks; thunk_index++){
                u32 function_rva = ((u32 *)thunk_map_substream.data)[thunk_index];
                
                // Use the address map to find the 'S_PUB32' for the 'function_rva'.
                s64 min_index = 0;
                s64 max_index = amount_of_address_map_entries - 1;
                
                char *found = 0;
                
                while(min_index <= max_index){
                    u32 index = min_index + (max_index - min_index)/2;
                    u32 symbol_offset = ((u32 *)address_map_substream.data)[index];
                    
                    struct codeview_public_symbol{
                        u32 flags;
                        s32 offset;
                        u16 section_id;
                        u8 name[];
                    } *public_symbol = (void *)(symbol_record_stream.data + symbol_offset + 4);
                    
                    u32 symbol_rva = section_table.data[public_symbol->section_id-1].virtual_address + public_symbol->offset;
                    
                    if(symbol_rva < function_rva){
                        min_index = index + 1;
                    }else if(symbol_rva > function_rva){
                        max_index = index - 1;
                    }else{
                        found = (char *)public_symbol->name;
                        break;
                    }
                }
                
                if(!found){
                    error("Error: Entry %u of the thunk map inside the public symbol index stream, specifies a relative virtual address of 0x%x, but there is no 'S_PUB32' associated with it.", thunk_index, function_rva);
                }
                
                if(dump) print("    [%u] 0x%x -> %s\n", thunk_index, function_rva, found);
            }
            
            // 
            // Validate the thunk section map.
            // We only have to know that the section of the incremental linking table is present
            // and that all the virtual addresses and sections are correct.
            // 
            
            struct pdb_thunk_section_map_entry{
                u32 virtual_address;
                u16 section_id;
            } *section_map = (void *)thunk_section_map_substream.data;
            u32 amount_of_section_map_entries = thunk_section_map_substream.size/sizeof(struct pdb_thunk_section_map_entry);
            
            int found = 0;
            
            if(dump) print("\nThunk section map:\n");
            
            for(u32 section_map_entry_index = 0; section_map_entry_index < amount_of_section_map_entries; section_map_entry_index++){
                struct pdb_thunk_section_map_entry section_map_entry = section_map[section_map_entry_index];
                
                if(dump) print("    [%u] virtual address: 0x%x, section id: 0x%hx\n", section_map_entry_index, section_map_entry.virtual_address, section_map_entry.section_id);
                
                u32 section_index = section_map_entry.section_id - 1;
                if(section_index >= section_table.size){
                    error("Error: Entry %u of the thunk section map of the thunk map contained in the public symbol index stream specifies an invalid section id (%hu).", section_map_entry_index, section_map_entry.section_id);
                }
                
                if(section_table.data[section_index].virtual_address != section_map_entry.virtual_address){
                    error("Error: Entry %u of the thunk section map of the thunk map contained in the public symbol index stream specifies a wrong virtual address 0x%x for section %hu, the correct virtual address is 0x%x (based of the section header dump stream).", section_map_entry_index, section_map_entry.virtual_address, section_map_entry.section_id, section_table.data[section_index].virtual_address);
                }
                
                if(section_map_entry.section_id == thunk_table_section) found = 1;
            }
            
            if(!found){
                error("Error: The thunk section map inside the public symbol index stream does not contain an entry for the section which contains the incremental linking table (section id %u).\n", thunk_table_section);
            }
        }
    }
    
    int have_no_public_symbol_index_stream = (dbi_stream_header.stream_index_of_the_public_symbol_index_stream == (u16)-1);
    for(u32 is_global_symbol_index_stream = have_no_public_symbol_index_stream; is_global_symbol_index_stream < 2; is_global_symbol_index_stream++){
        
        char *stream_name = is_global_symbol_index_stream ? "global symbol index" : "public symbol index";
        struct msf_stream symbol_index_stream = is_global_symbol_index_stream ? global_symbol_index_stream : public_symbol_index_substream;
        
        if(dump) print("\n%s stream:\n", stream_name);
        
        //
        // global symbol index stream and public symbol index stream.
        //
        // The global/public symbol index stream contains information to recreate a hash table
        //     string (pdb_string_hash) -> symbol_offset_in_symbol_record_stream
        // The resulting hash table is a chaining hash table of with a bucket count of
        // 4096 or 0x3ffff if /DEBUG:FASTLINK (this value is called the IPHR_HASH).
        // The stream consists of the records (ordered by their appearance in the hash table),
        // Then the one bit per bucket, telling us whether or not the bucket is filled.
        // Each bucket is sorted by a case insensitive string comparison.
        // After the Buckets and the bitmap for each present bucket, the offset into the records
        // is stored as a u32.
        //
        // In sum, the structure is as follows:
        //     u32 version_signature;
        //     u32 version;
        //     u32 hash_records_bytes_size;
        //     u32 bucket_information_size;
        //     struct pdb_hash_record hash_records[amount_of_public/global_symbols];
        //     u32 bucket_bitmap[(IPHR_HASH/32) + 1];
        //     u32 bucket_offsets[amount_of_present_buckets];
        //
        // The serialized hash records have the following layout:
        //    u32 symbol_offset;
        //    u32 reference_count;
        // And they are supposed to get deserialized into
        //    u32 next_symbol; (32-bit pointer)
        //    u32 symbol_offset;
        //    u32 reference_count;
        // as this table is chained. For this reason the size of the hash_records
        // is treated as if it was 12 bytes.
        //
        // The difference between the global symbol stream and the public symbol stream
        // is which symbols they reference.
        // The public symbol stream only contains S_PUB32, while the global symbol stream
        // contains a variety of symbols which are meant to find the corresponding module index.
        //
        
        struct symbol_index_stream_header{
            u32 version_signature;
            u32 version;
            u32 hash_records_byte_size;
            u32 bucket_information_size;
        } symbol_index_stream_header;
        
        if(msf_read_from_stream(&symbol_index_stream, &symbol_index_stream_header, sizeof(symbol_index_stream_header))){
            error("Error: The %s stream is to small to contain its header.", stream_name);
        }
        
        if(symbol_index_stream_header.version_signature != (u32)-1){
            error("Error: The %s stream has wrong version signature (%d). Expected -1.", stream_name, (s32)symbol_index_stream_header.version_signature);
        }
        
        if(symbol_index_stream_header.version != 0xeffe0000 + 19990810){
            error("Error: The %s stream has unexpected version (0xeffe0000 + %u). Expected 0xeffe0000 + 19990810.", stream_name, symbol_index_stream_header.version - 0xeffe0000);
        }
        
        if((symbol_index_stream_header.hash_records_byte_size & 7) != 0){
            error("Error: The hash record buffer inside the %s stream is incorrectly aligned (size is 0x%x). Expected 8-byte alignment.", stream_name, symbol_index_stream_header.hash_records_byte_size);
        }
        
        if(symbol_index_stream.size - symbol_index_stream.offset != (u64)symbol_index_stream_header.hash_records_byte_size + symbol_index_stream_header.bucket_information_size){
            
            u64 expected = sizeof(symbol_index_stream_header) + (u64)symbol_index_stream_header.hash_records_byte_size + symbol_index_stream_header.bucket_information_size;
            
            char *error_message = is_global_symbol_index_stream ? 
                    "Error: The global symbol index stream size differs from the expected size based on its header." :
                    "Error: Inside the public symbol index stream, the hash table information size differs from the expected size based on its header.";
            
            error("%s (Given: 0x%x, Expected; 0x%llx = /*header*/0x%llx + /*hash records*/0x%x + /*bucket information*/0x%x).", error_message, symbol_index_stream.size, expected, sizeof(symbol_index_stream_header), symbol_index_stream_header.hash_records_byte_size, symbol_index_stream_header.bucket_information_size);
        }
        
        if(dump){
            print("    version_signature: %d\n", (s32)symbol_index_stream_header.version_signature);
            print("    version: 0xeffe0000 + %u\n", symbol_index_stream_header.version - 0xeffe0000);
            print("    hash record bytes: 0x%x\n", symbol_index_stream_header.hash_records_byte_size);
            print("    bucket information bytes: 0x%x\n", symbol_index_stream_header.bucket_information_size);
        }
        
        struct msf_stream hash_record_stream; msf_substream(&symbol_index_stream, symbol_index_stream_header.hash_records_byte_size, &hash_record_stream);
        
        // Validate the hash records. On Disk, they have the following layout:
        struct pdb_serialized_hash_record{
            u32 symbol_offset_plus_one;
            u32 reference_count;
        } *hash_records = (void *)hash_record_stream.data;
        u32 amount_of_hash_records = hash_record_stream.size / sizeof(*hash_records);
        
        u32 *symbol_offsets   = is_global_symbol_index_stream ? global_symbol_offsets    : public_symbol_offsets;
        u32 amount_of_symbols = is_global_symbol_index_stream ? amount_of_global_symbols : amount_of_public_symbols;
        
        if(dump) print("\n%s hash records:\n", stream_name);
        for(u32 hash_record_index = 0; hash_record_index < amount_of_hash_records; hash_record_index++){
            struct pdb_serialized_hash_record hash_record = hash_records[hash_record_index];
            
            // For some reason these symbol offsets are adjusted by 1.
            u32 actual_symbol_offset = hash_record.symbol_offset_plus_one - 1;
            
            if(bsearch(&actual_symbol_offset, symbol_offsets, amount_of_symbols, sizeof(actual_symbol_offset), compare_u32) == 0){
                // @cleanup: Maybe detect if it's a correct offset but not to a correct symbol kind?
                error("Error: Hash record %u inside the %s stream does not specify a valid symbol offset into the symbol record stream (it specifies (0x%x + 1)).\n", hash_record_index, stream_name, actual_symbol_offset);
            }
            
            if(dump) print("    [%u] offset: 0x%x + 1, ref-count: %u -> (%s)\n", hash_record_index, actual_symbol_offset, hash_record.reference_count, pdb_symbol_record__get_name(symbol_record_stream.data + actual_symbol_offset));
            
            if(!is_global_symbol_index_stream && hash_record.reference_count != 1){
                error("Error: Inside the public symbol index stream all hash records are supposed to have reference count 1.\n");
            }
        }
        
        // @hmm: It seems for 'S_PUB32' there can be less hash records than there are S_PUB32.
        //       This is because it seems to add new 'S_PUB32' whenever incremental linking occurs,
        //       but does not delete the old entries.
        // @incomplete: This also affects the code below, as entries do not have to map to themselves anymore.
        //              I could count misses or something, and make sure the number is correct?
        //
        // @note: It seems only the symbols which are reachable through the index stream are the symbols which are
        //        "alive", older symbols might not point to valid data.
        //        
        
        if(amount_of_hash_records > amount_of_symbols){
            char *symbol_name = is_global_symbol_index_stream ? "global" : "S_PUB32";
            error("Error: The %s stream has too many of hash records. Got 0x%x, expected at most 0x%x (one for each %s symbol in the symbol record stream).", stream_name, amount_of_hash_records, amount_of_symbols, symbol_name);
        }
        
        // Validate the hash buckets:
        // 
        // The amount of hash buckets used depends on whether or not this is a /DEBUG:FASTLINK pdb.
        // 
        u32 IPHR_HASH = is_fastlink_pdb ? 0x3FFFF : 4096;
        static struct{
            u32 start;
            u32 end;
        } hash_buckets[0x3FFFF + 1];
        memset(hash_buckets, 0xff, IPHR_HASH * sizeof(hash_buckets[0]));
        
        if(symbol_index_stream_header.bucket_information_size){
            
            u32 bitmap_size = sizeof(u32) * ((IPHR_HASH/32) + 1);
            struct msf_stream bucket_stream;
            
            if(msf_substream(&symbol_index_stream, bitmap_size, &bucket_stream)){
                error("Error: The bucket information inside the %s stream is too small to contain the bucket bitmap. Size 0x%x, Expected bitmap size 0x%x = sizeof(u32) * ((IPHR_HASH/32) + 1). IPHR_HASH is 0x%x for a %s PDB.", stream_name, symbol_index_stream_header.bucket_information_size, bitmap_size, IPHR_HASH, is_fastlink_pdb ? "/DEBUG:FASTLINK" : "non-fastlink");
            }
            
            // 
            // Iterate over every bucket ^= every bit in the bitmap,
            // to figure out in which buckets the entries go.
            // 
            
            s64 last_record_offset = -1;
            s64 last_bucket_index  = 0;
            
            if(dump) print("\n%s hash buckets:\n", stream_name);
            for(u32 bucket_index = 0; bucket_index < 8 * bitmap_size; bucket_index++){
                if(!_bittest((long *)bucket_stream.data, bucket_index)) continue;
                
                u32 record_offset;
                if(msf_read_from_stream(&symbol_index_stream, &record_offset, sizeof(record_offset))){
                    error("The bitmap of the bucket information inside the %s stream has more bit set then there are bucket offsets.", stream_name);
                }
                
                //
                // The offset is given in deserialized hash_records (containing an additional 32-bit pointer 'psym')
                // So convert this offset to an offset in the table above.
                //
                
                if((record_offset % 12) != 0){
                    error("Error: A bucket offset specified for a bucket in the %s stream is not a multiple of 12. These offsets are offset into the hash record buffer if the record buffer entries were deserialized (12 bytes large, by adding the 32-bit 'next' field).", stream_name);
                }
                
                // Fix up the record offset and store them in the table.
                record_offset = (record_offset / 12) * 8;
                
                if((s64)record_offset <= last_record_offset){
                    error("Error: The bucket offsets in the %s stream should be sorted, but bucket %u specifies offset 0x%x, whereas the previous present bucket (%u) specified offset 0x%x.", stream_name, bucket_index, record_offset, (u32)last_bucket_index, (u32)last_record_offset);
                }
                
                if(record_offset >= hash_record_stream.size){
                    error("Error: Hash bucket %u in the %s stream specifies an invalid bucket offset 0x%x.", bucket_index, stream_name, record_offset);
                }
                
                u32 record_index = record_offset / sizeof(struct pdb_serialized_hash_record);
                
                hash_buckets[last_bucket_index].end = record_index;
                hash_buckets[bucket_index].start    = record_index;
                
                last_record_offset = record_offset;
                last_bucket_index  = bucket_index;
            }
            
            if(last_record_offset != -1){
                hash_buckets[last_bucket_index].end = hash_record_stream.size / sizeof(struct pdb_serialized_hash_record);
            }
            
            if(dump){
                for(u32 bucket_index = 0; bucket_index < IPHR_HASH; bucket_index++){
                    u32 start = hash_buckets[bucket_index].start;
                    u32 end   = hash_buckets[bucket_index].end;
                    
                    if(start == 0xffffffff) continue;
                    
                    print("    [%u] bucket start index %u, end index %u: ", bucket_index, start, end);
                    for(u32 record_index = start; record_index < end; record_index++){
                        struct pdb_serialized_hash_record hash_record = hash_records[record_index];
                        char *name = pdb_symbol_record__get_name(symbol_record_stream.data + hash_record.symbol_offset_plus_one - 1);
                        print("[%u (%s)]", record_index, name);
                    }
                    print("\n");
                }
            }
            
            if(symbol_index_stream.offset < symbol_index_stream.size){
                error("Error: The %s stream contains too many bucket offsets.", stream_name);
            }
            
            // 
            // @note: We only want to validate the symbols which are in a hash record.
            //        All other ones are old dead symbols.
            // 
            for(u32 hash_record_index = 0; hash_record_index < amount_of_hash_records; hash_record_index++){
                u32 symbol_offset = hash_records[hash_record_index].symbol_offset_plus_one - 1;
                char *name = pdb_symbol_record__get_name(symbol_record_stream.data + symbol_offset);
                
                u16 gsi_hash_index = (u16)pdb_hash_index((u8 *)name, strlen(name), IPHR_HASH);
                
                u32 bucket_start = hash_buckets[gsi_hash_index].start;
                u32 bucket_end   = hash_buckets[gsi_hash_index].end;
                
                int found = 0;
                if(bucket_start != 0xffffffff){
                    for(u32 record_index = bucket_start; record_index < bucket_end; record_index++){
                        struct pdb_serialized_hash_record hash_record = hash_records[record_index];
                        
                        if(hash_record.symbol_offset_plus_one == symbol_offset + 1){
                            found = 1;
                            break;
                        }
                    }
                }
                
                if(!found){
                    // @cleanup: This is only correct for entries which are pointed to by the hash table, 
                    //           as newer versions of symbols are added without removing older versions.
                    //           This happens for incrementally linked binaries.
                    error("Error: Symbol '%s' (offset 0x%x) does not hash to itself using the hash table inside the %s stream.", name, symbol_offset, stream_name);
                }
            }
        }
        
        if(is_global_symbol_index_stream){
            for(u32 module_index = 0; module_index < amount_of_modules; module_index++){
                char *module_name = modules[module_index].name;
                
                struct msf_stream global_reference_substream = modules[module_index].global_reference_substream;
                
                //
                // Global references are just an array of offsets into the symbol records stream
                // to global symbols which are used by the module.
                // They are here to _remember_ how the reference counts in the 'global symbol hash stream hash records'
                // came to be.
                //
                // The code in 'microsoft-pdb' iterates through these global references on load of a
                // global symbol and decrements the reference count for that symbol.
                // On 'Close' it then calls 'fProcessSyms' which iterates the symbols and adds
                // a reference to each symbol that needs it.
                //
                
                u32 amount_of_global_references = global_reference_substream.size / sizeof(u32);
                
                if(dump) print("\nGlobal references for module %s (index %u):\n", module_name, module_index);
                for(u32 global_ref_index = 0; global_ref_index < amount_of_global_references; global_ref_index++){
                    u32 symbol_offset = ((u32 *)global_reference_substream.data)[global_ref_index];
                    
                    if(dump) print("    [%u] 0x%x (%s)\n", global_ref_index, symbol_offset, pdb_symbol_record__get_name(symbol_record_stream.data + symbol_offset));
                    
                    if(bsearch(&symbol_offset, global_symbol_offsets, amount_of_global_symbols, sizeof(symbol_offset), compare_u32) == 0){
                        error("Global symbol reference %u inside module symbol stream of module %s (index %u) is not a valid offset (0x%x) to a global symbol in the symbol record stream.", global_ref_index, module_name, module_index, symbol_offset);
                    }
                    
                    char *name = pdb_symbol_record__get_name(symbol_record_stream.data + symbol_offset);
                    u16 gsi_hash_index = (u16)pdb_hash_index((u8 *)name, strlen(name), IPHR_HASH);
                    
                    u32 bucket_start = hash_buckets[gsi_hash_index].start;
                    u32 bucket_end   = hash_buckets[gsi_hash_index].end;
                    
                    int found = 0;
                    if(bucket_start != 0xffffffff){
                        for(u32 record_index = bucket_start; record_index < bucket_end; record_index++){
                            struct pdb_serialized_hash_record hash_record = hash_records[record_index];
                            
                            if(hash_record.symbol_offset_plus_one == symbol_offset + 1){
                                hash_records[record_index].reference_count -= 1;
                                found = 1;
                                break;
                            }
                        }
                    }
                    
                    if(!found){
                        error("Internal Error: We could not find a valid symbol record (%s/0x%x) in the symbol record stream using the validated global symbol index stream hash table.", name, symbol_offset);
                    }
                }
            }
            
            for(u32 hash_record_index = 0; hash_record_index < amount_of_hash_records; hash_record_index++){
                if(hash_records[hash_record_index].reference_count != 0){
                    u32 symbol_offset = hash_records[hash_record_index].symbol_offset_plus_one - 1;
                    char *name = pdb_symbol_record__get_name(symbol_record_stream.data + symbol_offset);
                    error("Error: Invalid reference count for '%s' (offset 0x%x) inside the global symbol index stream.", name, symbol_offset);
                }
            }
        }
    }
    
#if 0
    {
        // 
        // Check that we have the correct global references for each module symbol stream.
        // @incomplete: Validate pointer to parent and pointer to end members.
        // 
        
        for(u32 module_index = 0; module_index < amount_of_modules; module_index++){
            
            struct module *module = &modules[module_index];
            struct msf_stream module_symbol_stream = module->module_symbol_stream;
            
            struct msf_stream global_reference_substream = modules[module_index].global_reference_substream;
            u32 *global_references = (u32 *)global_reference_substream.data;
            u32 amount_of_global_references = global_reference_substream.size / sizeof(u32);
            
            u32 global_reference_at = 0;
            
            for(u64 symbol_index = 0; symbol_index < module->symbol_offsets.size; symbol_index++){
                u64 symbol_offset = module->symbol_offsets.data[symbol_index];
                
                struct codeview_symbol_header{
                    u16 length;
                    u16 kind;
                } *symbol_header = (void *)(module_symbol_stream.data + symbol_offset);
                
                switch(symbol_header->kind){
                    case /*S_LPROC32*/0x110f:
                    case /*S_GPROC32*/0x1110:{
                        
                        struct codeview_symbol_header *global_symbol = (void *)(symbol_record_stream.data + global_references[global_reference_at++]);
                        
                        print("global_symbol->kind 0x%hx, global_symbol->length 0x%hx\n", global_symbol->kind, global_symbol->length);
                    }break;
                    
                    case /*S_CONSTANT*/0x1107:{
                        // Should only give a global ref, if there is an identical one 
                        // in the global scope.
                        
                        char *name = pdb_symbol_record__get_name((u8 *)symbol_header);
                        
                        struct codeview_symbol_header *global_symbol = (void *)(symbol_record_stream.data + global_references[global_reference_at++]);
                        
                    }break;
                    
                    case /*S_UDT*/0x1108:{
                        
                    }break;
                    
                    case /*S_LDATA32*/0x110c:{
                    }break;
                    
                    case /*S_GDATA32*/0x110d:{
                        
                    }break;
                    
                    case /*S_ANNOTATION*/0x1019:{
                        
                    }break;
                    
                }
            }
        }
    }
#endif
}

struct file{
    u8 *memory;
    size_t size;
};

struct file load_file(char *file_name){
    struct file file = {0};
    
    FILE *handle = fopen(file_name, "rb");
    if(!handle){
        print("Could not open %s\n", file_name);
        return file;
    }
    
    fseek(handle, 0, SEEK_END);
    size_t size = _ftelli64(handle);
    if(size == -1){
        print("Could not get the file size for %s\n", file_name);
        return file;
    }
    fseek(handle, 0, SEEK_SET);
    
    u8 *memory = malloc(size);
    if(!memory){
        print("Could not allocate memory for %s\n", file_name);
        return file;
    }
    
    fread(memory, 1, size, handle);
    fclose(handle);
    
    return (struct file){ .memory = memory, .size = size };
}

int main(int argc, char *argv[]){
    
    if(argc < 2){
        print("usage: %s <pdb> [-dump]\n", argv[0]);
        return 1;
    }
    
    int dump = 0;
    if(argc == 3 && strcmp(argv[2], "-dump") == 0){
        dump = 1;
    }
    
    struct file pdb = load_file(argv[1]);
    if(!pdb.memory) return 1;
    
    pdb_validate(pdb.memory, pdb.size, dump);
    
    return 0;
}

