
#include <time.h>
#include <assert.h>

#define kilo_bytes(a) ((a) * 1024ULL)
#define mega_bytes(a) ((kilo_bytes(a)) * 1024ULL)
#define giga_bytes(a) ((mega_bytes(a)) * 1024ULL)

#define push_struct(arena, type) ((type *)memory_arena_allocate_bytes((arena), sizeof(type), _Alignof(type)))
#define push_array(arena, type, count) ((type *)memory_arena_allocate_bytes((arena), sizeof(type) * (count), _Alignof(type)))

#define push_struct_unaligned(arena, type) ((type *)memory_arena_allocate_bytes((arena), sizeof(type), 1))
#define push_array_unaligned(arena, type, count) ((type *)memory_arena_allocate_bytes((arena), sizeof(type) * (count), 1))

#define array_count(a) (sizeof(a)/sizeof(*a))


enum pdb_stream{
    
    // Fixed streams.
    PDB_STREAM_pdb_information = 1,
    PDB_STREAM_tpi = 2,
    PDB_STREAM_dbi = 3,
    PDB_STREAM_ipi = 4,
    
    PDB_STREAM_names,
    
    PDB_STREAM_tpi_hash,
    PDB_STREAM_ipi_hash,
    
    PDB_STREAM_section_header_dump,
    
    PDB_CURRENT_AMOUNT_OF_STREAMS, // @incomplete:
    
    PDB_STREAM_symbol_record,
    PDB_STREAM_global_symbol_index,
    PDB_STREAM_public_symbol_index,
    
    PDB_STREAM_module_symbol_stream_base = PDB_CURRENT_AMOUNT_OF_STREAMS, // @cleanup:
};

// For reference see `HashPbCb` in `microsoft-pdb/PDB/include/misc.h`.
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

u16 hash_string(char *string){
    return (u16)pdb_hash_index((u8 *)string, strlen(string), (u32)-1);
}

// returns -1 on failiure.
void pdb_stream_skip_numeric_leaf(struct stream *stream){
    
    u16 numeric_leaf;
    if(stream_read(stream, &numeric_leaf, sizeof(numeric_leaf))) return;
    
    if(!(numeric_leaf & 0x8000))return;
    
    //
    // @cleanup: implement this more correctly
    //
    
    switch(numeric_leaf){
        case 0x8000:{ // LF_CHAR
            stream_skip(stream, 1);
        }break;
        case 0x8001:  // LF_SHORT
        case 0x8002:{ // LF_USHORT
            stream_skip(stream, 2);
        }break;
        case 0x8005: // LF_REAL32
        case 0x8003: // LF_LONG
        case 0x8004:{ // LF_ULONG
            stream_skip(stream, 4);
        }break;
        
        case 0x8009: // LF_QUADWORD
        case 0x800a: // LF_UQUADWORD
        case 0x8006:{ // LF_REAL64
            stream_skip(stream, 8);
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
            stream_skip(stream, 16);
        }break;
        
        // case 0x8019: // LF_DECIMAL
        // case 0x801a: // LF_DATE
        // case 0x801b: // LF_UTF8STRING
        // case 0x801c: // LF_REAL16
        default:{
            print("WARNING: Unhandled numeric leaf kind 0x%hx. This might lead to incorrect type information.\n", numeric_leaf);
        }break;
    }
}

void pdb_stream_skip_zero_terminated_string(struct stream *stream){
    while(stream->offset < stream->size && stream->data[stream->offset] != 0){
        stream->offset += 1;
    }
    
    if(stream->offset < stream->size) stream->offset++;
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

struct codeview_type_record_header{
    u16 length;
    u16 kind;
};

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

u32 tpi_hash_table_index_for_record(struct codeview_type_record_header *type_record_header, u32 number_of_hash_buckets){
    
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
            length = sizeof(u32);
        }break;
    }
    
    u32 hash_index;
    if(name){
        if(!length) length = strlen(name);
        hash_index = pdb_hash_index((u8 *)name, length, number_of_hash_buckets);
    }else{
        hash_index = crc32(/*initial_crc*/0, (u8 *)type_record_header, type_record_header->length + sizeof(type_record_header->length)) % number_of_hash_buckets;
    }
    
    return hash_index;
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

struct write_pdb_information{
    
    struct pdb_guid{
        u32 data1;
        u16 data2;
        u16 data3;
        u8 data4[8];
    } pdb_guid;
    
    u32 amount_of_object_files;
    struct write_pdb_per_object_information{
        char *file_name;
        struct stream type_information;
        struct stream symbol_information;
    } *per_object;
    
    size_t amount_of_section_contributions;
    struct pdb_section_contribution *section_contributions;
    
    u16 amount_of_image_sections;
    struct coff_section_header *image_section_headers;
};

void write_pdb(struct write_pdb_information *write_pdb_information){
    
    struct memory_arena arena = create_memory_arena(giga_bytes(8));
    
    struct memory_arena pdb_information_stream = create_memory_arena(giga_bytes(8));
    {
        // 
        // Fill out the information stream.
        // 
        struct pdb_information_stream_header{
            u32 version;
            u32 timestamp;
            u32 age;
            struct pdb_guid guid;
        } *pdb_information_stream_header = push_struct(&pdb_information_stream, struct pdb_information_stream_header);
        pdb_information_stream_header->version = 20000404;
        pdb_information_stream_header->timestamp = time(NULL);
        pdb_information_stream_header->age = 1;
        pdb_information_stream_header->guid = write_pdb_information->pdb_guid;
        
        static struct {
            char *stream_name;
            u32   stream_index;
        } named_streams[] = {
            { "/names", PDB_STREAM_names },
        };
        
        u32 named_stream_table_capacity = 2 * array_count(named_streams);
        struct named_stream_table_entry{
            u32 key;
            u32 value;
        } *named_stream_table_entries = push_array(&arena, struct named_stream_table_entry, named_stream_table_capacity);
        
        u32 *string_buffer_size = push_struct(&pdb_information_stream, u32);
        u8 *string_buffer = push_array(&pdb_information_stream, u8, 0);
        
        for(u32 named_stream_index = 0; named_stream_index < array_count(named_streams); named_stream_index++){
            
            char *stream_name  = named_streams[named_stream_index].stream_name;
            u32   stream_index = named_streams[named_stream_index].stream_index;
            
            u16 hash = hash_string(stream_name);
            
            for(u32 hash_index = 0; hash_index < named_stream_table_capacity; hash_index++){
                
                u32 index = (hash_index + hash) % named_stream_table_capacity;
                
                // @note: Currently there are no deleted named steams. 
                //        So we don't have to care about tombstones!
                if(named_stream_table_entries[index].value == /*empty_slot*/0){
                    // We have found an empty slot.
                    
                    // Allocate the `stream_name` into the `string_buffer`.
                    size_t stream_name_length = strlen(stream_name);
                    u8 *stream_name_in_string_buffer = push_array(&pdb_information_stream, u8, stream_name_length + 1);
                    memcpy(stream_name_in_string_buffer, stream_name, stream_name_length + 1);
                    
                    named_stream_table_entries[index].key   = stream_name_in_string_buffer - string_buffer;
                    named_stream_table_entries[index].value = stream_index;
                    break;
                }
            }
        }
        
        *string_buffer_size = push_array(&pdb_information_stream, u8, 0) - string_buffer;
        
        // 
        // @WARNING: "Importantly, after the string table, the rest of the stream
        //            does not have any defined alignment anymore."
        // 
        
        /*amount_of_entries*/*push_struct_unaligned(&pdb_information_stream, u32) = array_count(named_streams);
        /*capacity         */*push_struct_unaligned(&pdb_information_stream, u32) = named_stream_table_capacity;
        
        u32 present_bits_word_count = ((named_stream_table_capacity + 31) & ~31)/32;
        
        /*present_bits.word_count*/*push_struct_unaligned(&pdb_information_stream, u32) = present_bits_word_count;
        
        u32 *present_bits_words = push_array_unaligned(&pdb_information_stream, u32, present_bits_word_count);
        for(u32 named_stream_table_index = 0; named_stream_table_index < named_stream_table_capacity; named_stream_table_index++){
            u32 word_index = named_stream_table_index / (sizeof(u32) * 8);
            u32 bit_index  = named_stream_table_index % (sizeof(u32) * 8);
            
            if(named_stream_table_entries[named_stream_table_index].value != 0){
                present_bits_words[word_index] |= (1u << bit_index);
            }
        }
        
        /*deleted_bits.word_count*/*push_struct_unaligned(&pdb_information_stream, u32) = 0;
        
        // struct { u32 key; u32 value; } entries[amount_of_entries];
        for(u32 named_stream_table_index = 0; named_stream_table_index < named_stream_table_capacity; named_stream_table_index++){
            if(named_stream_table_entries[named_stream_table_index].value != 0){
                *push_struct_unaligned(&pdb_information_stream, struct named_stream_table_entry) = named_stream_table_entries[named_stream_table_index];
            }
        }
        
        /*unused*/*push_struct_unaligned(&pdb_information_stream, u32) = 0;
        
        // Feature code: 
        *push_struct_unaligned(&pdb_information_stream, u32) = /*impvVC140*/20140508;
    }
    
    // @cleanup: this needs growing later!
    char *names_stream_buckets[0x100] = {0};
    struct memory_arena names_stream = create_memory_arena(giga_bytes(8));
    struct names_stream_header{
        u32 signature;
        u32 hash_version;
        u32 string_buffer_byte_size;
        char string_buffer[];
    } *names_stream_header = push_struct(&names_stream, struct names_stream_header);
    names_stream_header->signature = 0xEFFEEFFE;
    names_stream_header->hash_version = 1;
    names_stream_header->string_buffer_byte_size = 1;
    
    // "The first string inside the string buffer always has to be the zero-sized string, 
    //  as a zero offset is also used as an invalid offset in the hash table."
    push_struct(&names_stream, u8); // zero-sized string!
    
    
    struct memory_arena tpi_stream = create_memory_arena(giga_bytes(8));
    struct memory_arena ipi_stream = create_memory_arena(giga_bytes(8));
    
    struct memory_arena tpi_hash_stream = create_memory_arena(giga_bytes(8));
    struct memory_arena ipi_hash_stream = create_memory_arena(giga_bytes(8));
    
    {
        struct tpi_stream_header{
            u32 version;
            u32 header_size;
            u32 minimal_type_index;
            u32 one_past_last_type_index;
            u32 byte_count_of_type_record_data_following_the_header;
            
            u16 stream_index_of_hash_stream;
            u16 stream_index_of_auxiliary_hash_stream;
            
            u32 hash_key_size;
            u32 number_of_hash_buckets;
            
            u32 hash_table_index_buffer_offset;
            u32 hash_table_index_buffer_length;
            
            u32 index_offset_buffer_offset;
            u32 index_offset_buffer_length;
            
            u32 udt_order_adjust_table_offset;
            u32 udt_order_adjust_table_length;
        };
        
        struct tpi_stream_header *tpi_header = push_struct(&tpi_stream, struct tpi_stream_header);
        struct tpi_stream_header *ipi_header = push_struct(&ipi_stream, struct tpi_stream_header);
        
        struct tpi_index_offset_buffer_entry{
            u32 type_index;
            u32 offset_in_record_data;
        };
        
        struct tpi_index_offset_buffer_entry *tpi_index_offset_buffer_last_entry = push_struct(&tpi_hash_stream, struct tpi_index_offset_buffer_entry);
        tpi_index_offset_buffer_last_entry->type_index = 0x1000;
        struct tpi_index_offset_buffer_entry *ipi_index_offset_buffer_last_entry = push_struct(&ipi_hash_stream, struct tpi_index_offset_buffer_entry);
        ipi_index_offset_buffer_last_entry->type_index = 0x1000;
        
        u32 ipi_type_index_at = 0x1000;
        u32 tpi_type_index_at = 0x1000;
        
        u32 unhandled_type_indices[0x100];
        u32 unhandled_type_indices_at = 0;
        
        struct memory_arena hash_table_arena = create_memory_arena(giga_bytes(8));
        
        static struct tpi_hash_table_entry{
            struct tpi_hash_table_entry *next;
            u32 type_index;
            struct codeview_type_record_header *type_record;
        } *tpi_hash_table[0x3ffff] = {0}, *ipi_hash_table[0x3ffff] = {0};
        
        for(u32 object_file_index = 0; object_file_index < write_pdb_information->amount_of_object_files; object_file_index++){
            
            struct stream type_information = write_pdb_information->per_object[object_file_index].type_information;
            
            u32 signature;
            if(stream_read(&type_information, &signature, sizeof(signature)) || signature != /*CV_SIGNATURE_C13*/4) continue;
            
            // We daisy chain this map into 'arena', whenever we handle a type record below.
            u32 *object_file_type_index_to_pdb_file_type_index_map = push_array(&arena, u32, 0);
            
            struct codeview_type_record_header{
                u16 length;
                u16 kind;
            } type_record_header;
            
            u32 object_file_type_index = 0x1000;
            
            while(!stream_read(&type_information, &type_record_header, sizeof(type_record_header))){
                
                int record_size = type_record_header.length - sizeof(type_record_header.kind);
                if(record_size < 0) break;
                
                u8 *record_data = stream_read_array_by_pointer(&type_information, 1, record_size);
                if(!record_data) break;
                
                // 
                // We need to remap all of the type indices used by the type records,
                // from the object file local ones to the pdb ones.
                // 
                
#define remap_type_index(v) (v) = ((v) < 0x1000 ? (v) : ((v >= object_file_type_index) ? 0 : object_file_type_index_to_pdb_file_type_index_map[(v)-0x1000]))
                
                switch(type_record_header.kind){
                    
                    case /*LF_MODIFIER*/0x1001:
                    case /*LF_POINTER */0x1002:{
                        u32 *type_index = (void *)record_data;
                        if(sizeof(*type_index) >= record_size) break;
                        
                        remap_type_index(*type_index);
                    }break;
                    
                    case /*LF_PROCEDURE*/0x1008:{
                        struct {
                            u32 return_value;
                            u8 call_type;
                            u8 function_attributes;
                            u16 parameter_count;
                            u32 arglist;
                        } *procedure = (void *)record_data;
                        
                        if(sizeof(*procedure) > record_size) break;
                        
                        remap_type_index(procedure->return_value);
                        remap_type_index(procedure->arglist);
                    }break;
                    
                    case /*LF_ARGLIST*/0x1201:{
                        
                        struct{
                            u32 count;
                            u32 argument_type[];
                        } *arglist = (void *)record_data;
                        
                        if(sizeof(*arglist) > record_size) break;
                        
                        if((u64)arglist->count * sizeof(u32) > (u64)record_size - sizeof(u32)) break;
                        
                        for(u32 argument_index = 0; argument_index < arglist->count; argument_index++){
                            remap_type_index(arglist->argument_type[argument_index]);
                        }
                    }break;
                    
                    case /*LF_FIELDLIST*/0x1203:{
                        
                        // LF_FIELDLIST consist of a sequence of sub-records that describe the 
                        // struct, union or enum members in the form of LF_MEMBER or LF_ENUMERATE entries.
                        // There is also a special LF_INDEX entry for LF_FIELDLIST which would exceed
                        // the u16-length field.
                        // One annoying thing is that these sub-records are not sized.
                        
                        struct stream record_stream = {
                            .data = record_data,
                            .size = record_size,
                        };
                        
                        
                        while(record_stream.offset + sizeof(u16) <= record_stream.size){
                            switch(*(u16 *)(record_stream.data + record_stream.offset)){
                                
                                case /*LF_ENUMERATE*/0x1502:{
                                    struct {
                                        u16 kind;
                                        u16 attributes;
                                        //  numeric_leaf field_offset;
                                        //  char name[];
                                    } *enumerate = stream_read_array_by_pointer(&record_stream, sizeof(*enumerate), 1);
                                    if(!enumerate) break;
                                    
                                    pdb_stream_skip_numeric_leaf(&record_stream);
                                    pdb_stream_skip_zero_terminated_string(&record_stream);
                                }break;
                                
                                case /*LF_MEMBER*/0x150d:{
                                    struct {
                                        u16 kind;
                                        u16 attributes;
                                        u32 type_index;
                                        //  numeric_leaf field_offset;
                                        //  char name[];
                                    } *member = stream_read_array_by_pointer(&record_stream, sizeof(*member), 1);
                                    if(!member) break;
                                    
                                    remap_type_index(member->type_index);
                                    
                                    pdb_stream_skip_numeric_leaf(&record_stream);
                                    pdb_stream_skip_zero_terminated_string(&record_stream);
                                    
                                }break;
                                
                                case /*LF_INDEX*/0x1404:{
                                    struct {
                                        u16 kind;
                                        u16 padding;
                                        u32 type_index;
                                    } *index = stream_read_array_by_pointer(&record_stream, sizeof(*index), 1);
                                    if(!index) break;
                                    remap_type_index(index->type_index);
                                }break;
                                
                                default:{
                                    print("Warning: Unhandled entry in LF_FIELDLIST of kind 0x%hx. Unable to recover for this fieldlist.\n", *(u16 *)(record_stream.data + record_stream.offset));
                                    
                                    record_stream.offset = record_stream.size; // break the outer loop.
                                }break;
                            }
                            
                            record_stream.offset = (record_stream.offset + 3) & ~3;
                        }
                    }break;
                    
                    case /*LF_ARRAY*/0x1503:{
                        struct{
                            u32 element_type;
                            u32 index_type;
                        } *array = (void *)record_data;
                        
                        if(sizeof(*array) > record_size) break;
                        
                        remap_type_index(array->element_type);
                        remap_type_index(array->index_type);
                    }break;
                        
                    case /*LF_STRUCTURE*/0x1505:{
                        struct{
                            u16 count;
                            u16 property;
                            u32 fieldlist;
                            u32 derived;
                            u32 vshape;
                        } *structure = (void *)record_data;
                        
                        if(sizeof(*structure) > record_size) break;
                        
                        remap_type_index(structure->fieldlist);
                        remap_type_index(structure->derived);
                        remap_type_index(structure->vshape);
                    }break;
                    
                    case /*LF_UNION*/0x1506:{
                        struct{
                            u16 count;
                            u16 property;
                            u32 fieldlist;
                        } *lf_union = (void *)record_data;
                        
                        if(sizeof(*lf_union) > record_size) break;
                        
                        remap_type_index(lf_union->fieldlist);
                    }break;
                    case /*LF_ENUM*/0x1507:{
                        struct{
                            u16 count;
                            u16 property;
                            u32 underlying_type;
                            u32 fieldlist;
                        } *enumeration = (void *)record_data;
                        
                        if(sizeof(*enumeration) > record_size) break;
                        
                        remap_type_index(enumeration->underlying_type);
                        remap_type_index(enumeration->fieldlist);
                    }break;
                    
                    // 
                    // Id Records:
                    // 
                    
                    case /*LF_FUNC_ID*/0x1601:{
                        struct {
                            u32 scope_id;
                            u32 type;
                        } *func_id = (void *)record_data;
                        
                        if(sizeof(*func_id) > record_size) break;
                        
                        remap_type_index(func_id->scope_id);
                        remap_type_index(func_id->type);
                    }break;
                    
                    case /*LF_BUILDINFO*/0x1603:{
                        struct{
                            u16 count;
                        } *buildinfo = (void *)record_data;
                        
                        if(sizeof(*buildinfo) > record_size) break;
                        
                        u32 *arg = (u32 *)(buildinfo + 1);
                        if((u64)buildinfo->count * sizeof(u32) > (u64)record_size - sizeof(u32)) break;
                        
                        for(u32 argument_index = 0; argument_index < buildinfo->count; argument_index++){
                            remap_type_index(arg[argument_index]);
                        }
                    }break;
                    
                    case /*LF_SUBSTR_LIST*/0x1604:{
                        
                        // @note: This is the same code as arglist, because its the same record, 
                        //        but I want to keep types and records seperate.
                        
                        struct{
                            u32 count;
                            u32 substring[];
                        } *substring_list = (void *)record_data;
                        
                        if(sizeof(*substring_list) > record_size) break;
                        
                        if((u64)substring_list->count * sizeof(u32) > (u64)record_size - sizeof(u32)) break;
                        
                        for(u32 argument_index = 0; argument_index < substring_list->count; argument_index++){
                            remap_type_index(substring_list->substring[argument_index]);
                        }
                    }break;
                    case /*LF_STRING_ID*/0x1605:{
                        
                        u32 *id = (u32 *)record_data;
                        if(sizeof(*id) > record_size) break;
                        
                        remap_type_index(*id);
                    }break;
                    
                    case /*LF_UDT_SRC_LINE*/0x1606:{
                        
                        // @incomplete: we are supposed to make this into a LF_UDT_MOD_SRC_LINE entry.
                        
                        struct {
                            u32 type_index;
                            u32 src_file_string_id;
                            u32 line_number;
                        } *udt_src_line  = (void *)record_data;
                        
                        if(sizeof(*udt_src_line) > record_size) break;
                        
                        remap_type_index(udt_src_line->type_index);
                        remap_type_index(udt_src_line->src_file_string_id);
                    }break;
                    
                    default:{
                        int found = 0;
                        for(u32 index = 0; index < unhandled_type_indices_at; index++){
                            if(unhandled_type_indices[index] == type_record_header.kind){
                                found = 1;
                                break;
                            }
                        }
                        
                        if(!found){
                            unhandled_type_indices[unhandled_type_indices_at++] = type_record_header.kind;
                        }
                        
                        print("Warning: Unknown type record kind 0x%hx ignored. This might lead to incorrect type information in the pdb.\n", type_record_header.kind);
                    }break;
                }
                
                // 
                // Push the type record to the stream and insert an element into the map.
                // 
                
                u32 pdb_type_index;
                
                // 
                // Add the type record either to the IPI or the TPI stream.
                // 
                struct codeview_type_record_header *record = (void *)(record_data - sizeof(type_record_header));
                
                struct memory_arena *stream, *hash_stream;
                struct tpi_hash_table_entry *(*hash_table)[array_count(tpi_hash_table)];
                struct tpi_stream_header *stream_header;
                struct tpi_index_offset_buffer_entry **index_offset_buffer_last_entry;
                u32 *type_index_at;
                
                if(0x1600 <= type_record_header.kind && type_record_header.kind < 0x1700){
                    // This record is a Id-record.
                    hash_table                     = &ipi_hash_table;
                    stream                         = &ipi_stream;
                    hash_stream                    = &ipi_hash_stream;
                    stream_header                  =  ipi_header;
                    index_offset_buffer_last_entry = &ipi_index_offset_buffer_last_entry;
                    type_index_at                  = &ipi_type_index_at;
                }else{
                    // This record is a Type-record.
                    hash_table                     = &tpi_hash_table;
                    stream                         = &tpi_stream;
                    hash_stream                    = &tpi_hash_stream;
                    stream_header                  =  tpi_header;
                    index_offset_buffer_last_entry = &tpi_index_offset_buffer_last_entry;
                    type_index_at                  = &tpi_type_index_at;
                }
                
                struct tpi_hash_table_entry *hash_table_entry = 0;
                
                u32 hash_index = tpi_hash_table_index_for_record(record, array_count(*hash_table));
                
                for(hash_table_entry = (*hash_table)[hash_index]; hash_table_entry; hash_table_entry = hash_table_entry->next){
                    if(memcmp(hash_table_entry->type_record, record, sizeof(*record) + record_size) == 0){
                        break;
                    }
                }
                
                if(hash_table_entry){
                    pdb_type_index = hash_table_entry->type_index;
                }else{
                    // Emit a 'index offset buffer' entry if we need to.
                    u32 current_offset = (u32)(arena_current(stream) - (u8 *)(stream_header + 1));
                    if(current_offset + record_size + sizeof(*record) >= (*index_offset_buffer_last_entry)->offset_in_record_data + 8 * 0x1000){
                        (*index_offset_buffer_last_entry) = push_struct(hash_stream, struct tpi_index_offset_buffer_entry);
                        
                        (*index_offset_buffer_last_entry)->offset_in_record_data = current_offset;
                        (*index_offset_buffer_last_entry)->type_index = *type_index_at;
                    }
                    
                    u8 *copied_record = push_array(stream, u8, sizeof(struct codeview_type_record_header) + record_size);
                    memcpy(copied_record, record, sizeof(struct codeview_type_record_header) + record_size);
                    
                    pdb_type_index = (*type_index_at)++;
                    
                    hash_table_entry = push_struct(&hash_table_arena, struct tpi_hash_table_entry);
                    hash_table_entry->type_index  = pdb_type_index;
                    hash_table_entry->type_record = (void *)copied_record;
                    
                    hash_table_entry->next = (*hash_table)[hash_index];
                    (*hash_table)[hash_index] = hash_table_entry;
                }
                
                /*object_file_type_index_to_pdb_file_type_index_map = */
                *push_struct(&arena, u32) = pdb_type_index;
                object_file_type_index++;
            }
        }
        
        tpi_header->version = 20040203;
        tpi_header->header_size = sizeof(*tpi_header);
        tpi_header->minimal_type_index = 0x1000;
        tpi_header->one_past_last_type_index = tpi_type_index_at;
        tpi_header->byte_count_of_type_record_data_following_the_header = arena_current(&tpi_stream) - (u8 *)(tpi_header + 1);
        tpi_header->stream_index_of_hash_stream = PDB_STREAM_tpi_hash;
        tpi_header->stream_index_of_auxiliary_hash_stream = (u16)-1;
        
        tpi_header->index_offset_buffer_offset = 0;
        tpi_header->index_offset_buffer_length = arena_current(&tpi_hash_stream) - tpi_hash_stream.base;
        
        // 
        // Serialize the tpi_hash_table.
        // 
        u32 *tpi_hash_table_index_buffer = push_array(&tpi_hash_stream, u32, tpi_type_index_at - 0x1000);
        
        for(u32 index = 0; index < array_count(tpi_hash_table); index++){
            for(struct tpi_hash_table_entry *entry = tpi_hash_table[index]; entry; entry = entry->next){
                tpi_hash_table_index_buffer[entry->type_index - 0x1000] = index;
            }
        }
        
        tpi_header->hash_key_size = 4;
        tpi_header->number_of_hash_buckets = array_count(tpi_hash_table);
        tpi_header->hash_table_index_buffer_offset = (u8 *)tpi_hash_table_index_buffer - tpi_hash_stream.base;
        tpi_header->hash_table_index_buffer_length = (tpi_type_index_at - 0x1000) * sizeof(*tpi_hash_table_index_buffer);
        
        tpi_header->udt_order_adjust_table_offset = 0;
        tpi_header->udt_order_adjust_table_length = 0;
        
        ipi_header->version = 20040203;
        ipi_header->header_size = sizeof(*ipi_header);
        ipi_header->minimal_type_index = 0x1000;
        ipi_header->one_past_last_type_index = ipi_type_index_at;
        ipi_header->byte_count_of_type_record_data_following_the_header = arena_current(&ipi_stream) - (u8 *)(ipi_header + 1);
        ipi_header->stream_index_of_hash_stream = PDB_STREAM_ipi_hash;
        ipi_header->stream_index_of_auxiliary_hash_stream = (u16)-1;
        
        ipi_header->index_offset_buffer_offset = 0;
        ipi_header->index_offset_buffer_length = arena_current(&ipi_hash_stream) - ipi_hash_stream.base;
        
        // 
        // Serialize the ipi_hash_table.
        // 
        u32 *ipi_hash_table_index_buffer = push_array(&ipi_hash_stream, u32, ipi_type_index_at - 0x1000);
        
        for(u32 index = 0; index < array_count(ipi_hash_table); index++){
            for(struct tpi_hash_table_entry *entry = ipi_hash_table[index]; entry; entry = entry->next){
                ipi_hash_table_index_buffer[entry->type_index - 0x1000] = index;
            }
        }
        
        ipi_header->hash_key_size = 4;
        ipi_header->number_of_hash_buckets = array_count(tpi_hash_table);
        ipi_header->hash_table_index_buffer_offset = (u8 *)ipi_hash_table_index_buffer - ipi_hash_stream.base;
        ipi_header->hash_table_index_buffer_length = (ipi_type_index_at - 0x1000) * sizeof(*ipi_hash_table_index_buffer);
        
        ipi_header->udt_order_adjust_table_offset = 0;
        ipi_header->udt_order_adjust_table_length = 0;
        
        if(unhandled_type_indices_at > 0){
            print("unhandled type indices:\n");
            for(u32 index = 0; index < unhandled_type_indices_at; index++){
                print("    0x%x\n", unhandled_type_indices[index]);
            }
        }
    }
    
    u64 amount_of_streams = PDB_CURRENT_AMOUNT_OF_STREAMS + write_pdb_information->amount_of_object_files;
    struct msf_stream *streams = push_array(&arena, struct msf_stream, amount_of_streams);
    
    // @cleanup: allocate one per module symbol stream?
    struct memory_arena module_symbol_stream = create_memory_arena(giga_bytes(8));
    
    struct module_sizes{
        u32 symbols_size;
        u32 lines_size;
    } *module_sizes = push_array(&arena, struct module_sizes, write_pdb_information->amount_of_object_files);
    
    for(u32 object_file_index = 0; object_file_index < write_pdb_information->amount_of_object_files; object_file_index++){
        
        struct stream symbol_information = write_pdb_information->per_object[object_file_index].symbol_information;
        
        streams[PDB_STREAM_module_symbol_stream_base + object_file_index].data = arena_current(&module_symbol_stream);
                
        print("\n%s:\n", write_pdb_information->per_object[object_file_index].file_name);
        
        u32 signature;
        if(stream_read(&symbol_information, &signature, sizeof(signature)) || signature != /*CV_SIGNATURE_C13*/4) continue;
        
        // 
        // Copy out the signature to the symbol subsection of the module symobl stream.
        // 
        
        u8 *symbols_start = arena_current(&module_symbol_stream);
        *push_struct(&module_symbol_stream, u32) = signature;
        
        struct codeview_debug_subsection_header{
            u32 type;
            u32 length;
        } debug_subsection_header;
        
        // 
        // We iterate all of the subsection _once_ for all of the symobls (DEBUG_S_SYMBOLS)
        // and then another time for all of the line information related entries. (DEBUG_S_LINES, DEBUG_S_STRINGTABLE, DEBUG_S_FILECHKSMS)
        // 
        
        while(!stream_read(&symbol_information, &debug_subsection_header, sizeof(debug_subsection_header))){
            print(debug_subsection_header);
            
            if(debug_subsection_header.type == /*DEBUG_S_SYMBOLS*/0xf1){
                // @incomplete: Add the symbol information to the pdb.
            }
            
            u32 size = (debug_subsection_header.length + 3) & ~3;
            stream_read_array_by_pointer(&symbol_information, 1, size); // skip the data.
        }
        
        u64 symbols_size = arena_current(&module_symbol_stream) - symbols_start;
        
        // 
        // Extract line information.
        // 
        u8 *lines_start = arena_current(&module_symbol_stream);
        
        u8 *filechksms = 0;
        u32 filechksms_size = 0;
        
        char *string_table = 0;
        u32 string_table_size = 0;
        
        // 
        // Reset the offset in the symbol information stream and read all line information related entries.
        // 
        symbol_information.offset = /*signature*/sizeof(u32);
        while(!stream_read(&symbol_information, &debug_subsection_header, sizeof(debug_subsection_header))){
            print("wat {}\n", debug_subsection_header);
            
            u32 aligned_subsection_size = (debug_subsection_header.length + 3) & ~3;
            u8 *subsection_data = stream_read_array_by_pointer(&symbol_information, 1, aligned_subsection_size);
            
            if(debug_subsection_header.type == /*DEBUG_S_LINES*/0xf2){
                // These can simply be copied out into the c13 line data.
                *push_struct(&module_symbol_stream, struct codeview_debug_subsection_header) = debug_subsection_header;
                
                u8 *dest = push_array(&module_symbol_stream, u8, aligned_subsection_size);
                memcpy(dest, subsection_data, aligned_subsection_size);
            }
            
            if(debug_subsection_header.type == /*DEBUG_S_STRINGTABLE*/0xf3){
                // These have to get added to the /names string table.
                string_table      = (char *)subsection_data;
                string_table_size = debug_subsection_header.length;
            }
            
            if(debug_subsection_header.type == /*DEBUG_S_FILECHKSMS*/0xf4){
                print("hello {}\n", debug_subsection_header);
                filechksms      = subsection_data;
                filechksms_size = debug_subsection_header.length;    
            }
        }
        
        // 
        // Iterate all of the file checksums and patch the string offset.
        // 
        struct stream file_checksums_stream = { .data = filechksms, .size = filechksms_size };
        
        while(1){
            
            struct codeview_line_file_checksums{
                u32 offset_in_string_table;
                u8  checksum_size;
                u8  checksum_kind;
                u8  checksum[];
            } *file_checksum_entry = stream_read_array_by_pointer(&file_checksums_stream, 6, 1);
            if(!file_checksum_entry) break;
            
            // @cleanup: sanity-check this.
            char *string = string_table + file_checksum_entry->offset_in_string_table;
            size_t string_length = strlen(string);
            u32 hash = pdb_hash_index((u8 *)string, string_length, (u32)-1);
            
            s64 offset_in_string_table = -1;
            
            // @cleanup: growing and failiure.
            for(u32 index = 0; index < array_count(names_stream_buckets); index++){
                u32 hash_index = (hash + index) % array_count(names_stream_buckets);
                
                char *bucket = names_stream_buckets[hash_index];
                if(!bucket){
                    char *string_in_string_buffer = push_array(&names_stream, char, string_length + 1);
                    memcpy(string_in_string_buffer, string, string_length + 1);
                    names_stream_buckets[hash_index] = string_in_string_buffer;
                    offset_in_string_table = string_in_string_buffer - names_stream_header->string_buffer;
                    break;
                }
                
                if(strcmp(bucket, string) == 0){
                    offset_in_string_table = bucket - names_stream_header->string_buffer;
                    break;
                }
            }
            
            assert(offset_in_string_table != -1);
            file_checksum_entry->offset_in_string_table = (u32)offset_in_string_table;
            
            u32 full_aligned_size = ((file_checksum_entry->checksum_size + 6) + 3) & ~3;
            
            // skip the checksum.
            stream_read_array_by_pointer(&file_checksums_stream, full_aligned_size - 6, 1);
        }
        
        // 
        // Write out the file checksums header.
        // 
        debug_subsection_header.type   = /*DEBUG_S_FILECHKSMS*/0xf4;
        debug_subsection_header.length = filechksms_size;
        *push_struct(&module_symbol_stream, struct codeview_debug_subsection_header) = debug_subsection_header;
        
        u8 *filechksms_data = push_array(&module_symbol_stream, u8, (filechksms_size + 3) & ~3);
        memcpy(filechksms_data, filechksms, filechksms_size);
        
        u64 lines_size = arena_current(&module_symbol_stream) - lines_start;
        
        *push_struct(&module_symbol_stream, u32) = 0; // @incomplete: amount_of_global_references
        
        streams[PDB_STREAM_module_symbol_stream_base + object_file_index].size = arena_current(&module_symbol_stream) - streams[PDB_STREAM_module_symbol_stream_base + object_file_index].data;
        
        module_sizes[object_file_index].lines_size = (u32)lines_size;
        module_sizes[object_file_index].symbols_size = (u32)symbols_size;
    }
    
    struct memory_arena dbi_stream = create_memory_arena(giga_bytes(8));
    {
        // 
        // Fill out the DBI stream.
        // 
        
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
            u16 version_number_of_mspdb_dll_which_build_the_pdb;
            u16 stream_index_of_the_symbol_record_stream;
            u16 build_number_of_mspdb_dll_which_build_the_pdb;
            
            u32 byte_size_of_the_module_information_substream;   // substream 0
            u32 byte_size_of_the_section_contribution_substream; // substream 1
            u32 byte_size_of_the_section_map_substream;          // substream 2
            u32 byte_size_of_the_source_information_substream;   // substream 3
            u32 byte_size_of_the_type_server_map_substream;      // substream 4
            
            u32 index_of_the_MFC_type_server_in_type_server_map_substream;
            
            u32 byte_size_of_the_optional_debug_header_substream; // substream 6
            u32 byte_size_of_the_edit_and_continue_substream;     // substream 5
            
            struct{
                u16 was_linked_incrementally         : 1;
                u16 private_symbols_were_stripped    : 1;
                u16 the_pdb_allows_conflicting_types : 1;
            } flags;
            
            u16 machine_type;
            u32 reserved_padding;
        } *dbi_stream_header = push_struct(&dbi_stream, struct dbi_stream_header);
        
        dbi_stream_header->version_signature = (u32)-1;
        dbi_stream_header->version = 19990903;
        dbi_stream_header->age = 1;
        
        dbi_stream_header->stream_index_of_the_global_symbol_index_stream = (u16)-1;
        dbi_stream_header->stream_index_of_the_public_symbol_index_stream = (u16)-1;
        dbi_stream_header->stream_index_of_the_symbol_record_stream = (u16)-1;
        
        // @cleanup: check these?
        dbi_stream_header->toolchain_version.is_new_version_format = 1;
        dbi_stream_header->toolchain_version.major_version = 14;
        dbi_stream_header->toolchain_version.minor_version = 29;
        dbi_stream_header->version_number_of_mspdb_dll_which_build_the_pdb = 30151;
        dbi_stream_header->build_number_of_mspdb_dll_which_build_the_pdb   = 0;
        
        // Should we set `dbi_stream_header->flags.the_pdb_allows_conflicting_types`?
        dbi_stream_header->machine_type = /*CV_CFL_AMD64*/0xd0;
        
        struct pdb_module_information{
            u32 unused;
            
            struct pdb_section_contribution first_code_contribution;
            
            struct{
                u16 was_written : 1;
                u16 edit_and_continue_enabled : 1;
                u16 unused : 6;
                u16 TSM_index : 8;
            } flags;
            
            u16 stream_index_of_module_symbol_stream;
            
            u32 byte_size_of_symbol_information;
            u32 byte_size_of_c11_line_information;
            u32 byte_size_of_c13_line_information;
            
            u16 amount_of_source_files;
            u16 padding;
            u32 unused2;
            
            u32 edit_and_continue_source_file_string_index;
            u32 edit_and_continue_pdb_file_string_index;
            
            char module_name_and_file_name[];
        } **module_information_per_object_file = push_array(&arena, struct pdb_module_information *, write_pdb_information->amount_of_object_files);
        
        struct pdb_module_information *linker_module = 0;
        
        {
            // 
            // Module Information Substream.
            // 
            
            u8 *module_information_substream_start = arena_current(&dbi_stream);
            
            for(u32 object_file_index = 0; object_file_index < write_pdb_information->amount_of_object_files; object_file_index++){
                struct pdb_module_information *module_information = push_struct(&dbi_stream, struct pdb_module_information);
                module_information_per_object_file[object_file_index] = module_information;
                
                module_information->first_code_contribution = (struct pdb_section_contribution){
                    .section_id = -1,
                    .size = -1,
                    .module_index = -1,
                };
                
                // @incomplete:
                module_information->stream_index_of_module_symbol_stream = (u16)(PDB_STREAM_module_symbol_stream_base + object_file_index);
                module_information->byte_size_of_symbol_information = module_sizes[object_file_index].symbols_size;
                module_information->byte_size_of_c11_line_information = 0;
                module_information->byte_size_of_c13_line_information = module_sizes[object_file_index].lines_size;
                module_information->amount_of_source_files = 0;
                
                char *object_file_name = write_pdb_information->per_object[object_file_index].file_name;
                size_t size = strlen(object_file_name) + 1;
                
                // Module name and object name.
                memcpy(push_array(&dbi_stream, char, size), object_file_name, size);
                memcpy(push_array(&dbi_stream, char, size), object_file_name, size);
                
                // Align the stream on a 4-byte boundary.
                push_array(&dbi_stream, u32, 0);
            }
            
            // @cleanup: Talk abount module alignment in the documentation.
            
            {
                // 
                // Special '* Linker *' module.
                // 
                
                linker_module = push_struct(&dbi_stream, struct pdb_module_information);
                
                linker_module->first_code_contribution = (struct pdb_section_contribution){
                    .section_id = -1,
                    .size = -1,
                    .module_index = -1,
                };
                
                // @incomplete:
                linker_module->stream_index_of_module_symbol_stream = (u16)-1;
                linker_module->byte_size_of_symbol_information = 0;
                linker_module->byte_size_of_c11_line_information = 0;
                linker_module->byte_size_of_c13_line_information = 0;
                linker_module->amount_of_source_files = 0;
                
                // @cleanup: talk about the object name being * Linker * in the Readme.
                char *object_file_name = "* Linker *";
                size_t size = strlen(object_file_name) + 1;
                memcpy(push_array(&dbi_stream, char, size + /*object name = 0*/1), object_file_name, size);
                
                // Align the stream on a 4-byte boundary.
                push_array(&dbi_stream, u32, 0);
            }
            
            size_t module_information_substream_size = arena_current(&dbi_stream) - module_information_substream_start;
            
            dbi_stream_header->byte_size_of_the_module_information_substream = (u32)module_information_substream_size;
        }
        
        {
            // 
            // Section Contribution Substream.
            // 
            
            u8 *section_contribution_substream_start = arena_current(&dbi_stream);
            
            *push_struct(&dbi_stream, u32) = /*section contribution version 1*/0xeffe0000 + 19970605;
            
            struct pdb_section_contribution *section_contributions = push_array(&dbi_stream, struct pdb_section_contribution, write_pdb_information->amount_of_section_contributions);
            
            memcpy(section_contributions, write_pdb_information->section_contributions, sizeof(*section_contributions) * write_pdb_information->amount_of_section_contributions);
            
            size_t section_contribution_substream_size = arena_current(&dbi_stream) - section_contribution_substream_start;
            
            dbi_stream_header->byte_size_of_the_section_contribution_substream = (u32)section_contribution_substream_size;
        }
        
        {
            // 
            // Section Map Substream
            // 
            u8 *section_map_substream_start = arena_current(&dbi_stream);
            
            *push_struct(&dbi_stream, u16) = /*number_of_section_descriptors        */write_pdb_information->amount_of_image_sections + 1;
            *push_struct(&dbi_stream, u16) = /*number_of_logical_section_descriptors*/write_pdb_information->amount_of_image_sections + 1;
            
            struct pdb_section_map_entry{
                u16 flags;
                u16 logical_overlay_number;
                u16 group;
                u16 frame;
                u16 section_name;
                u16 class_name;
                u32 offset;
                u32 section_size;
            } *section_map = push_array(&dbi_stream, struct pdb_section_map_entry, write_pdb_information->amount_of_image_sections + 1);
            
            // @cleanup: flags?
            
            for(u32 section_index = 0; section_index < write_pdb_information->amount_of_image_sections; section_index++){
                section_map[section_index].frame = section_index + 1;
                section_map[section_index].section_name = (u16)-1;
                section_map[section_index].class_name = (u16)-1;
                section_map[section_index].section_size = write_pdb_information->image_section_headers[section_index].virtual_size;
            }
            
            u32 section_index = write_pdb_information->amount_of_image_sections;
            section_map[section_index].frame = section_index + 1;
            section_map[section_index].section_name = (u16)-1;
            section_map[section_index].class_name = (u16)-1;
            section_map[section_index].section_size = 0xffffffff;
            
            size_t section_map_substream_size = arena_current(&dbi_stream) - section_map_substream_start;
            dbi_stream_header->byte_size_of_the_section_map_substream = (u32)section_map_substream_size;
        }
        
        {
            // 
            // Source Information Substream
            // @incomplete: For now this is stubbed.
            // 
            u8 *source_information_substream_start = arena_current(&dbi_stream);
            
            u16 amount_of_modules = (u16)(write_pdb_information->amount_of_object_files + 1);
            
            *push_struct(&dbi_stream, u16) = amount_of_modules;
            *push_struct(&dbi_stream, u16) = /* truncated_amount_of_source_files */0;
            
            /*source_file_base_index_per_module*/push_array(&dbi_stream, u16, amount_of_modules);
            /*amount_of_source_files_per_module*/push_array(&dbi_stream, u16, amount_of_modules);
            
            // @cleanup: source_file_name_offset_in_string_buffer is aligned or not Document?
            /*source_file_name_offset_in_string_buffer*/;
            
            /*string_buffer*/push_struct(&dbi_stream, u8);
            
            // Align the stream on a 4-byte boundary.
            push_array(&dbi_stream, u32, 0);
            
            size_t source_information_substream_size = arena_current(&dbi_stream) - source_information_substream_start;
            dbi_stream_header->byte_size_of_the_source_information_substream = (u32)source_information_substream_size;
        }
        
        {   
            u8 *edit_and_continue_substream_start = arena_current(&dbi_stream);
            
            // 
            // The Edit and continue substream is a version of the /names stream.
            // Here is a stub!
            // 
            // Layout:
            //     u32 signature;
            //     u32 hash_version;
            //     u32 string_buffer_byte_size;
            //     u8  string_buffer[string_buffer_byte_size];
            //     u32 bucket_count;
            //     u32 buckets[bucket_count];
            //     u32 amount_of_strings;
            // 
            
            *push_struct(&dbi_stream, u32) = /*signature*/0xEFFEEFFE;
            *push_struct(&dbi_stream, u32) = /*hash_version*/1;
            
            u32 *string_buffer_byte_size = push_struct(&dbi_stream, u32);
            u8 *string_buffer = push_array(&dbi_stream, u8, 0);
            
            // "The first string inside the string buffer always has to be the zero-sized string, 
            //  as a zero offset is also used as an invalid offset in the hash table."
            push_struct(&dbi_stream, u8); // zero-sized string!
            
            *string_buffer_byte_size = push_array(&dbi_stream, u8, 0) - string_buffer;
            
            // @WARNING: "Importantly, the size of the string buffer is not aligned, 
            //            thus usually the rest of the stream is unaligned."
            
            *push_struct_unaligned(&dbi_stream, u32) = /*bucket_count*/1;
            *push_struct_unaligned(&dbi_stream, u32) = /*bucket[0]*/0;
            
            *push_struct_unaligned(&dbi_stream, u32) = /*amount_of_strings*/0;
            
            size_t edit_and_continue_substream_size = arena_current(&dbi_stream) - edit_and_continue_substream_start;
            dbi_stream_header->byte_size_of_the_edit_and_continue_substream = (u32)edit_and_continue_substream_size;
        }
        
        {
            struct optional_debug_header_substream{
                u16 stream_index_of_fpo_data;
                u16 stream_index_of_exception_data;
                u16 stream_index_of_fixup_data;
                u16 stream_index_of_omap_to_src_data;
                u16 stream_index_of_omap_from_src_data;
                u16 stream_index_of_section_header_dump;
                u16 stream_index_of_clr_token_to_clr_record_id;
                u16 stream_index_of_xdata;
                u16 stream_index_of_pdata;
                u16 stream_index_of_new_fpo_data;
                u16 stream_index_of_original_section_header_dump;
            } *debug_headers = push_struct_unaligned(&dbi_stream, struct optional_debug_header_substream);
            memset(debug_headers, 0xff, sizeof(*debug_headers)); // Initialize all to "not present".
            
            debug_headers->stream_index_of_section_header_dump = PDB_STREAM_section_header_dump;
            
            dbi_stream_header->byte_size_of_the_optional_debug_header_substream = sizeof(*debug_headers);
        }
    }
    
    {
        // 
        // Finish the /names stream.
        // 
    
        names_stream_header->string_buffer_byte_size = push_array(&names_stream, char, 0) - names_stream_header->string_buffer;
        
        // @WARNING: "Importantly, the size of the string buffer is not aligned, 
        //            thus usually the rest of the stream is unaligned."
        
        u32 bucket_count = array_count(names_stream_buckets);
        
        *push_struct_unaligned(&names_stream, u32) = bucket_count;
        u32 *buckets = push_array_unaligned(&names_stream, u32, bucket_count);
        
        u32 amount_of_strings = 0;
        for(u32 bucket_index = 0; bucket_index < bucket_count; bucket_index++){
            if(names_stream_buckets[bucket_index] != 0){
                buckets[bucket_index] = names_stream_buckets[bucket_index] - names_stream_header->string_buffer;
                amount_of_strings += 1;
            }
        }
        
        *push_struct_unaligned(&names_stream, u32) = amount_of_strings;
    }
    
    streams[PDB_STREAM_pdb_information].data = pdb_information_stream.base;
    streams[PDB_STREAM_pdb_information].size = arena_current(&pdb_information_stream) - pdb_information_stream.base;
    
    streams[PDB_STREAM_tpi].data = tpi_stream.base,
    streams[PDB_STREAM_tpi].size = arena_current(&tpi_stream) - tpi_stream.base,
    
    streams[PDB_STREAM_dbi].data = dbi_stream.base,
    streams[PDB_STREAM_dbi].size = arena_current(&dbi_stream) - dbi_stream.base,
    
    streams[PDB_STREAM_ipi].data = ipi_stream.base,
    streams[PDB_STREAM_ipi].size = arena_current(&ipi_stream) - ipi_stream.base,
    
    streams[PDB_STREAM_tpi_hash].data = tpi_hash_stream.base,
    streams[PDB_STREAM_tpi_hash].size = arena_current(&tpi_hash_stream) - tpi_hash_stream.base,
    
    streams[PDB_STREAM_ipi_hash].data = ipi_hash_stream.base,
    streams[PDB_STREAM_ipi_hash].size = arena_current(&ipi_hash_stream) - ipi_hash_stream.base,
    
    streams[PDB_STREAM_names].data = names_stream.base;
    streams[PDB_STREAM_names].size = arena_current(&names_stream) - names_stream.base;
    
    streams[PDB_STREAM_section_header_dump].data = (u8 *)write_pdb_information->image_section_headers;
    streams[PDB_STREAM_section_header_dump].size = write_pdb_information->amount_of_image_sections * sizeof(*write_pdb_information->image_section_headers);
    
    // @note: The 0-th stream is added by the write_msf function implicitly.
    write_msf("a.pdb", streams + 1, amount_of_streams - 1);
}

