
// @cleanup: what are ST pdbs? Seems to have something to do with the strings in symbols?
// @cleanup: rename stream_table stream to stream table stream
// @cleanup: test that type indices only refer to prior members.

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#error This wont compile with a normal compiler! Read the warning Below this #error.
// 
// WARNING: This currently only compiles using an unreleased version of my 
//          own c-compiler. When I want to release this:
//          
//             1) All fancy 'pbc_print' calls need to be changed to normal printf.
//             2) All local functions need to be put into global scope and duplicate names changed.
//             3) Some global symbols will need to be reordered because c only compiles linearly.
// 

__declspec(printlike) int pbc_print(char *format, ...){
    va_list va;
    va_start(va, format);
    int ret = vprintf(format, va);
    va_end(va);
    
    fflush(0);
    return ret;
}

#define print pbc_print

void print_memory_range(u8 *memory, u64 size, u64 offset){
    
    for(u64 index = 0; index < size; index += 16){
        print("%p: ", (char *)(offset + index));
        
        for(u64 column_index = 0; column_index < 16; column_index++){
            if(index + column_index < size){
                print("%.2x ", (u32)memory[index + column_index]);
            }else{
                print("   ");
            }
            
            if(column_index == 7) print(" ");
        }
        
        print(" ");
        
        for(u64 column_index = 0; column_index < 16; column_index++){
            if(index + column_index < size){
                u8 c = memory[index + column_index];
                if(c < 32 || c >= 127) c = '.';
                
                print("%c", c);
            }else{
                print(" ");
            }
        }
        print("\n");
    }
}

typedef unsigned __int8  u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;

typedef __int8  s8;
typedef __int16 s16;
typedef __int32 s32;
typedef __int64 s64;

enum pdb_fixed_streams{
    PDB_STREAM_old_stream_table = 0,
    PDB_STREAM_pdb = 1,
    PDB_STREAM_tpi = 2,
    PDB_STREAM_dbi = 3,
    PDB_STREAM_ipi = 4,
    
    PDB_STREAM_first_non_fixed_stream,
};

struct pdb_stream{
    u32 stream_index;
    u32 page_array_offset_in_stream_table_stream;
    
    u64 stream_size;
    u64 base_offset;
    u64 current_offset;
};

struct pdb_context{
    
    char message_buffer[0x1000];
    
    u8 *pdb_base;
    
    u32 page_size;
    u32 amount_of_pages;
    u32 amount_of_streams;
    u32 pdb_age;
    
    u32 fastlink_pdb;
    u32 conflict_types;
    
    struct{
        u32 *data;
        u64 size;
    } stream_table_stream_page_array;
    
    //
    // fixed streams
    //
    struct pdb_stream pdb_stream;
    struct pdb_stream tpi_stream;
    struct pdb_stream dbi_stream;
    struct pdb_stream ipi_stream;
    
    //
    // hash streams, used to speed up searching the tpi/ipi stream
    //
    struct pdb_stream tpi_hash_stream;
    struct pdb_stream ipi_hash_stream;
    
    
    //
    // named streams
    //
    struct pdb_stream names_stream;
    struct pdb_stream LinkInfo_stream;
    struct pdb_stream TMCache_stream;
    struct pdb_stream src_headerblock_stream;
    struct pdb_stream UDTSRCLINEUNDONE_stream;
    
    //
    // the /names stream contains a string buffer,
    // which is indexed to save on string size.
    //
    struct pdb_stream names_string_buffer_substream;
    
    //
    // streams specified by the DBI stream
    //
    struct pdb_stream public_symbol_index_stream;
    struct pdb_stream global_symbol_index_stream;
    struct pdb_stream symbol_record_stream;
    
    //
    // DBI substreams
    //
    struct pdb_stream module_information_substream;
    struct pdb_stream section_contribution_substream;
    struct pdb_stream section_map_substream;              // @cleanup:
    struct pdb_stream source_info_substream;
    struct pdb_stream type_server_map_substream;       // Type servers are disabled in 'mspdbcore.dll'
    struct pdb_stream edit_and_continue_substream;     // same format as 'names_stream' contains object file names for each module, contains pdb name for each module, infomation comes from from S_ENVBLOCK or S_COMPILE2
    struct pdb_stream optional_debug_header_substream;
    
    //
    // The header dump stream contains the section table of the .exe
    //
    struct pdb_stream section_header_dump_stream;
    
    u32 amount_of_sections;
    u32 amount_of_modules;
    u32 amount_of_section_contributions;
    u64 total_amount_of_source_files;
};

// based on hashStringV1 in llvm, which is based on Hasher::lhashPbCb
u32 pdb_string_hash(char *string_data, u64 string_length){
    u32 ret = 0;
    
    u32 *string_as_u32 = (u32 *)string_data;
    u64 truncated_amount_of_u32 = (string_length / sizeof(u32));
    
    for(u32 i = 0; i < truncated_amount_of_u32; i++){
        ret ^= string_as_u32[i];
    }
    
    u32 remaining = string_length & 3;
    u64 at = truncated_amount_of_u32 * sizeof(u32);
    
    if(remaining >= 2){
        ret ^= *(u16 *)(string_data + at);
        remaining -= 2;
        at += 2;
    }
    
    if(remaining){
        ret ^= *(u8 *)(string_data + at);
    }
    
    u32 to_lower = 0x20202020;
    ret |= to_lower;
    ret ^= (ret >> 11);
    ret ^= (ret >> 16);
    
    return ret;
}

u32 pdb_read_u32_from_stream_table_stream(struct pdb_context *context, u64 offset){
    
    u64 page_number_index = offset / context->page_size;
    u64 offset_in_page    = offset % context->page_size;
    
    //
    // @note: the caller has to make sure the 'offset' behaves correctly
    //
    assert(page_number_index < context->stream_table_stream_page_array.size && (offset_in_page & 3) == 0);
    
    //
    // @note: we checked the page number to be valid in 'pdb_initialize_context'
    //
    u64 page_number = context->stream_table_stream_page_array.data[page_number_index];
    u8 *page = context->pdb_base + page_number * context->page_size;
    
    return *(u32 *)(page + offset_in_page);
}

// internal function used for fixed streams
int pdb_get_stream_from_index(struct pdb_context *context, u32 stream_index, struct pdb_stream *out_stream){
    
    if(stream_index < PDB_STREAM_first_non_fixed_stream || stream_index > context->amount_of_streams){
        return 1;
    }
    
    u64 stream_sizes_offset = 4;
    
    u32 stream_size = pdb_read_u32_from_stream_table_stream(context, stream_sizes_offset + stream_index * 4);
    u64 stream_pages_offset = stream_sizes_offset + (u64)context->amount_of_streams * 4;
    
    if(stream_size == 0xffffffff){
        return 1;
    }
    
    u64 offset = stream_pages_offset;
    for(u64 other_stream_index = 0; other_stream_index < stream_index; other_stream_index++){
        u32 other_stream_size = pdb_read_u32_from_stream_table_stream(context, stream_sizes_offset + other_stream_index * 4);
        
        // skip deleted streams
        if(other_stream_size == 0xffffffff) continue;
        
        u32 amount_of_pages_in_stream = ((u64)other_stream_size + context->page_size - 1) / context->page_size;
        offset += 4 * amount_of_pages_in_stream;
    }
    
    *out_stream = (struct pdb_stream){
        .page_array_offset_in_stream_table_stream = offset,
        .current_offset = 0,
        .stream_size    = stream_size,
        .stream_index   = stream_index,
    };
    return 0;
}

struct pdb_stream pdb_substream(struct pdb_stream *stream, u64 size){
    assert(stream->current_offset + size <= stream->stream_size);
    
    struct pdb_stream ret = {
        .page_array_offset_in_stream_table_stream = stream->page_array_offset_in_stream_table_stream,
        
        .stream_index   = stream->stream_index,
        .current_offset = 0,
        .base_offset    = stream->current_offset + stream->base_offset,
        .stream_size    = size,
    };
    
    stream->current_offset += size;
    return ret;
}

// returns -1 on failiure.
int pdb_numeric_leaf_size_or_error(u16 numeric_leaf){
    
    if(!(numeric_leaf & 0x8000)) return 0;
    
    //
    // @cleanup: implement this more correctly
    //
    
    switch(numeric_leaf){
        case 0x8000:{ // LF_CHAR
            return 1;
        }break;
        case 0x8001:  // LF_SHORT
        case 0x8002:{ // LF_USHORT
            return 2;
        }break;
        case 0x8005: // LF_REAL32
        case 0x8003: // LF_LONG
        case 0x8004:{ // LF_ULONG
            return 4;
        }break;
        
        case 0x8009: // LF_QUADWORD
        case 0x800a: // LF_UQUADWORD
        case 0x8006:{ // LF_REAL64
            return 8;
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
            return 16;
        }break;
        // case 0x8019: // LF_DECIMAL
        // case 0x801a: // LF_DATE
        // case 0x801b: // LF_UTF8STRING
        // case 0x801c: // LF_REAL16
        default:{
            return -1;
        }break;
    }
    
    return 0;
}

int pdb_skip_numeric_leaf(struct pdb_context *context, struct pdb_stream *stream){
    //
    // numeric leafs are at first a u16, but if this u16 has the top bit set
    // one is supposed to interpret, the numeric leaf based on the u16.
    //
    
    u16 numeric_leaf;
    if(pdb_read_from_stream(context, stream, &numeric_leaf, sizeof(numeric_leaf))){
        return 1;
    }
    
    int numeric_leaf_size = pdb_numeric_leaf_size_or_error(numeric_leaf);
    if(numeric_leaf_size == -1){
        // could not parse the numeric leaf
        return 1;
    }
    
    if(stream->current_offset + numeric_leaf_size > stream->stream_size){
        return 1;
    }
    stream->current_offset += numeric_leaf_size;
    
    return 0;
}

int pdb_align_stream(struct pdb_stream *stream, u64 alignment){
    u64 offset = (stream->current_offset + alignment - 1) & ~(alignment - 1);
    if(offset <= stream->stream_size){
        stream->current_offset = offset;
        return 0;
    }else{
        return 1;
    }
}

int pdb_read_from_stream(struct pdb_context *context, struct pdb_stream *stream, void *destination, u64 destination_size){
    u64 stream_end     = stream->base_offset + stream->stream_size;
    u64 current_offset = stream->base_offset + stream->current_offset;
    
    // @cleanup: maybe make sure this add does not overflow?
    if(current_offset + destination_size > (u64)stream_end){
        stream->current_offset = stream->stream_size;
        return 1;
    }
    
    stream->current_offset += destination_size;
    
    u32 page_size = context->page_size;
    
    u64 first_page = current_offset / page_size;
    u64 last_page  = (current_offset + destination_size + page_size - 1) / page_size;
    
    u8 *out = destination;
    u64 out_offset = 0;
    
    for(u64 page_number_index = first_page; page_number_index <= last_page; page_number_index++){
        //
        // @note: 'page_number_index' was checked above, the 'page_number' was checked in 'pdb_initialize_context'.
        //
        u32 page_number = pdb_read_u32_from_stream_table_stream(context, stream->page_array_offset_in_stream_table_stream + page_number_index * 4);
        u8 *page = context->pdb_base + page_size * page_number;
        
        u64 offset_in_page    = current_offset & (context->page_size - 1);
        u64 size_left_in_page = page_size - offset_in_page;
        u64 to_copy = destination_size > size_left_in_page ? size_left_in_page : destination_size;
        
        memcpy(out + out_offset, page + offset_in_page, to_copy);
        
        destination_size -= to_copy;
        current_offset   += to_copy;
        out_offset       += to_copy;
    }
    
    return 0;
}

#define pdb_read_type_from_stream(context, stream, type) *(type *)pdb_read_type_from_stream_(context, stream, &(type){}, sizeof(type))
void *pdb_read_type_from_stream_(struct pdb_context *context, struct pdb_stream *stream, void *destination, u64 destination_size){
    int error = pdb_read_from_stream(context, stream, destination, destination_size);
    assert(!error);
    return destination;
}



int pdb_skip_string(struct pdb_context *context, struct pdb_stream *stream){
    
    //
    // @cleanup: rename into 'pdb_stream_skip_string' and implement a faster version.
    //
    
    while(1){
        char character;
        if(pdb_read_from_stream(context, stream, &character, sizeof(character))) return 1;
        
        if(character == 0) break;
    }
    
    return 0;
}

u32 pdb_stream_string_hash_range(struct pdb_context *context, struct pdb_stream string_stream, u64 start_offset, u64 end_offset){
    
    u64 string_length = end_offset - start_offset;
    
    // @cleanup: faster version?
    
    //
    // Adjust the stream so we can only read what we are supposed to!
    //
    string_stream.base_offset   += start_offset;
    string_stream.current_offset = 0;
    string_stream.stream_size    = string_length;
    
    // print_stream_range(context, &string_stream, 0, string_length);
    
    u32 string_hash = 0;
    
    while(string_stream.current_offset + 4 <= string_stream.stream_size){
        u32 value = pdb_read_type_from_stream(context, &string_stream, u32);
        string_hash ^= value;
    }
    
    if(string_stream.current_offset + 2 <= string_stream.stream_size){
        string_hash ^= pdb_read_type_from_stream(context, &string_stream, u16);
    }
    
    if(string_stream.current_offset + 1 <= string_stream.stream_size){
        string_hash ^= pdb_read_type_from_stream(context, &string_stream, u8);
    }
    
    string_hash |= 0x20202020;
    string_hash ^= (string_hash >> 11);
    string_hash ^= (string_hash >> 16);
    
    return string_hash;
}

// @note: copy and paste from above
int print_stream_range(struct pdb_context *context, struct pdb_stream *stream, u64 start, u64 size){
    u32 page_size = context->page_size;
    
    assert(start + size <= stream->stream_size);
    
    u64 current_offset = start + stream->base_offset;
    
    u64 first_page = current_offset / page_size;
    u64 last_page  = (current_offset + size + page_size - 1) / page_size;
    
    u64 out_offset = 0;
    
    for(u64 page_number_index = first_page; page_number_index <= last_page; page_number_index++){
        u32 page_number = pdb_read_u32_from_stream_table_stream(context, stream->page_array_offset_in_stream_table_stream + page_number_index * 4);
        u8 *page = context->pdb_base + page_size * page_number;
        
        u64 offset_in_page    = current_offset & (context->page_size - 1);
        u64 size_left_in_page = page_size - offset_in_page;
        u64 to_copy = size > size_left_in_page ? size_left_in_page : size;
        
        print_memory_range(page + offset_in_page, to_copy, stream->base_offset + start + out_offset);
        
        size             -= to_copy;
        current_offset   += to_copy;
        out_offset       += to_copy;
    }
}

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
    struct pdb_section_contribution;
    u32 segment_id_in_object_file; // this is presumably here to support /DEBUG:FASTLINK
};

char *pdb_error(struct pdb_context *pdb_context, char *format, ...){
    va_list va;
    va_start(va, format);
    
    vsnprintf(pdb_context->message_buffer, sizeof(pdb_context->message_buffer), format, va);
    va_end(va);
    
    return pdb_context->message_buffer;
}

char *pdb_parse_and_validate_tpi_or_ipi_stream(struct pdb_context *context, struct pdb_stream index_stream, int is_ipi){
    
    char *tpi_or_ipi = is_ipi ? "IPI" : "TPI";
    
    struct index_stream_header{
        // We expect the version to be '20040203'.
        u32 version;
        
        // The size of this header
        u32 header_size;
        
        //
        // The range of type indices present in this stream
        //
        u32 minimal_type_index;
        u32 one_past_last_type_index;
        
        u32 byte_count_of_type_record_data_following_the_header;
        
        //
        // The stream index for the TPI/IPI hash stream.
        // The aux stream seems to be unused.
        //
        u16 hash_stream_index;
        u16 hash_aux_stream_index;
        
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
        u32 hash_key_buffer_offset;
        u32 hash_key_buffer_length;
        
        //
        // The 'index offset buffer' is an array of 'struct { u32 type_index; u32 offset_in_stream; }'.
        // The offset of each entry increases by about 8 kb each entry.
        // This buffer is intended for binary searching by type index, to get a rough (8kb accurate) offset
        // to the type, and from there one can search linearly to find the type record.
        //
        u32 index_offset_buffer_offset;
        u32 index_offset_buffer_length;
        
        // @cleanup: incorrect!
        // @cleanup: 
        //
        // The incremental linking hash table is a serialized hash table,
        // which takes the 'hash_key_buffer' keys and produces a type index.
        // This is supposetly useful in incremental linking scenarios.
        //
        u32 hash_adjust_table_offset;
        u32 hash_adjust_table_length;
    } index_stream_header;
    
    if(pdb_read_from_stream(context, &index_stream, &index_stream_header, sizeof(index_stream_header))){
        return pdb_error(context, "Error: The %s stream is too small to contain its header.", tpi_or_ipi);
    }
    
    if(index_stream_header.version != 20040203){
        return pdb_error(context, "Error: The %s stream has an unexpected version number. Expected 20040203.", tpi_or_ipi);
    }
    
    if(index_stream_header.header_size != sizeof(index_stream_header)){
        return pdb_error(context, "Error: The %s stream specifies an unexpected header size. Expected 0x38.", tpi_or_ipi);
    }
    
    if(index_stream.stream_size != (u64)index_stream_header.byte_count_of_type_record_data_following_the_header + (u64)index_stream_header.header_size){
        return pdb_error(context, "Error: The %s stream size does not match the one specified in its header.", tpi_or_ipi);
    }
    
    //
    // @note: for some reason the 'LF_UDT_MODE_SRC_LINE' is not aligned.
    //
    if(!is_ipi && (index_stream_header.byte_count_of_type_record_data_following_the_header & 3) != 0){
        return pdb_error(context, "Error: The %s stream size is incorrectly aligned. Expected 4 byte alignment.", tpi_or_ipi);
    }
    
    struct pdb_stream *hash_stream = is_ipi ? &context->ipi_hash_stream : &context->tpi_hash_stream;
    
    //
    // The hash stream is optional. @cleanup: but we should still check the records.
    //
    if(index_stream_header.hash_stream_index == (u16)-1) return 0;
    
    if(pdb_get_stream_from_index(context, index_stream_header.hash_stream_index, hash_stream)){
        return pdb_error(context, "Error: The %s stream header specifies an invalid %s hash stream.", tpi_or_ipi, tpi_or_ipi);
    }
    
    if((u64)index_stream_header.hash_key_buffer_offset + (u64)index_stream_header.hash_key_buffer_length > hash_stream->stream_size){
        return pdb_error(context, "Error: The hash key buffer does not fit inside the %s hash stream.", tpi_or_ipi);
    }
    
    if((u64)index_stream_header.index_offset_buffer_offset + (u64)index_stream_header.index_offset_buffer_length > hash_stream->stream_size){
        return pdb_error(context, "Error: The index offset buffer does not fit inside the %s hash stream.", tpi_or_ipi);
    }
    
    if((index_stream_header.index_offset_buffer_offset % 4) != 0){
        return pdb_error(context, "Error: The index offset buffer offset specified in the %s stream has invalid alignment. Expected 4 byte alignment.", tpi_or_ipi);
    }
    
    if((index_stream_header.index_offset_buffer_length % 8) != 0){
        return pdb_error(context, "Error: The index offset buffer size specified in the %s stream has invalid alignment. Expected 8 byte alignment.", tpi_or_ipi);
    }
    
    if((u64)index_stream_header.hash_adjust_table_offset + (u64)index_stream_header.hash_adjust_table_length > hash_stream->stream_size){
        return pdb_error(context, "Error: The incremental linking hash table does not fit inside the %s hash stream.", tpi_or_ipi);
    }
    
    //
    // iterate the 'index_offset_buffer' and the symbol records at the same time to validate
    // the 'index_offset_buffer' and the symbol records.
    //
    
    if(index_stream_header.index_offset_buffer_length){
        struct pdb_stream index_offset_buffer_stream = *hash_stream;
        index_offset_buffer_stream.current_offset = index_stream_header.index_offset_buffer_offset;
        index_offset_buffer_stream.stream_size    = index_stream_header.index_offset_buffer_offset + index_stream_header.index_offset_buffer_length;
        
        struct pdb_index_offset_buffer_entry{
            u32 type_index;
            u32 offset_in_stream;
        } current_entry = pdb_read_type_from_stream(context, &index_offset_buffer_stream, struct pdb_index_offset_buffer_entry);
        
        u32 type_index = index_stream_header.minimal_type_index;
        
        while(index_stream.current_offset < index_stream.stream_size){
            if(type_index == current_entry.type_index){
                
                if(index_stream.current_offset != current_entry.offset_in_stream + index_stream_header.header_size){
                    return pdb_error(context, "Error: The index offset buffer contained in the %s hash stream specifies an incorrect offset for a type index.", tpi_or_ipi);
                }
                
                if(index_offset_buffer_stream.current_offset < index_offset_buffer_stream.stream_size){
                    current_entry = pdb_read_type_from_stream(context, &index_offset_buffer_stream, struct pdb_index_offset_buffer_entry);
                }else{
                    // make it so the 'type_index' will not match anymore.
                    current_entry.type_index = 0;
                }
            }
            
            //
            // Because we checked 4 byte alignment above and we have  'index_stream.current_offset < index_stream.stream_size',
            // we know that the symbol record header fits in the stream.
            //
            
            u16 record_length = pdb_read_type_from_stream(context, &index_stream, u16);
            u16 kind          = pdb_read_type_from_stream(context, &index_stream, u16);
            
            // @note: for some reason 'LF_UDT_MOD_SRC_LINE' has non 4-byte aligned size.
            if(kind != 0x1607 && (record_length + 2) % 4 != 0){
                return pdb_error(context, "Error: A type record in the %s stream has incorrectly aligned record length.", tpi_or_ipi);
            }
            
            record_length -= 2;
            
            if(index_stream.current_offset + record_length > index_stream.stream_size){
                return pdb_error(context, "Error: A type record in the %s stream has incorrect length.", tpi_or_ipi);
            }
            
            print("type index 0x%x, kind 0x%x\n", type_index, kind);
            print_stream_range(context, &index_stream, index_stream.current_offset, record_length);
            
            type_index += 1;
            index_stream.current_offset += record_length;
        }
        
        if(type_index != index_stream_header.one_past_last_type_index){
            return pdb_error(context, "Error: The %s stream specifies a different number of type indices then present in the stream.", tpi_or_ipi);
        }
        
        if(current_entry.type_index || index_offset_buffer_stream.current_offset < index_offset_buffer_stream.stream_size){
            return pdb_error(context, "Error: The index offset buffer in the %s hash stream specifies type indices which are too large for the %s stream.", tpi_or_ipi, tpi_or_ipi);
        }
    }
    
    print("hash_adjust table\n");
    print_stream_range(context, hash_stream, index_stream_header.hash_adjust_table_offset, index_stream_header.hash_adjust_table_length);
    
    return 0;
}

char *pdb_parse_and_validate_public_or_global_symbol_index_stream(struct pdb_context *context, struct pdb_stream symbol_index_stream, int is_public_symbol_index_stream){
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
    //     u32 bucket_offset[amount_of_present_buckets];
    //
    // The serialized hash records have the follwing layout:
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
    
    char *public_or_global = is_public_symbol_index_stream ? "public" : "global";
    
    struct symbol_index_stream_header{
        u32 version_signature;
        u32 version;
        u32 hash_records_byte_size;
        u32 bucket_information_size;
    } symbol_index_stream_header;
    
    if(pdb_read_from_stream(context, &symbol_index_stream, &symbol_index_stream_header, sizeof(symbol_index_stream_header))){
        return pdb_error(context, "Error: The %s symbol index stream is to small to contain its header.", public_or_global);
    }
    
    if(symbol_index_stream_header.version_signature != (u32)-1){
        return pdb_error(context, "Error: The %s symbol index stream has wrong version sigature. Expected -1.", public_or_global);
    }
    
    if(symbol_index_stream_header.version != 0xeffe0000 + 19990810){
        return pdb_error(context, "Error: The %s symbol index stream has unexpected version. Expected 0xeffe0000 + 19990810.", public_or_global);
    }
    
    if((symbol_index_stream_header.hash_records_byte_size & 7) != 0){
        return pdb_error(context, "Error: The hash record buffer inside the %s symbol index stream is incorrectly aligned. Expected 8 byte alignment.", public_or_global);
    }
    
    if(symbol_index_stream.stream_size - symbol_index_stream.current_offset != (u64)symbol_index_stream_header.hash_records_byte_size + symbol_index_stream_header.bucket_information_size){
        if(is_public_symbol_index_stream){
            return pdb_error(context, "Error: Inside the public symbol index stream, the hash table information size differs from the expected size based on its header.");
        }else{
            return pdb_error(context, "Error: The global symbol index stream size differs from the expected size based on its header.");
        }
    }
    
    u32 IPHR_HASH = context->fastlink_pdb ? 0x3FFFF : 4096;
    static u32 hash_buckets[0x3FFFF + 1];
    memset(hash_buckets, 0xff, IPHR_HASH * sizeof(hash_buckets[0]));
    
    struct pdb_stream hash_record_stream = pdb_substream(&symbol_index_stream, symbol_index_stream_header.hash_records_byte_size);
    
    // print("hash records:\n");
    // print_stream_range(context, &hash_record_stream, 0, hash_record_stream.stream_size);
    // print("\n");
    
    if(symbol_index_stream_header.bucket_information_size){
        
        u32 bitmap_size = 4 * ((IPHR_HASH/32) + 1);
        if(symbol_index_stream_header.bucket_information_size < bitmap_size){
            return pdb_error(context, "Error: The %s symbol index stream is too small to contain its hash table bitmap.", public_or_global);
        }
        
        struct pdb_stream bitmap_stream               = pdb_substream(&symbol_index_stream, bitmap_size);
        struct pdb_stream bucket_record_offset_stream = pdb_substream(&symbol_index_stream, symbol_index_stream_header.bucket_information_size - bitmap_size);
        
        // print("bitmap:\n");
        // print_stream_range(context, &bitmap_stream, 0, bitmap_stream.stream_size);
        // print("\n");
        
        // print("bucket_record_offset\n");
        // print_stream_range(context, &bucket_record_offset_stream, 0, bucket_record_offset_stream.stream_size);
        // print("\n");
        
        s64 last_record_offset = -1;
        
        for(u32 bitmap_index = 0; bitmap_index < IPHR_HASH/32 + 1; bitmap_index++){
            u32 bitmap_entry = pdb_read_type_from_stream(context, &bitmap_stream, u32);
            
            for(u32 bit_index = 0; bit_index < 32; bit_index++){
                if(_bittest((long *)&bitmap_entry, bit_index)){
                    u32 record_offset;
                    if(pdb_read_from_stream(context, &bucket_record_offset_stream, &record_offset, sizeof(record_offset))){
                        return pdb_error(context, "Error: The %s symbol index stream does not contain enough hash records offsets.", public_or_global);
                    }
                    
                    //
                    // The offset is given in deserialized hash_records (containing an additional 32-bit pointer 'psym')
                    // So convert this offset to an offset in the table above.
                    //
                    
                    if((record_offset % 12) != 0){
                        return pdb_error(context, "Error: A record offset specified for a bucket in the %s hash stream is not a multiple of 12. These offsets are offset into the hash record buffer if the record buffer entries were deserialized (12 bytes large, by adding the next field).", public_or_global);
                    }
                    
                    // fix up the record offset and store them in the table.
                    record_offset = (record_offset / 12) * 8;
                    
                    if((s64)record_offset < last_record_offset){
                        return pdb_error(context, "Error: The record offsets in the %s index stream should be sorted.", public_or_global);
                    }
                    
                    last_record_offset = record_offset;
                    
                    hash_buckets[bitmap_index * 32 + bit_index] = record_offset;
                }
            }
        }
        
        if(bucket_record_offset_stream.current_offset < bucket_record_offset_stream.stream_size){
            return pdb_error(context, "Error: The %s symbol index stream contains too many hash records offsets.", public_or_global);
        }
    }
    
    u32 amount_of_hash_records = symbol_index_stream_header.hash_records_byte_size / 8;
    for(u32 hash_record_index = 0; hash_record_index < amount_of_hash_records; hash_record_index++){
        struct pdb_hash_record{
            u32 symbol_offset;
            u32 reference_count;
        } hash_record = pdb_read_type_from_stream(context, &hash_record_stream, struct pdb_hash_record);
        
        if(hash_record.reference_count == 0){
            return pdb_error(context, "Error: The %s symbol index stream contains a hash record with a zero reference count.", public_or_global);
        }
        
        u32 actual_symbol_offset = hash_record.symbol_offset - 1;
        if((actual_symbol_offset & 3) != 0){
            return pdb_error(context, "Error: The %s symbol index stream contains a hash record which specifies an offset with incorrect alignment. Expected 4 byte alignment.", public_or_global);
        }
        
        if(actual_symbol_offset >= context->symbol_record_stream.stream_size){
            return pdb_error(context, "Error: The %s symbol index stream contains a hash record which specifies an invalid offset. Expected 4 byte alignment.", public_or_global);
        }
        
        struct pdb_stream record_stream = context->symbol_record_stream;
        
        record_stream.current_offset = actual_symbol_offset;
        
        u16 record_length = pdb_read_type_from_stream(context, &record_stream, u16);
        u16 record_kind   = pdb_read_type_from_stream(context, &record_stream, u16);
        record_stream.stream_size = actual_symbol_offset + record_length + 2;
        
        if(is_public_symbol_index_stream){
            if(record_kind != /*S_PUB32*/0x110e){
                return pdb_error(context, "Error: The public symbol index stream contains a hash record which does not point to a S_PUB32.");
            }else{
                record_stream.current_offset += 10;
            }
        }else{
            switch(record_kind){
                case 0x1107:{ // S_CONSTANT
                    record_stream.current_offset += 4; // type_index
                    if(pdb_skip_numeric_leaf(context, &record_stream)){
                        return pdb_error(context, "Error: The %s symbol index stream contains a hash record which points to a constant which has an invalid value.", public_or_global);
                    }
                }break;
                case 0x1108:{ // S_UDT
                    record_stream.current_offset += 4;
                }break;
                
                case 0x1129:  // S_TOKENREF
                case 0x1128:  // S_ANNOTATIONREF
                case 0x1127:  // S_LPROCREF
                case 0x1126:  // S_DATAREF
                case 0x1125:  // S_PROCREF
                case 0x110d:  // S_GDATA32
                case 0x110c:{ // S_LDATA32
                    record_stream.current_offset += 10;
                }break;
                
                default:{
                    return pdb_error(context, "Internal Error: The %s symbol index stream contains a reference to a symbol (0x%x) we don't know. Sorry :(", public_or_global, record_kind);
                }break;
            }
        }
        
        u32 string_hash = 0;
        {
            //
            // manually compute the 'pdb_string_hash', as we dont get a string size
            // and we cannot read unbounded data without allocating.
            //
            
            struct pdb_stream string_stream = record_stream;
            if(pdb_skip_string(context, &string_stream)){
                return pdb_error(context, "Error: The %s symbol index stream contains a hash record which points to a symbol record with an invalid name.", public_or_global);
            }
            
            string_hash = pdb_stream_string_hash_range(context, string_stream, record_stream.current_offset, string_stream.current_offset - 1);
        }
        
        //
        // @note: there are three different pdb hashes used in the pdb.
        //        pdb_string_hash (LHashPbCb), the u16 truncated pd_string_hash (HashPbCb) used here
        //        and the 'LHashPbCbV2'. Which seem to be optionally usable but not enabled.
        // @note: the modulus operator happens before the truncation!
        //
        u32 index  = (u16)(string_hash % IPHR_HASH);
        u32 offset = hash_buckets[index];
        
        //
        // @cleanup: we are only varifying that we hit the 'any symbol' but not that we correct symbol.
        //           this is sort of difficult in the way we do it, because if there is a collision,
        //           they are _chained_ into the slot.
        //           We should figure out the slot lengths, so we know how many hash records to check here.
        //
        
        if(offset == 0xffffffff){
            return pdb_error(context, "Error: The %s symbol index stream contains a hash record, which does not hash to itself using the %s symbol hash stream hash table.", public_or_global, public_or_global);
        }
    }
    
    return 0;
}

char *pdb_validate_module_symbol_stream(struct pdb_context *context, struct pdb_stream module_symbol_stream, u32 module_index,
        u32 byte_size_of_symbol_information, u32 byte_size_of_c11_line_information, u32 byte_size_of_c13_line_information){
    
    u32 signature;
    if(pdb_read_from_stream(context, &module_symbol_stream, &signature, sizeof(signature))){
        return pdb_error(context, "Error: The size of the module symbol stream of module %d is to small to contain its signature.", module_index);
    }
    
    if(signature != /*CV_SIGNATURE_C13*/4){
        return pdb_error(context, "Error: The module symbol stream of module %d contains unexpected signature %d. Expected '4' (CV_SIGNATURE_C13 see cvinfo.h).", module_index, signature);
    }
    
    struct pdb_stream symbol_substream   = pdb_substream(&module_symbol_stream, byte_size_of_symbol_information - 4);
    struct pdb_stream c11_line_substream = pdb_substream(&module_symbol_stream, byte_size_of_c11_line_information);
    struct pdb_stream c13_line_substream = pdb_substream(&module_symbol_stream, byte_size_of_c13_line_information);
    
    //
    // validate alignment for all symbols in the symbol substream
    //
    u32 symbol_index = 0;
    while(symbol_substream.current_offset < symbol_substream.stream_size){
        u64 start_offset = symbol_substream.current_offset;
        
        // @note: we know that the offset is 4 byte aligned and the stream_size is 4 byte aligned
        //        thus we are in bounds.
        u16 length = pdb_read_type_from_stream(context, &symbol_substream, u16);
        u16 kind   = pdb_read_type_from_stream(context, &symbol_substream, u16);
        
        if((length % 4) != 2){
            return pdb_error(context, "Error: Symbol %d in the module symbol stream of module %d specifies incorrectly aligned length 0x%x.", symbol_index, module_index, length);
        }
        length -= 2;
        
        if(symbol_substream.current_offset + length > symbol_substream.stream_size){
            return pdb_error(context, "Error: Symbol %d in the module symbol stream of module %d specifies invalid length 0x%x.", symbol_index, module_index, length);
        }
        
        print("kind: %x\n", kind);
        print_stream_range(context, &symbol_substream, start_offset, length + 4);
        print("\n\n");
        
        //
        // Read the symbol into a 'symbol_buffer'. The length is always a bound to at most '0xffff',
        // because it is a u16.
        // @cleanup: figure out what to do abount longer symbols.
        //
        static u8 symbol_buffer[0x10000];
        {
            int error = pdb_read_from_stream(context, &symbol_substream, symbol_buffer, length);
            assert(!error);
            symbol_buffer[length] = 0;
        }
        
        switch(kind){
            
            char *codeview_symbol_check_name_field(struct pdb_context *context, u8 *name, u8 *symbol_end, u32 symbol_index, u32 module_index, u8 *symbol_buffer, u16 length, u16 kind){
                
                size_t name_length = strlen((char *)name) + 1;
                
                if(name + name_length > symbol_end){
                    return pdb_error(context, "Error: Symbol %d in the module symbol stream of module %d has a name which is not zero-terminated. (name starts %s)", symbol_index, module_index, name);
                }
                
                if(name + name_length + 3 < symbol_end){
                    if(strcmp((char *)name, "Microsoft (R) Macro Assembler") == 0){
                        // @sigh: apperantly this has too much padding... Microsoft please!
                    }else{
                        return pdb_error(context, "Error: Symbol %d in the module symbol stream of module %d has more padding then expected.", symbol_index, module_index);
                    }
                }
                
                for(u8 *it = name + name_length; it < symbol_end; it++){
                    if(*it != 0 && *it != 0xf0 + (symbol_end - it)){
                        print_memory_range(symbol_buffer, length, 0);
                        return pdb_error(context, "Error: Symbol %d (0x%x: %s) in the module symbol stream of module %d has unexpected padding. Expected zero or F3-F2-F1-padding.", symbol_index, kind, name, module_index);
                    }
                }
                
                return 0;
            }
            
            case /*S_LPROC32*/0x110f:
            case /*S_GPROC32*/0x1110:{
                struct codeview_gproc32{
                    u32 pointer_to_parent;
                    u32 pointer_to_end;
                    u32 pointer_to_next;
                    u32 procedure_length;
                    u32 debug_start_offset;
                    u32 debug_end_offset;
                    u32 type_index;
                    u32 offset_in_section;
                    u16 section_id;
                    u8 procedure_flags;
                    u8 procedure_name[];
                } *proc32 = (void *)symbol_buffer;
                
                char *lproc_gproc = (kind == 0x110f) ? "S_LPROC32" : "S_GPROC32";
                
                if(sizeof(*proc32) > length){
                    return pdb_error(context, "Error: %s (symbol_index %d) symbol in the module symbol stream of module %d is too small.", lproc_gproc, symbol_index, module_index);
                }
                
                // print("%#?\n", *proc32);
                // print("%s\n", proc32->procedure_name);
                
                char *error = codeview_symbol_check_name_field(context, proc32->procedure_name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_FRAMEPROC*/0x1012:{
                struct codeview_frameproc{
                    u32 stack_frame_size;
                    u32 stack_frame_padding_size;
                    u32 offset_of_padding;
                    u32 callee_saved_registers_size;
                    u32 offset_in_section_of_exception_handler;
                    u16 section_id_of_exception_handler;
                    u16 padding;
                    u32 flags;
                } *frameproc = (void *)symbol_buffer;
                
                if(sizeof(*frameproc) != length){
                    return pdb_error(context, "Error: S_FRAMEPROC (symbol_index %d) symbol in the module symbol stream of module %d has unexpected size.", symbol_index, module_index);
                }
            }break;
            
            case /*S_REGREL32*/0x1111:{
                struct codeview_regrel{
                    u32 offset_of_symbol;
                    u32 type_index;
                    u16 register_index;
                    u8 name[];
                } *regrel = (void *)symbol_buffer;
                
                if(sizeof(*regrel) > length){
                    return pdb_error(context, "Error: S_REGREL32 (symbol_index %d) symbol in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                char *error = codeview_symbol_check_name_field(context, regrel->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_LABEL32*/0x1105:{
                struct codeview_label{
                    u32 offset_in_section;
                    u16 section_id;
                    u8  procedure_flags;
                    u8 name[];
                } *label = (void *)symbol_buffer;
                
                if(sizeof(*label) > length){
                    return pdb_error(context, "Error: S_LABEL32 (symbol index %d) symbol in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                char *error = codeview_symbol_check_name_field(context, label->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_BLOCK32*/0x1103:{
                struct codeview_block{
                    u32 pointer_to_parent;
                    u32 pointer_to_end;
                    u32 length;
                    u32 offset_in_section;
                    u16 section_id;
                    u8  name[];
                } *block = (void *)symbol_buffer;
                
                if(sizeof(*block) > length){
                    return pdb_error(context, "Error: S_BLOCK32 (symbol index %d) symbol in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                char *error = codeview_symbol_check_name_field(context, block->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_CALLSITEINFO*/0x1139:{
                struct codeview_callsite_info{
                    u32 offset_in_section;
                    u16 section_index_of_call_site;
                    u16 reserved;
                    u32 type_index;
                } *callsite_info = (void *)symbol_buffer;
                
                if(sizeof(*callsite_info) != length){
                    return pdb_error(context, "Error: S_CALLSITEINFO (symbol index %d) sym in the module symbol stream of module %d has unexpected size.", symbol_index, module_index);
                }
            }break;
            
            case /*S_END*/0x0006:{
                if(length != 0){
                    return pdb_error(context, "Error: Expected no information after S_END for symbol index %d in the symbol module stream of module %d.");
                }
            }break;
            
            case /*S_OBJNAME*/0x1101:{
                struct codeview_object_name{
                    u32 signature;
                    u8 name[];
                } *object_name = (void *)symbol_buffer;
                
                // print("Signature 0x%x name %s\n", object_name->signature, object_name->name);
                
                if(sizeof(*object_name) > length){
                    return pdb_error(context, "Error: S_OBJNAME (symbol index %d) symbol in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                char *error = codeview_symbol_check_name_field(context, object_name->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_BUILDINFO*/0x114c:{
                u32 *build_info_symbol_id = (u32 *)symbol_buffer;
                
                if(sizeof(*build_info_symbol_id) != length){
                    return pdb_error(context, "Error: S_BUILDINFO (symbol index %d) sym in the module symbol stream of module %d has unexpected size.", symbol_index, module_index);
                }
                
            }break;
            
            case /*S_REF_MINIPDB2*/0x1167:{
                //
                // based on 'REFMINIPDB' (in cvinfo.h) and observation while dumping.
                //
                struct codeview_ref_minipdb2{
                    union{
                        u32 type_index; // for is udt.
                        u32 section_id_in_object_file;
                    };
                    union{
                        u16 flags;
                        struct{
                            u16 is_local : 1; // static
                            u16 is_data  : 1; // as opposed to code
                            u16 is_udt   : 1; // a udt (user defined type) is either a struct, union, enum, alias or something like this.
                            u16 is_label : 1; // lables are usually only present for assembly
                            u16 is_const : 1; // an enum member or maybe a const_expr (?)
                            u16 reserved : 11;
                        };
                    };
                    u8 name[];
                } *ref = (void *)symbol_buffer;
                
                if(sizeof(*ref) > length){
                    return pdb_error(context, "Error: S_REF_MINIPDB2 at symbol index %d in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                char *error = codeview_symbol_check_name_field(context, ref->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_COMPILE2*/0x1116:{
                struct codeview_compile2{
                    u32 flags;
                    u16 machine;
                    u16 front_end_major_version;
                    u16 front_end_minor_version;
                    u16 front_end_build_version;
                    u16 back_end_major_version;
                    u16 back_end_minor_version;
                    u16 back_end_build_version;
                    u8  compiler_version_strings[];
                } *compile2 = (void *)symbol_buffer;
                
                if(sizeof(*compile2) > length){
                    return pdb_error(context, "Error: S_COMPILE3 at symbol index %d in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                // "Length-prefixed compiler version string, followed
                //  by an optional block of zero terminated strings
                //  terminated with a double zero."
                
                for(u8 *it = compile2->compiler_version_strings; it < symbol_buffer + length;){
                    size_t string_length = strlen((char *)it);
                    
                    if(string_length == 0) break;
                    
                    if(it + string_length + 1 > symbol_buffer + length){
                        return pdb_error(context, "Error: Last string of S_COMPILE3 (symbol index %d) in symbol stream of module stream %d is not zero-terminated.", symbol_index, module_index);
                    }
                    
                    it += string_length + 1;
                }
                
                //
                // @cleanup: check padding
                //
                
            }break;
            case /*S_COMPILE3*/0x113c:{
                
                struct codeview_compile3{
                    u32 flags;
                    u16 machine;
                    u16 front_end_major_version;
                    u16 front_end_minor_version;
                    u16 front_end_build_version;
                    u16 front_end_QFE_version; // QuickFixEngineering (?)
                    u16 back_end_major_version;
                    u16 back_end_minor_version;
                    u16 back_end_build_version;
                    u16 back_end_QFE_version;
                    u8  compiler_version_string[];
                } *compile3 = (void *)symbol_buffer;
                
                if(sizeof(*compile3) > length){
                    return pdb_error(context, "Error: S_COMPILE3 at symbol index %d in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                // print("%#?\n", *compile3);
                // print("%s\n", compile3->compiler_version_string);
                
                char *error = codeview_symbol_check_name_field(context, compile3->compiler_version_string, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_ENVBLOCK*/0x113d:{
                struct codeview_envblock{
                    u8 flags;
                    u8 environment_strings[];
                } *envblock = (void *)symbol_buffer;
                
                if(sizeof(*envblock) > length){
                    return pdb_error(context, "Error: S_ENVBLOCK at symbol index %d in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                for(u8 *it = envblock->environment_strings; it < symbol_buffer + length;){
                    size_t string_length = strlen((char *)it);
                    
                    if(string_length == 0){
                        char *error = codeview_symbol_check_name_field(context, it, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                        if(error) return error;
                        break;
                    }
                    
                    if(it + string_length + 1 > symbol_buffer + length){
                        return pdb_error(context, "Error: Last string of S_ENVBLOCK (symbol index %d) in symbol stream of module stream %d is not zero-terminated.", symbol_index, module_index);
                    }
                    
                    it += string_length + 1;
                }
            }break;
            
            case /*S_ANNOTATION*/0x1019:
            case /*S_SEPCODE*/0x1132:{
                // @incomplete:
            }break;
            
            case /*S_SECTION*/0x1136:{
                struct codeview_section{
                    u16 section_id;
                    u8  section_alignment;
                    u8  reserved;
                    u32 relative_virtual_address;
                    u32 size;
                    u32 characteristics;
                    u8  name[];
                } *section = (void *)symbol_buffer;
                
                if(sizeof(*section) > length){
                    return pdb_error(context, "Error: S_SECTION at symbol index %d in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                //
                // @cleanup: compare this to the section_header_stream
                //
                
                // print("%#?\n", *section);
                // print("%s\n", section->name);
                
                char *error = codeview_symbol_check_name_field(context, section->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_COFFGROUP*/0x1137:{
                struct codeview_coffgroup{
                    u32 size;
                    u32 characteristics;
                    u32 offset_in_section;
                    u32 section_id;
                    u8 name[];
                } *coffgroup = (void *)symbol_buffer;
                
                if(sizeof(*coffgroup) > length){
                    return pdb_error(context, "Error: S_COFFGROUP at symbol index %d in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                //
                // @cleanup: compare this to the section_header_stream (?)
                //
                
                // print("%#?\n", *coffgroup);
                // print("%s\n", coffgroup->name);
                
                char *error = codeview_symbol_check_name_field(context, coffgroup->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            //
            // @note: the symbols S_GDATA32, S_LDATA32, S_CONSTANT and S_UDT 
            //        can appear in either the module symbol stream or the 
            //        symbol record stream.
            //
            case /*S_GDATA32*/0x110d:
            case /*S_LDATA32*/0x110c:{
                struct codeview_data32{
                    u32 type_index;
                    u32 offset_in_section;
                    u16 section_id;
                    u8 name[];
                } *data32 = (void *)symbol_buffer;
                
                // print("S_DATA:");
                // print_memory_range(symbol_buffer, length, 0);
                
                char *gdata32_ldata32 = (kind == 0x110c) ? "S_LDATA32" : "S_GDATA32";
                
                if(sizeof(*data32) > length){
                    return pdb_error(context, "Error: %s (symbol index %d) symbol in the module symbol stream of module %d is too small.", gdata32_ldata32, symbol_index, module_index);
                }
                
                char *error = codeview_symbol_check_name_field(context, data32->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_CONSTANT*/0x1107:{
                //
                // constants are sort of weird they contain a _numeric leaf_,
                // which is like a typed value.
                //
                
                struct codeview_constant{
                    u32 type_index;
                    u16 numeric_leaf;
                } *constant = (void *)symbol_buffer;
                
                int numeric_leaf_size = pdb_numeric_leaf_size_or_error(constant->numeric_leaf);
                if(numeric_leaf_size == -1){
                    return pdb_error(context, "Error: Could not parse numeric leaf for S_CONSTANT at symbol index %d in the module symbol stream of module %d.", symbol_index, module_index);
                }
                
                if(6 + numeric_leaf_size > length){
                    return pdb_error(context, "Error: Numeric leaf for S_CONSTANT at symbol index %d in module symbol stream of module %d speicifies a size which exceeds the symbol size.", symbol_index, module_index);
                }
                
                u8 *name = symbol_buffer + 6 + numeric_leaf_size;
                
                //
                // @cleanup: maybe try to search up this constant as a way to check the name.
                //
                
                char *error = codeview_symbol_check_name_field(context, name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_UDT*/0x1108:{
                struct codeview_udt{
                    u32 type_index;
                    u8 name[];
                } *udt = (void *)symbol_buffer;
                
                if(sizeof(*udt) > length){
                    return pdb_error(context, "Error: S_UDT (symbol index %d) symbol in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                char *error = codeview_symbol_check_name_field(context, udt->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            
            case /*S_UNAMESPACE*/0x1124:{
                char *error = codeview_symbol_check_name_field(context, symbol_buffer, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            case /*S_INLINEES*/0x1168:
            case /*S_CALLEES*/0x115a:{
                
                char *symbol_name = "S_CALLEES";
                if(kind == 0x1168) symbol_name = "S_INLINEES";
                
                if(length < 4) return pdb_error(context, "Error: %s (symbol index %d) symbol in the module symbol stream of module %d is too small.", symbol_name, symbol_index, module_index);
                
                u32 count = *(u32 *)symbol_buffer;
                
                u32 *function_type_indices = (void *)(symbol_buffer + 4);
                u32 *invocation_counts     = (void *)(function_type_indices + count);
                
                if((u8 *)(invocation_counts + count) < symbol_buffer + length){
                    return pdb_error(context, "Error: %s (symbol index %d) symbol in the module symbol stream of module %d has unexpected size based on the specified count of %u.", symbol_name, symbol_index, module_index, count);
                }
            }break;
            
            case /*S_LOCAL*/0x113e:{
                struct codeview_local{
                    u32 type_index;
                    u16 flags;
                    u8  name[];
                } *local = (void *)symbol_buffer;
                
                if(sizeof(*local) > length){
                    return pdb_error(context, "Error: S_LOCAL (symbol_index %d) symbol in the module symbol stream of module %d is too small.", symbol_index, module_index);
                }
                
                char *error = codeview_symbol_check_name_field(context, local->name, symbol_buffer + length, symbol_index, module_index, symbol_buffer, length, kind);
                if(error) return error;
            }break;
            
            struct codeview_lvalue_address_range{
                u32 offset_in_section;
                u16 section_id;
                u16 range_size_in_bytes;
            };
            
            struct code_view_lvalue_address_range_gap{
                u16 offset_in_range;
                u16 gap_size_in_bytes;
            };
            
            // S_LOCAL         =  0x113e,  // defines a local symbol in optimized code
            // S_DEFRANGE      =  0x113f,  // defines a single range of addresses in which symbol can be evaluated
            // S_DEFRANGE_SUBFIELD =  0x1140,           // ranges for a subfield
            // 
            // S_DEFRANGE_REGISTER =  0x1141,           // ranges for en-registered symbol
            // S_DEFRANGE_FRAMEPOINTER_REL =  0x1142,   // range for stack symbol.
            // S_DEFRANGE_SUBFIELD_REGISTER =  0x1143,  // ranges for en-registered field of symbol
            // S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE =  0x1144, // range for stack symbol span valid full scope of function body, gap might apply.
            // S_DEFRANGE_REGISTER_REL =  0x1145, // range for symbol address as register + offset.
            
#define temp_print(format, ...) (void)(__VA_ARGS__)
            
            case /*S_DEFRANGE*/0x113f:{
                struct codeview_defrange{
                    u32 dia_programm;   // wth?
                    struct codeview_lvalue_address_range valid_range;
                    struct code_view_lvalue_address_range_gap gaps[];
                } *defrange = (void *)symbol_buffer;
                temp_print("%#?\n", *defrange);
            }break;
            
            case /*S_DEFRANGE_SUBFIELD*/0x1140:{
                struct codeview_defrange_subfield{
                    u32 dia_programm;   // wth?
                    u32 offset_in_parent;
                    struct codeview_lvalue_address_range valid_range;
                    struct code_view_lvalue_address_range_gap gaps[];
                } *defrange_subfield = (void *)symbol_buffer;
                temp_print("%#?\n", *defrange_subfield);
            }break;
            
            
            case /*S_DEFRANGE_REGISTER*/0x1141:{
                struct codeview_defrange_register{
                    u16 reg;
                    u16 flags;
                    struct codeview_lvalue_address_range valid_range;
                    struct code_view_lvalue_address_range_gap gaps[];
                } *defrange_register = (void *)symbol_buffer;
                temp_print("%#?\n", *defrange_register);
            }break;
            
            case /*S_DEFRANGE_FRAMEPOINTER_REL*/0x1142:{
                struct codeview_framepointer_rel{
                    u32 offset_of_frame_pointer;
                    struct codeview_lvalue_address_range valid_range;
                    struct code_view_lvalue_address_range_gap gaps[];
                } *defrange_framepointer_rel = (void *)symbol_buffer;
                temp_print("%#?\n", *defrange_framepointer_rel);
            }break;
            
            case /*S_DEFRANGE_SUBFIELD_REGISTER*/0x1143:{
                struct codeview_defrange_subfield_register{
                    u16 reg;
                    u16 flags;
                    u32 offset_in_parent;
                    struct codeview_lvalue_address_range valid_range;
                    struct code_view_lvalue_address_range_gap gaps[];
                } *defrange_subfield_register = (void *)symbol_buffer;
                temp_print("%#?\n", *defrange_subfield_register);
            }break;
            
            case /*S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE*/0x1144:{
                struct codeview_framepointer_rel{
                    u32 offset_of_frame_pointer;
                } *defrange_framepointer_rel_full_scope = (void *)symbol_buffer;
                temp_print("%#?\n", *defrange_framepointer_rel_full_scope);
            }break;
            
            case /*S_DEFRANGE_REGISTER_REL*/0x1145:{
                struct codeview_defrange_register_rel{
                    u16 base_register;
                    u16 is_spilled_udt   : 1;
                    u16 padding          : 3;
                    u16 offset_in_parent : 12;
                    u32 offset_to_base_pointer; // wat?
                    
                    struct codeview_lvalue_address_range valid_range;
                    struct code_view_lvalue_address_range_gap gaps[];
                } *defrange_register_rel = (void *)symbol_buffer;
                temp_print("%#?\n", *defrange_register_rel);
            }break;
            
            case /*S_INLINESITE*/0x114d:{
                struct codeview_inlinesite{
                    u32 pointer_to_inliner; // @cleanup: 
                    u32 pointer_to_end;
                    u32 inlinee_id; // @cleanup: is this an 'id_index'?
                    u8  binary_annotations[];
                } *inline_site = (void *)symbol_buffer;
                
                temp_print("%#?\n", *inline_site);
            }break;
            
            case /*S_INLINESITE_END*/0x114e:{
                // @note: nothing in here!
            }break;
            
            case /*S_HEAPALLOCSITE*/0x115e:{
                struct codeview_heap_allocation_site{
                    u32 offset_in_section;
                    u16 section_id;
                    u16 call_instruction_length;
                    u32 call_function_type_index;
                } *heap_allocation_site = (void *)symbol_buffer;
                
                temp_print("%#?\n", *heap_allocation_site);
            }break;
            
            case /*S_FILESTATIC*/0x1153:{
                struct codeview_file_static{
                    u32 type_index;
                    u32 module_filename_string_index;
                    u16 flags;
                    u8  name[];
                } *file_static = (void *)symbol_buffer;
                temp_print("%#?\n", *file_static);
            }break;
            
            case /*S_FRAMECOOKIE*/0x113a:{
                struct codeview_framecookie{
                    u32 offset_in_stackframe;
                    u16 reg;
                    u8 cookietype; // @warning: this has the wrong definition in codeview.h
                    u8 flags;
                } *framecookie = (void *)symbol_buffer;
                
                if(sizeof(*framecookie) > length){
                    return pdb_error(context, "Framecookie?\n");
                }
                
                temp_print("%#?\n", *framecookie);
            }break;
            
            case /*S_THUNK32*/0x1102:{
                struct codeview_thunk{
                    u32 pointer_to_parent;
                    u32 pointer_to_end;
                    u32 pointer_to_next;
                    u32 offset_in_section;
                    u16 section_id;
                    u16 length;
                    u8  thunk_ordinal; // https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/thunk-ordinal?view=vs-2022
                    u8  name[];
                    // u8 variant[]; ?? 
                } *thunk = (void *)symbol_buffer;
                temp_print("%#?\n", *thunk);
            }break;
            
            case /*S_TRAMPOLINE*/0x112c:{
                struct codeview_trampoline{
                    u16 trampoline_type;
                    u16 trampoline_size;
                    u32 trampoline_offset_in_section;
                    u32 target_offset_in_section;
                    u16 trampoline_section_id;
                    u16 target_section_id;
                } *trampoline = (void *)symbol_buffer;
                temp_print("%#?\n", *trampoline);
            }break;
            
            default:{
                print_stream_range(context, &symbol_substream, start_offset, length + 4);
                
                return pdb_error(context, "Internal Error: Unknown symbol kind 0x%x, for Symbol %d in the module symbol stream of module %d.", kind, symbol_index, module_index);
            }break;
        }
        
        symbol_index += 1;
    }
    
    if(c11_line_substream.stream_size != 0){
        return pdb_error(context, "Error: Module %d: C11 line information currently not supported. All compilers seem to emit C13 line information.", module_index);
    }
    
    //
    // Search for the DEBUG_S_FILECHKSMS first, as apperantly there can be DEBUG_S_LINES before it.
    //
    struct pdb_stream checksum_stream = {0};
    int has_lines = 0;
    {
        struct pdb_stream file_checksum_stream = c13_line_substream;
        while(file_checksum_stream.current_offset < file_checksum_stream.stream_size){
            u64 start_offset = file_checksum_stream.current_offset + file_checksum_stream.base_offset;
            
            struct codeview_line_number_data_header{
                u32 type;
                u32 length;
            } header;
            
            if(pdb_read_from_stream(context, &file_checksum_stream, &header, sizeof(header))){
                return pdb_error(context, "Error: The C13 line information entry at offset 0x%llx inside the module symbol stream of module %d exceeds the size specified.", start_offset, module_index);
            }
            
            if((header.length & 3) != 0){
                return pdb_error(context, "Error: The C13 line information entry at offset 0x%llx inside the module symbol stream of module %d specifies unaligned length. Expected 4 byte alignment.", start_offset, module_index);
            }
            
            if(file_checksum_stream.current_offset + header.length > file_checksum_stream.stream_size){
                return pdb_error(context, "Error: The C13 line information inside the module symbol stream of module %d exceeds the size specified.", module_index);
            }
            
            struct pdb_stream entry_stream = pdb_substream(&file_checksum_stream, header.length);
            
            if(header.type == /*DEBUG_S_FILECHKSMS*/0xf4){
                if(checksum_stream.stream_index != (u64)0){
                    return pdb_error(context, "Error: More then one DEBUG_S_FILECHKSMS in the C13 line information for module stream %d.", module_index);
                }
                checksum_stream = entry_stream;
                
                while(entry_stream.current_offset < entry_stream.stream_size){
                    struct{
                        u32 offset_in_names;
                        u8  checksum_size;
                        u8  checksum_kind;
                        u8  checksum[];
                    } file_checksum_header;
                    
                    // @cleanup: there is struct alignment issues here!
                    
                    if(pdb_read_from_stream(context, &entry_stream, &file_checksum_header, sizeof(file_checksum_header) - /* remove padding */2)){
                        return pdb_error(context, "Error: The DEBUG_S_FILECHKSMS at offset 0x%llx inside the module symbol stream of module %d is not big enough to contain all of its entries.", start_offset, module_index);
                    }
                    
                    u32 offset_in_names = file_checksum_header.offset_in_names;
                    
                    if(offset_in_names == 0 || offset_in_names >= context->names_string_buffer_substream.stream_size){
                        return pdb_error(context, "Error: The DEBUG_S_FILECHKSMS at offset 0x%llx inside the the module symbol stream of module %d specifies an invalid file offset for the /names stream.", start_offset, module_index);
                    }
                    
                    context->names_string_buffer_substream.current_offset = offset_in_names - 1;
                    u8 byte = pdb_read_type_from_stream(context, &context->names_string_buffer_substream, u8);
                    if(byte != 0){
                        return pdb_error(context, "Error: The DEBUG_S_FILECHKSMS at offset 0x%llx inside the the module symbol stream of module %d specifies a file offset which does not point to the beginning of a file in the /names stream.", start_offset, module_index);
                    }
                    
                    u64 checksum_size = file_checksum_header.checksum_size;
                    if(file_checksum_header.checksum_kind > 3){
                        return pdb_error(context, "Error: The DEBUG_S_FILECHKSMS at offset 0x%llx inside the the module symbol stream of module %d specifies unknown hash type %d. (0 = none, 1 = MD5, 2 = SHA1, 3 = SHA256).", start_offset, module_index, file_checksum_header.checksum_kind);
                    }
                    
                    if(entry_stream.current_offset + checksum_size > entry_stream.stream_size){
                        return pdb_error(context, "Error: The last checksum of the DEBUG_S_FILECHKSMS at offset 0x%llx inside the the module symbol stream of module %d does not fit.", start_offset, module_index);
                    }
                    
                    entry_stream.current_offset += checksum_size;
                    
                    // align the stream to 4.
                    entry_stream.current_offset = (entry_stream.current_offset + 3) & ~3;
                }
            }
            
            if(header.type == /*DEBUG_S_LINES*/0xf2){
                has_lines = 1;
            }
        }
    }
    
    if(has_lines && checksum_stream.stream_index == 0 && byte_size_of_c13_line_information){
        return pdb_error(context, "Error: The C13 line information inside the module stream of module %d does not contain a DEBUG_S_FILECHKSMS, but contains a DEBUG_S_LINES.", module_index);
    }
    
    while(c13_line_substream.current_offset < c13_line_substream.stream_size){
        u64 start_offset = c13_line_substream.current_offset + c13_line_substream.base_offset;
        
        struct codeview_line_number_data_header{
            u32 type;
            u32 length;
        } line_number_data_header = pdb_read_type_from_stream(context, &c13_line_substream, struct codeview_line_number_data_header);
        
        u32 length = line_number_data_header.length;
        u32 type   = line_number_data_header.type;
        
        struct pdb_stream entry_stream = pdb_substream(&c13_line_substream, length);
        
        if(type & /*DEBUG_S_IGNORE*/0x80000000) continue;
        
        switch(type){
            case /*DEBUG_S_LINES*/0xf2:{
                
                struct codeview_line_header{
                    u32 contribution_offset;
                    u16 contribution_section_id;
                    u16 flags;
                    u32 contribution_size;
                } line_header;
                
                if(pdb_read_from_stream(context, &entry_stream, &line_header, sizeof(line_header))){
                    return pdb_error(context, "Error: The DEBUG_S_LINES at offset 0x%x in the module symbol stream of module %d which is not big enough to contain its header.", start_offset, module_index);
                }
                
                if(line_header.flags & ~1){
                    return pdb_error(context, "Error: The DEBUG_S_LINES at offset 0x%x in the module symbol stream of module %d has an unknown flag set (only know 1 = CV_LINES_HAVE_COLUMNS).", start_offset, module_index);
                }
                
                u16 section_index = line_header.contribution_section_id - 1;
                if(section_index >= context->amount_of_sections){
                    return pdb_error(context, "Error: The DEBUG_S_LINES at offset 0x%x in the module symbol stream of module %d specifies invalid section id %d. They are a one indexed index into the section table.", start_offset, module_index, line_header.contribution_section_id);
                }
                
                context->section_header_dump_stream.current_offset = sizeof(struct pdb_image_section_header) * section_index;
                struct pdb_image_section_header section_header = pdb_read_type_from_stream(context, &context->section_header_dump_stream, struct pdb_image_section_header);
                
                if((u64)section_header.virtual_size < (u64)line_header.contribution_offset + (u64)line_header.contribution_size){
                    return pdb_error(context, "Error: The DEBUG_S_LINES at offset 0x%x in the module symbol stream of module %d specifies a range which invalid for the section it specifies.", start_offset, module_index);
                }
                
                int have_columns = line_header.flags & /*CV_LINES_HAVE_COLUMNS*/1;
                
                //
                // After the line_header there come "blocks" (CV_DebugSLinesFileBlockHeader_t) of lines.
                // This construct seems to be fairly useless, there only ever seems to be one block.
                // In theory this would allow you to specify different files, which contribute to a
                // specific section of code.
                //
                // It seems to me one could just specify the whole section for the 'line_header'
                // and then put the line information in there for all the functions, but
                // that is not what they do. They have one 'line_header + block_header' per function.
                //
                
                struct pdb_stream block_stream = entry_stream;
                
                while(block_stream.current_offset < block_stream.stream_size){
                    u64 block_offset = block_stream.current_offset;
                    
                    struct codeview_line_block_header{
                        u32 offset_in_file_checksums;
                        u32 amount_of_lines;
                        u32 block_size;
                    } block_header;
                    
                    if(pdb_read_from_stream(context, &block_stream, &block_header, sizeof(block_header))){
                        return pdb_error(context, "Error: The block at offset 0x%llx inside the DEBUG_S_LINES at offset 0x%llx in the module symbol stream of module %d is not large enough to contain the block header.", block_offset, start_offset, module_index);
                    }
                    
                    u32 line_size   = block_header.amount_of_lines * 8;
                    u32 column_size = have_columns ? block_header.amount_of_lines * 4 : 0; // @note: not tested, there are never any columns present
                    
                    if((block_header.block_size & 3) != 0){
                        return pdb_error(context, "Error: The block at offset 0x%llx inside the DEBUG_S_LINES at offset 0x%llx in the module symbol stream of module %d has incorrectly aligned size.", block_offset, start_offset, module_index);
                    }
                    
                    if(block_header.block_size < line_size + column_size){
                        return pdb_error(context, "Error: The block at offset 0x%llx inside the DEBUG_S_LINES at offset 0x%llx in the module symbol stream of module %d specifies a block size which is too small to contain the line information.", block_offset, start_offset, module_index);
                    }
                    
                    {
                        //
                        // Search the DEBUG_S_FILECHKSMS entry to check that the 'offset_in_file_checksums' is correct
                        //
                        checksum_stream.current_offset = 0;
                        
                        int found = 0;
                        while(checksum_stream.current_offset < checksum_stream.stream_size){
                            if(block_header.offset_in_file_checksums == checksum_stream.current_offset){
                                found = 1;
                                break;
                            }
                            
                            struct{
                                u32 offset_in_names;
                                u8  checksum_size;
                                u8  checksum_kind;
                                u8  checksum[];
                            } file_checksum_header;
                            
                            if(pdb_read_from_stream(context, &checksum_stream, &file_checksum_header, sizeof(file_checksum_header) - 2)){
                                assert(0);
                            }
                            
                            checksum_stream.current_offset += file_checksum_header.checksum_size;
                            checksum_stream.current_offset = (checksum_stream.current_offset + 3) & ~3;
                        }
                        
                        if(!found){
                            return pdb_error(context, "Error: The block at offset 0x%llx inside the DEBUG_S_LINES at offset 0x%llx in the module symbol stream of module %d specifies a file offset which is not a valid offset into the DEBUG_S_FILECHKSMS.", block_offset, start_offset, module_index);
                        }
                    }
                    
                    struct pdb_stream lines_stream = pdb_substream(&block_stream, block_header.block_size - sizeof(block_header));
                    
                    for(u32 line_index = 0, last_offset = 0; line_index < block_header.amount_of_lines; line_index++){
                        struct codeview_line{
                            u32 offset;
                            u32 start_line_number     : 24;
                            u32 optional_delta_to_end :  7;
                            u32 is_a_statement        :  1;
                        } line_information = pdb_read_type_from_stream(context, &lines_stream, struct codeview_line);
                        
                        print("last_offset {} line_information.offset {}\n", last_offset, line_information.offset);
                        
                        if(last_offset > line_information.offset){
                            return pdb_error(context, "Error: The lines inside the DEBUG_S_LINE blocks have to be sorted by offset. This was not true for the block at offset 0x%llx of the DEBUG_S_LINES at offset 0x%llx in the module symbol stream of module %d.", block_offset, start_offset, module_index);
                        }
                        
                        if(line_information.start_line_number > 500000){
                            return pdb_error(context, "Error: A line > 500,000 was detected in the block at offset 0x%llx inside the DEBUG_S_LINES at offset 0x%x in the module symbol stream of module %d. This is considered invalid for the purposes of detecting bugs.", block_offset, start_offset, module_index);
                        }
                        
                        if(line_information.offset >= line_header.contribution_size){
                            return pdb_error(context, "Error: The block at offset 0x%llx inside DEBUG_S_LINES at offset 0x%x in the module symbol stream of module %d contains a line with an offset which execeeds the contribution range specified by the DEBUG_S_LINES header.", block_offset, start_offset, module_index);
                        }
                        
                        print(line_information);
                        
                        last_offset = line_information.offset;
                    }
                    
                    //
                    // @cleanup: if columns are present, maybe make sure they do not exceed 10k?
                    //
                }
            }break;
            case /*DEBUG_S_FILECHKSMS*/0xf4:{
                // we dealt with these above!
            }break;
            
            case /*DEBUG_S_INLINEELINES*/0xf6:{
                
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
                // print("[DEBUG_S_MERGED_ASSEMBLYINPUT]\n");
            }break;
            
            default:{
                return pdb_error(context, "Internal Error: The C13 line information inside of the module symbol stream of module %d uses unknown type 0x%x.", module_index, type);
            }break;
        }
    }
    
    u32 global_reference_byte_size = 0;
    if(pdb_read_from_stream(context, &module_symbol_stream, &global_reference_byte_size, sizeof(global_reference_byte_size))){
        return pdb_error(context, "Error: The module stream for module %d ends after the C13 line information, we expect global references to follow. (At least a u32-0 to indicate no global references are present).");
    }
    
    if(module_symbol_stream.current_offset + global_reference_byte_size > module_symbol_stream.stream_size){
        return pdb_error(context, "Error: The byte size for the global references of the module stream of module %d, exceeds the size left in the stream.");
    }
    
    if(global_reference_byte_size & 3){
        return pdb_error(context, "Error: The byte size for the global references of the module stream of module %d is unaligned, expected 4 byte alignment.");
    }
    
    struct pdb_stream global_ref_substream = pdb_substream(&module_symbol_stream, global_reference_byte_size);
    
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
    
    u32 global_reference_index = 0;
    while(global_ref_substream.current_offset < global_ref_substream.stream_size){
        u32 reference = pdb_read_type_from_stream(context, &global_ref_substream, u32);
        
        if((reference & 3) != 0){
            return pdb_error(context, "Error: Global reference %d in the module symbol stream of module %d is an unaligned offset into the symbol record stream. Expected 4 byte alignment.", global_reference_index, module_index);
        }
        
        struct pdb_stream symbol_stream = context->symbol_record_stream;
        symbol_stream.current_offset = reference;
        
        struct{
            u16 length;
            u16 type;
        } symbol_header;
        
        if(pdb_read_from_stream(context, &symbol_stream, &symbol_header, sizeof(symbol_header))){
            return pdb_error(context, "Error: Global reference %d in the module symbol stream of module %d is an invalid offset into the symbol record stream.", global_reference_index, module_index);
        }
        
        if(0x2000 < symbol_header.type || 0x1000 > symbol_header.type || (symbol_header.length - 2) + symbol_stream.current_offset > symbol_stream.stream_size){
            return pdb_error(context, "Error: Global reference %d in the module symbol stream of module %d points to an invalid symbol.", global_reference_index, module_index);
        }
        
        global_reference_index++;
    }
    
    if(module_symbol_stream.current_offset != module_symbol_stream.stream_size){
        return pdb_error(context, "Error: The module stream for module %d is bigger then expected.", module_index);
    }
    
    return 0;
}

// @note: used for both the '/names' stream and the 'edit_and_continue_substream'.
char *pdb_validate_string_table_stream(struct pdb_context *context, struct pdb_stream names_stream, char *name){
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
    // One important aspect here is that there is no enforced alignement on the 'string_buffer'.
    // In fact usually, the rest of the section after the string buffer is just unaligned.
    //
    
    // print_stream_range(context, &names_stream, 0, names_stream.stream_size);
    
    struct{
        u32 signature;
        u32 hash_version;
        u32 string_buffer_size;
    } names_stream_header;
    
    if(pdb_read_from_stream(context, &names_stream, &names_stream_header, sizeof(names_stream_header))){
        return pdb_error(context, "Error: %s stream is too small to contain its header.", name);
    }
    
    if(names_stream_header.signature != 0xEFFEEFFE){
        return pdb_error(context, "Error: %s stream has wrong signature 0x%x, expected 0xeffeeffe.", name, names_stream_header.signature);
    }
    
    if(names_stream_header.hash_version != 1){
        return pdb_error(context, "Error: %s stream has unknown hash version %d, expected 1.", name, names_stream_header.hash_version);
    }
    
    if(names_stream.current_offset + names_stream_header.string_buffer_size > names_stream.stream_size){
        return pdb_error(context, "Error: %s stream specifies invalid string buffer size.", name);
    }
    
    struct pdb_stream string_buffer_stream = pdb_substream(&names_stream, names_stream_header.string_buffer_size);
    context->names_string_buffer_substream = string_buffer_stream;
    
    //
    // @note: There is no alignment after the string buffer.
    //        The rest of the stream is just unaligned.
    //
    
    u32 bucket_count;
    if(pdb_read_from_stream(context, &names_stream, &bucket_count, sizeof(bucket_count))){
        return pdb_error(context, "Error: The %s stream ends after its string buffer. Expected a hash table to follow.", name);
    }
    
    struct pdb_stream bucket_stream = pdb_substream(&names_stream, bucket_count * 4);
    
    string_buffer_stream.current_offset = 0;
    
    u8 zero_byte;
    if(pdb_read_from_stream(context, &string_buffer_stream, &zero_byte, sizeof(zero_byte)) || zero_byte != 0){
        return pdb_error(context, "Error: The string buffer of the %s stream should contain the zero-sized string as the first element.", name);
    }
    
    u32 amount_of_strings = 0;
    while(string_buffer_stream.current_offset < string_buffer_stream.stream_size){
        amount_of_strings += 1;
        
        u64 string_start_offset = string_buffer_stream.current_offset;
        
        if(pdb_skip_string(context, &string_buffer_stream)){
            return pdb_error(context, "Error: The last string in the string buffer of the %s stream is not zero-terminated. Or the size specified does not match the bytes of strings present.", name);
        }
        
        u32 string_hash = pdb_stream_string_hash_range(context, string_buffer_stream, string_start_offset, string_buffer_stream.current_offset - 1);
        
        
        int found = 0;
        for(u32 table_index = 0; table_index < bucket_count; table_index++){
            u32 index = (table_index + string_hash) % bucket_count;
            
            bucket_stream.current_offset = index * 4;
            u32 offset = pdb_read_type_from_stream(context, &bucket_stream, u32);
            
            if(offset == 0){
                break;
            }else if(offset == string_start_offset){
                found = 1;
                break;
            }
        }
        
        if(!found){
            return pdb_error(context, "Error: The %s stream string buffer contains a string at offset 0x%llx which does not hash to it self using the hash buckets.", name, string_start_offset);
        }
    }
    
    u32 bucket_amount_of_strings = 0;
    bucket_stream.current_offset = 0;
    while(bucket_stream.current_offset < bucket_stream.stream_size){
        u32 bucket = pdb_read_type_from_stream(context, &bucket_stream, u32);
        
        if(bucket != 0){
            bucket_amount_of_strings += 1;
        }
    }
    
    u32 specified_amount_of_strings;
    if(pdb_read_from_stream(context, &names_stream, &specified_amount_of_strings, sizeof(specified_amount_of_strings))){
        return pdb_error(context, "Error: Expected the amount of strings to be at the very end of the %s stream (after the bucket array).", name);
    }
    
    if(specified_amount_of_strings != amount_of_strings){
        return pdb_error(context, "Error: The %s stream specifies the wrong number of strings. Expected %u, got %u.", name, amount_of_strings, specified_amount_of_strings);
    }
    
    if(bucket_amount_of_strings != amount_of_strings){
        return pdb_error(context, "Error: The %s stream specifies the wrong number of strings. Expected %u, got %u.", name, amount_of_strings, specified_amount_of_strings);
    }
    
    if(names_stream.current_offset != names_stream.stream_size){
        return pdb_error(context, "Error: The %s stream is bigger then expected.", name);
    }
    
    return 0;
}


char *pdb_initialize_context(struct pdb_context *context, u8 *pdb_base, size_t pdb_file_size){
    memset(context, 0, sizeof(*context));
    
    struct pdb_header{
        //
        // "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0\0"
        //
        u8 signature[32];
        
        //
        // The pdb format allocates data in "pages".
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
        u32 page_number_of_free_page_map;
        
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
        // version of the pdb format, but never used.
        //
        u32 reserved;
        
        // @cleanup: make sure everything about this is correct!
        // @cleanup: we are currently ignoring the fact that there can be more then one!
        //
        // The page number list of an array of page numbers.
        // Each page number in the array corresponds to a page in the stream_table stream.
        // The amount of entries is determined by 'stream_table_stream_size'.
        //
        u32 page_list_of_stream_table_stream_page_list[1];
    };
    
    if(pdb_file_size < sizeof(struct pdb_header)){
        return pdb_error(context, "Error: File to small to contain pdb header.");
    }
    
    struct pdb_header *pdb_header = (struct pdb_header *)pdb_base;
    
    static char pdb_signature[] = "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0\0";
    
    if(memcmp(pdb_header->signature, pdb_signature, 32) != 0){
        return pdb_error(context, "Error: Invalid pdb signature.");
    }
    
    u32 page_size = pdb_header->page_size;
    if(!page_size || (page_size & (page_size - 1))){
        return pdb_error(context, "Error: Page size specified in pdb header must be a power of two.");
    }
    
    if(pdb_header->page_number_of_free_page_map != 1 && pdb_header->page_number_of_free_page_map != 2){
        return pdb_error(context, "Error: The page number of the free page map specified by the pdb header must be '1' or '2'.");
    }
    
    if((u64)pdb_header->amount_of_pages * (u64)page_size != pdb_file_size){
        return pdb_error(context, "Error: The number of pages specified by the pdb header does not equal the amount of pages present.");
    }
    
    u32 amount_of_pages = pdb_header->amount_of_pages;
    
    if(pdb_header->reserved != 0){
        return pdb_error(context, "Error: Reserved field in the pdb header is non-zero.");
    }
    
    // @cleanup:
    if(pdb_header->page_list_of_stream_table_stream_page_list[0] < 3 || pdb_header->page_list_of_stream_table_stream_page_list[0] >= amount_of_pages){
        return pdb_error(context, "Error: The page number of the stream table stream specified in the pdb header is invalid.");
    }
    
    u32 stream_table_stream_size = pdb_header->stream_table_stream_size;
    
    u64 size_of_stream_table_stream_number_list = (((u64)stream_table_stream_size + page_size - 1) / page_size);
    u64 size_of_stream_table_stream_number_list_in_pages = (size_of_stream_table_stream_number_list * 4 + page_size - 1) / page_size;
    
    
    if((u64)pdb_header->page_list_of_stream_table_stream_page_list[0] + size_of_stream_table_stream_number_list_in_pages > amount_of_pages){
        return pdb_error(context, "Error: The size of the stream table stream specified in the pdb header is invalid.");
    }
    
    //
    // Validate the stream table stream pages, so we do not have to do it all over the place.
    //
    u32 *stream_table_stream_pages = (u32 *)(pdb_base + page_size * pdb_header->page_list_of_stream_table_stream_page_list[0]);
    for(u64 stream_table_stream_page_index = 0; stream_table_stream_page_index < size_of_stream_table_stream_number_list; stream_table_stream_page_index++){
        u32 page_number = stream_table_stream_pages[stream_table_stream_page_index];
        
        if(page_number < 3 || page_number >= amount_of_pages){
            return pdb_error(context, "Error: A stream table stream page is invalid.");
        }
    }
    
    print_memory_range(pdb_base, 0x1000, 0);
    
    context->pdb_base        = pdb_base;
    context->page_size       = page_size;
    context->amount_of_pages = amount_of_pages;
    context->stream_table_stream_page_array.size = size_of_stream_table_stream_number_list;
    context->stream_table_stream_page_array.data = stream_table_stream_pages;
    
    if(stream_table_stream_size < 4){
        return pdb_error(context, "Error: The stream table stream is too small to contain any information.");
    }
    
    //
    // The stream table stream tells us where all the other streams are located.
    // It has the following layout:
    //     u32 amount_of_streams;
    //     u32 stream_sizes[amount_of_streams];
    //     u32 stream_one_pages[];
    //     u32 stream_two_pages[];
    //     ...
    //
    
    u32 amount_of_streams = pdb_read_u32_from_stream_table_stream(context, /*offset=*/0);
    
    if(amount_of_streams < PDB_STREAM_first_non_fixed_stream){
        return pdb_error(context, "Error: The stream table stream specifies less streams then are necessary for a valid PDB.");
    }
    
    u64 stream_sizes_offset = 4;
    
    if(stream_sizes_offset + (u64)amount_of_streams * 4 > (u64)stream_table_stream_size){
        return pdb_error(context, "Error: The stream table stream is too small to contain size information for every stream.");
    }
    
    u64 stream_pages_offset = stream_sizes_offset + (u64)amount_of_streams * 4;
    
    for(u64 stream_index = 0; stream_index < amount_of_streams; stream_index++){
        u32 stream_size = pdb_read_u32_from_stream_table_stream(context, stream_sizes_offset + stream_index * 4);
        
        if(stream_index < PDB_STREAM_first_non_fixed_stream){
            
            struct pdb_stream *stream = (void *)0;
            
            switch(stream_index){
                case PDB_STREAM_old_stream_table:{
                    // ignored
                }break;
                case PDB_STREAM_pdb:{
                    stream = &context->pdb_stream;
                }break;
                case PDB_STREAM_tpi:{
                    stream = &context->tpi_stream;
                }break;
                case PDB_STREAM_dbi:{
                    stream = &context->dbi_stream;
                }break;
                case PDB_STREAM_ipi:{
                    stream = &context->ipi_stream;
                }break;
            }
            
            if(stream){
                if(stream_size == 0xffffffff){
                    // @cleanup: if ipi is not present, then maybe this is fine?
                    return pdb_error(context, "Error: A fixed stream was marked deleted.");
                }
                
                *stream = (struct pdb_stream){
                    .stream_index = stream_index,
                    .page_array_offset_in_stream_table_stream = stream_pages_offset,
                    .stream_size = stream_size,
                    .current_offset = 0,
                };
            }
        }
        
        u32 amount_of_pages_in_stream = ((u64)stream_size + page_size - 1) / page_size;
        
        // This can apparently happen in which case we will assume the
        // stream to have been deleted.
        if(stream_size == 0xffffffff) continue;
        
        if(stream_pages_offset + (u64)amount_of_pages_in_stream * 4 > (u64)stream_table_stream_size){
            return pdb_error(context, "Error: The stream table stream is too small to contain all stream page numbers.");
        }
        
        for(u32 stream_page_number_index = 0; stream_page_number_index < amount_of_pages_in_stream; stream_page_number_index++){
            u32 page_number = pdb_read_u32_from_stream_table_stream(context, stream_pages_offset + stream_page_number_index * 4);
            
            if(page_number < 3 || page_number >= amount_of_pages){
                return pdb_error(context, "Error: A page number specified in the stream table stream is invalid.");
            }
        }
        
        stream_pages_offset += (u64)amount_of_pages_in_stream * 4;
    }
    
    if(stream_table_stream_size != stream_pages_offset){
        return pdb_error(context, "Error: The stream table stream is bigger then expected.");
    }
    
    context->amount_of_streams = amount_of_streams;
    
    {
        //
        // The PDB Information Stream (stream index 1), contains the 'guid'
        // and age information to match the .exe to its .pdb.
        // It also contains information about _named streams_ in a serialized hash table.
        // We care about the '/names' stream.
        //
        struct pdb_stream pdb_stream = context->pdb_stream;
        
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
        
        if(pdb_read_from_stream(context, &pdb_stream, &pdb_info_stream_header, sizeof(pdb_info_stream_header))){
            return pdb_error(context, "Error: The PDB Information Stream (stream index 1), is not large enough to hold its header.\n");
        }
        
        if(pdb_info_stream_header.version != /*VC70*/20000404){
            return pdb_error(context, "Error: Unexpected PDB version specified in the PDB Information Stream header. We expected '20000404'.\n");
        }
        
        context->pdb_age = pdb_info_stream_header.age;
        
        //
        // The serialized hash table consists of two parts.
        // First a string buffer, preceeded by a u32 which determines the buffers size.
        //
        u32 string_buffer_size;
        if(pdb_read_from_stream(context, &pdb_stream, &string_buffer_size, sizeof(string_buffer_size)) || pdb_stream.current_offset + string_buffer_size > pdb_stream.stream_size){
            return pdb_error(context, "Error: The string table contained in the PDB Information Stream does not fit inside the stream.\n");
        }
        
        if(pdb_stream.current_offset + string_buffer_size > pdb_stream.stream_size){
            return pdb_error(context, "Error: The string table contained in the PDB Information Stream does not fit inside the stream.");
        }
        
        struct pdb_stream string_buffer_stream = pdb_substream(&pdb_stream, string_buffer_size);
        
        u32 src_headerblock_offset  = (u32)-1;
        u32 TMCache_offset          = (u32)-1;
        u32 LinkInfo_offset         = (u32)-1;
        u32 names_offset            = (u32)-1;
        u32 UDTSRCLINEUNDONE_offset = (u32)-1;
        
        u32 amount_of_strings = 0;
        while(string_buffer_stream.current_offset < string_buffer_stream.stream_size){
            
            u64 string_start_offset = string_buffer_stream.current_offset;
            
            if(pdb_skip_string(context, &string_buffer_stream)){
                return pdb_error(context, "Error: The last string of the string table contained in the PDB Information Stream is not zero-terminated.");
            }
             
            char string_buffer[0x100] = {0};
            
            // @note: include the null-terminator
            u64 string_length = string_buffer_stream.current_offset - string_start_offset;
            
            if(string_length < sizeof(string_buffer)){
                string_buffer_stream.current_offset = string_start_offset;
                int error = pdb_read_from_stream(context, &string_buffer_stream, string_buffer, string_length);
                assert(!error);
            }
            
            print("%llx: %.*s\n", string_start_offset, string_length, string_buffer);
            
            int handled = 0;
            
            if(string_length == sizeof("/names") && strncmp(string_buffer, "/names", string_length) == 0){
                names_offset = string_start_offset;
                handled = 1;
            }
            
            if(string_length == sizeof("/LinkInfo") && strncmp(string_buffer, "/LinkInfo", string_length) == 0){
                LinkInfo_offset = string_start_offset;
                handled = 1;
            }
            
            if(string_length == sizeof("/TMCache") && strncmp(string_buffer, "/TMCache", string_length) == 0){
                TMCache_offset = string_start_offset;
                handled = 1;
            }
            
            if(string_length == sizeof("/src/headerblock") && strncmp(string_buffer, "/src/headerblock", string_length) == 0){
                src_headerblock_offset = string_start_offset;
                handled = 1;
            }
            
            if(string_length == sizeof("/UDTSRCLINEUNDONE") && strncmp(string_buffer, "/UDTSRCLINEUNDONE", string_length) == 0){
                UDTSRCLINEUNDONE_offset = string_start_offset;
                handled = 1;
            }
            
            if(!handled){
                return pdb_error(context, "Internal Error: Unknown named stream '%s'.", string_buffer);
            }
            
            amount_of_strings += 1;
        }
        
        //
        // Parse out the serialized hash table, it has the following layout:
        //    u32 amount_of_entries;
        //    u32 capacity;
        //    struct {
        //        u32 word_count;
        //        u32 words[word_count];
        //    } present_bits;
        //    struct {
        //        u32 word_count;
        //        u32 words[word_count];
        //    } deleted_bits;
        //    struct {
        //        u32 key;
        //        u32 value;
        //    } entries[amount_of_entries];
        //    u32 unused;
        //
        // Here note that this is enough information to reconstruct the hash table,
        // but the hash table is not actually usable in its serialized form.
        // For this particular hash table, the 'key' is the offset of the string inside the
        // 'string_buffer' and the value is the stream index of the corresponding stream.
        //
        
        //
        // @cleanup: this hash table is not checked to work correctly...
        //
        
        char *hash_table_error = "Error: The serialized hash table inside of the PDB Information stream does not fit.";
        
        struct{
            u32 amount_of_entries;
            u32 capacity;
            u32 present_bits_word_count;
        } serialized_hash_table_header;
        
        if(pdb_read_from_stream(context, &pdb_stream, &serialized_hash_table_header, sizeof(serialized_hash_table_header))){
            return pdb_error(context, hash_table_error);
        }
        
        if(amount_of_strings != serialized_hash_table_header.amount_of_entries){
            return pdb_error(context, "Error: The serialized hash table inside the PDB Information stream speicifies a different amount of entries then there are strings.");
        }
        
        if(pdb_stream.current_offset + (u64)serialized_hash_table_header.present_bits_word_count * 4 > pdb_stream.stream_size){
            return pdb_error(context, hash_table_error);
        }
        
        pdb_stream.current_offset += serialized_hash_table_header.present_bits_word_count * 4;
        
        u32 deleted_bits_word_count;
        if(pdb_read_from_stream(context, &pdb_stream, &deleted_bits_word_count, sizeof(deleted_bits_word_count))){
            return pdb_error(context, hash_table_error);
        }
        
        if(pdb_stream.current_offset + (u64)deleted_bits_word_count * 4 > pdb_stream.stream_size){
            return pdb_error(context, hash_table_error);
        }
        
        pdb_stream.current_offset += deleted_bits_word_count * 4;
        
        if(pdb_stream.current_offset + serialized_hash_table_header.amount_of_entries * 8 > pdb_stream.stream_size){
            return pdb_error(context, hash_table_error);
        }
        
        for(u32 entry_index = 0; entry_index < serialized_hash_table_header.amount_of_entries; entry_index++){
            struct pdb_serialized_hash_table_entry{
                u32 key;
                u32 value;
            } entry = pdb_read_type_from_stream(context, &pdb_stream, struct pdb_serialized_hash_table_entry);
            
            print("entry {}\n", entry);
            
            if(entry.key >= string_buffer_size){
                return pdb_error(context, "Error: The serialized hash table inside of the PDB Information stream has an entry with a key which exceeds the string buffer size.");
            }
            
            if(entry.key == names_offset){
                if(pdb_get_stream_from_index(context, entry.value, &context->names_stream)){
                    return pdb_error(context, "Error: /names stream has invalid stream index.");
                }
                continue;
            }
            
            if(entry.key == TMCache_offset){
                if(pdb_get_stream_from_index(context, entry.value, &context->TMCache_stream)){
                    return pdb_error(context, "Error: /TMCache stream has invalid stream index.");
                }
                continue;
            }
            
            if(entry.key == LinkInfo_offset){
                if(pdb_get_stream_from_index(context, entry.value, &context->LinkInfo_stream)){
                    return pdb_error(context, "Error: /LinkInfo stream has invalid stream index.");
                }
                continue;
            }
            
            if(entry.key == src_headerblock_offset){
                if(pdb_get_stream_from_index(context, entry.value, &context->src_headerblock_stream)){
                    return pdb_error(context, "Error: /src/headerblock stream has invalid stream index.");
                }
                continue;
            }
            
            if(entry.key == UDTSRCLINEUNDONE_offset){
                if(pdb_get_stream_from_index(context, entry.value, &context->UDTSRCLINEUNDONE_stream)){
                    return pdb_error(context, "Error: /UDTSRCLINEUNDONE stream has invalid stream index.");
                }
                continue;
            }
            
            //
            // @cleanup: if /src/headerblock is present, other streams might be present
            //
            
            return pdb_error(context, "Error: The serialized hash table inside of the PDB Information stream has an entry with an offset that does not point to the beginning of a string.");
        }
        
        if(names_offset != (u32)-1 && context->names_stream.stream_index == 0){
            return pdb_error(context, "Error: The /names stream was contained in the string buffer inside the .pdb stream, but not in the hash table to define its stream index.");
        }
        
        if(TMCache_offset != (u32)-1 && context->TMCache_stream.stream_index == 0){
            return pdb_error(context, "Error: The /TMCache_offset stream was contained in the string buffer inside the .pdb stream, but not in the hash table to define its stream index.");
        }
        
        if(LinkInfo_offset != (u32)-1 && context->LinkInfo_stream.stream_index == 0){
            return pdb_error(context, "Error: The /LinkInfo stream was contained in the string buffer inside the .pdb stream, but not in the hash table to define its stream index.");
        }
        
        if(src_headerblock_offset != (u32)-1 && context->src_headerblock_stream.stream_index == 0){
            return pdb_error(context, "Error: The /src/headerblock stream was contained in the string buffer inside the .pdb stream, but not in the hash table to define its stream index.");
        }
        
        if(UDTSRCLINEUNDONE_offset != (u32)-1 && context->UDTSRCLINEUNDONE_stream.stream_index == 0){
            return pdb_error(context, "Error: The /UDTSRCLINEUNDONE stream was contained in the string buffer inside the .pdb stream, but not in the hash table to define its stream index.");
        }
        
        //
        // The stream is followed by a single u32 '0'.
        // This is because the hash table implementation used for the string indices is a template.
        // This template allows (optionally), to specify an integer allocation function (which in this
        // case allocates stream indices). Otherwise, the template allocates integers starting at
        // a base index. This base index is this 0.
        //
        pdb_read_from_stream(context, &pdb_stream, &(u32){0}, sizeof(u32));
        
        //
        // At the very end there is an array of _feature-flags_, which tells us if the pdb was
        // linked using /DEBUG:FASTLINK
        //
        while(pdb_stream.current_offset < pdb_stream.stream_size){
            u32 feature_code;
            if(pdb_read_from_stream(context, &pdb_stream, &feature_code, sizeof(feature_code))){
                return pdb_error(context, "Error: The PDB Information Stream size has invalid alignment.");
            }
            
            int should_break = 0;
            switch(feature_code){
                
                case /*VC110*/20091201:{
                    
                    // "No other signatre appened for vc110 PDB"
                    should_break = 1;
                }break;
                case /*VC140*/20140508:{
                    
                }break;
                case 'MTON':{ // NOTM
                    // record Conflict types (/DEBUG:CTYPES)
                    context->conflict_types = 1;
                }break;
                case 'INIM':{ // MINI
                    // Minimal Debug Info (/DEBUG:FASTLINK)
                    context->fastlink_pdb = 1;
                }break;
                
                default:{
                    return pdb_error(context, "Internal Error: Unknown pdb feature code 0x%x.", feature_code);
                }break;
            }
            if(should_break) break;
        }
        
        if(pdb_stream.current_offset != pdb_stream.stream_size){
            return pdb_error(context, "Error: The PDB Information Stream is bigger then expected.");
        }
    }
    
    if(context->names_stream.stream_index){
        char *error = pdb_validate_string_table_stream(context, context->names_stream, "/names");
        if(error) return error;
    }
    
    if(context->LinkInfo_stream.stream_size){
        // print("/LinkInfo (0x%x):\n", context->LinkInfo_stream.stream_size);
        // print_stream_range(context, &context->LinkInfo_stream, 0, context->LinkInfo_stream.stream_size);
        // print("\n\n");
    }
    
    if(context->UDTSRCLINEUNDONE_stream.stream_size){
        // Could not get a non-empty one...
        // print("/UDTSRCLINEUNDONE (0x%x):\n", context->UDTSRCLINEUNDONE_stream.stream_size);
        // print_stream_range(context, &context->UDTSRCLINEUNDONE_stream, 0, context->UDTSRCLINEUNDONE_stream.stream_size);
        // print("\n\n");
    }
    
    if(context->src_headerblock_stream.stream_size){
        // print("/src/headerblock:\n");
        // print_stream_range(context, &context->src_headerblock_stream, 0, context->src_headerblock_stream.stream_size);
    }
    
    {
        char *error = pdb_parse_and_validate_tpi_or_ipi_stream(context, context->tpi_stream, /*is_ipi*/0);
        if(error) return error;
    }
    
    if(context->dbi_stream.stream_size){
        //
        // The DeBug Information Stream (stream index 3) contains and links to
        // debug information for each linked obj file.
        // It is organized into one header followed by a couple of substreams.
        // Most importantly it contains the stream indices for the 'symbol stream'
        // as well as all the 'module symbols streams' for each obj.
        //
        
        struct pdb_stream dbi_stream = context->dbi_stream;
        
        struct dbi_stream_header{
            u32 version_signature;
            u32 version;
            u32 age;
            u16 stream_index_of_the_global_symbol_index_stream;
            struct{
                u16 major_version : 8;
                u16 minor_version : 7;
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
            
            u32 offset_of_the_MFC_type_server_in_the_type_server_map_substream;
            
            u32 byte_size_of_the_optional_debug_header_substream; // substream 6
            u32 byte_size_of_the_edit_and_continue_substream;     // substream 5
            
            struct{
                u16 was_linked_incrementally    : 1;
                u16 private_data_is_stripped    : 1;
                u16 the_pdb_uses_conflict_types : 1; // undocumented /DEBUG:CTYPES flag.
            }flags;
            
            u16 machine_type; // (0x8664)
            
            u32 reserved_padding;
        } dbi_stream_header;
        
        if(pdb_read_from_stream(context, &dbi_stream, &dbi_stream_header, sizeof(dbi_stream_header))){
            return pdb_error(context, "Error: The DBI stream (stream index 3) is too small for its header.");
        }
        
        if(dbi_stream_header.version_signature != (u32)-1){
            return pdb_error(context, "Error: DBI stream version signature is not -1.");
        }
        
        if(dbi_stream_header.version != 19990903){
            return pdb_error(context, "Error: DBI stream wrong version, expected '19990903'.");
        }
        
        // @note: this is not true, because it is only updated when the dbi is written.
        // if(dbi_stream_header.age != context->pdb_age){
        //     return pdb_error(context, "Error: DBI stream age does not match PDB age (this should be true from VC60 on).");
        // }
        
        if(!dbi_stream_header.toolchain_version.is_new_version_format){
            return pdb_error(context, "Internal Error: DBI stream toolchain version does not have the 'is_new_version_format' bit set, this is not supported.");
        }
        
        //
        // Validate the stream indices for the public symbol, global symbol and symbol record stream.
        //
        
        if(dbi_stream_header.stream_index_of_the_public_symbol_index_stream != (u16)-1){
            if(pdb_get_stream_from_index(context, dbi_stream_header.stream_index_of_the_public_symbol_index_stream, &context->public_symbol_index_stream)){
                return pdb_error(context, "Error: The DBI stream specifies an invalid stream index for the public symbol hash stream.");
            }
        }
        
        if(dbi_stream_header.stream_index_of_the_global_symbol_index_stream != (u16)-1){
            if(pdb_get_stream_from_index(context, dbi_stream_header.stream_index_of_the_global_symbol_index_stream, &context->global_symbol_index_stream)){
                return pdb_error(context, "Error: The DBI stream specifies an invalid stream index for the global symbol hash stream.");
            }
        }
        
        if(dbi_stream_header.stream_index_of_the_symbol_record_stream != (u16)-1){
            if(pdb_get_stream_from_index(context, dbi_stream_header.stream_index_of_the_symbol_record_stream, &context->symbol_record_stream)){
                return pdb_error(context, "Error: The DBI stream specifies an invalid stream index for the symbol record stream.");
            }
        }
        
        //
        // Check all the substreams contained in the dbi stream.
        //
        if(dbi_stream.current_offset + (u64)dbi_stream_header.byte_size_of_the_module_info_substream > dbi_stream.stream_size){
            return pdb_error(context, "Error: The module info substream does not fit inside the DBI stream.");
        }
        context->module_information_substream = pdb_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_module_info_substream);
        
        if(dbi_stream.current_offset + (u64)dbi_stream_header.byte_size_of_the_section_contribution_substream > dbi_stream.stream_size){
            return pdb_error(context, "Error: The section contribution substream does not fit inside the DBI stream.");
        }
        context->section_contribution_substream = pdb_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_section_contribution_substream);
        
        if(dbi_stream.current_offset + (u64)dbi_stream_header.byte_size_of_the_section_map_substream > dbi_stream.stream_size){
            return pdb_error(context, "Error: The section map substream does not fit inside the DBI stream.");
        }
        context->section_map_substream = pdb_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_section_map_substream);
        
        if(dbi_stream.current_offset + (u64)dbi_stream_header.byte_size_of_the_source_info_substream > dbi_stream.stream_size){
            return pdb_error(context, "Error: The source info substream does not fit inside the DBI stream.");
        }
        context->source_info_substream = pdb_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_source_info_substream);
        
        if(dbi_stream.current_offset + (u64)dbi_stream_header.byte_size_of_the_type_server_map_substream > dbi_stream.stream_size){
            return pdb_error(context, "Error: The type server map substream does not fit inside the DBI stream.");
        }
        context->type_server_map_substream = pdb_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_type_server_map_substream);
        
        if(dbi_stream.current_offset + (u64)dbi_stream_header.byte_size_of_the_edit_and_continue_substream > dbi_stream.stream_size){
            return pdb_error(context, "Error: The edit and continue substream does not fit inside the DBI stream.");
        }
        context->edit_and_continue_substream = pdb_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_edit_and_continue_substream);
        
        if(dbi_stream.current_offset + (u64)dbi_stream_header.byte_size_of_the_optional_debug_header_substream > dbi_stream.stream_size){
            return pdb_error(context, "Error: The optional debug header substream does not fit inside the DBI stream.");
        }
        context->optional_debug_header_substream = pdb_substream(&dbi_stream, dbi_stream_header.byte_size_of_the_optional_debug_header_substream);
        
        if(dbi_stream_header.offset_of_the_MFC_type_server_in_the_type_server_map_substream > dbi_stream_header.byte_size_of_the_type_server_map_substream){
            // @note: allow equality here, because both might be 0.
            return pdb_error(context, "Error: The offset of the MFC type server specified in the DBI stream is invalid.");
        }
        
        if(dbi_stream.current_offset != dbi_stream.stream_size){
            return pdb_error(context, "Error: The DBI stream is bigger then expected based on its header.");
        }
        
        //
        // Validate all the streams!
        // We do this in a different order then they are layed out on the disk.
        // We start with the 'optional_debug_header_substream' as it gives us
        // the section header dump stream, which in turn specified the amount sections
        // which are present in the .exe.
        // This mapping then defines the section_id used throughout the pdb.
        //
        
        {
            struct pdb_stream optional_debug_header_substream = context->optional_debug_header_substream;
            
            //
            // The 'optional_debug_header_substream' defines a bunch of stream indices
            // to a variety of information about the executable.
            // In practice most of the indices are '-1' and the only index which is present
            // is the 'section_header_dump_stream_index'.
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
            } debug_headers;
            
            if(dbi_stream_header.byte_size_of_the_optional_debug_header_substream < sizeof(debug_headers)){
                return pdb_error(context, "Error: The debug header substream of the DBI stream is the incorrect size.");
            }
            
            print("Optional Debug Header Substream:\n");
            print_stream_range(context, &optional_debug_header_substream, 0, optional_debug_header_substream.stream_size);
            
            pdb_read_from_stream(context, &optional_debug_header_substream, &debug_headers, sizeof(debug_headers));
            
            if(debug_headers.section_header_dump_stream_index == (u16)-1){
                return pdb_error(context, "Internal Error: The debug header substream of the DBI stream does not specify a Section Header Dump stream index. We need this stream to validate the section id's.");
            }
            
            if(pdb_get_stream_from_index(context, debug_headers.section_header_dump_stream_index, &context->section_header_dump_stream)){
                return pdb_error(context, "Error: The debug header substream of the DBI stream specifies an invalid Section Header Dump stream index.");
            }
            
            u64 section_header_size = context->section_header_dump_stream.stream_size;
            
            if(section_header_size % sizeof(struct pdb_image_section_header) != 0){
                return pdb_error(context, "Error: The size of the Section Header Stream is not a multiple of the size of a section header.");
            }
            
            context->amount_of_sections = section_header_size / sizeof(struct pdb_image_section_header);
        }
        
        {
            struct pdb_stream module_information_substream = context->module_information_substream;
            
            //
            // Parse the module information substream.
            //
            // It contains a 'pdb_module_information' structure for each module.
            // Most importantly, this specifies the 'module_symbol_stream_index' for
            // each module.
            // A module is just a compilation unit/an .obj.
            //
            
            u32 module_index = 0;
            u32 total_amount_of_source_files = 0;
            
            // print("\nModule Information Substream:\n");
            // print_stream_range(context, &module_information_substream, 0, module_information_substream.stream_size);
            
            while(module_information_substream.current_offset < module_information_substream.stream_size){
                struct pdb_module_information{
                    u32 pmod; // currently open mod ? I think this does not matter for us.
                    
                    // a module can have multiple section contributions so it is not clear why the first one is in here.
                    struct pdb_section_contribution first_section_contribution; // @cleanup: make sure this is either invalid, or the first contribution i guess
                    
                    struct{
                        u16 was_written_since_the_dbi_was_opened : 1;
                        u16 the_module_has_edit_and_continue_symbolic_information : 1;
                        u16 : 6;
                        u16 index_into_TSM_list_for_this_mods_server : 8;
                    } flags;
                    u16 module_symbol_stream_index;
                    
                    u32 byte_size_of_symbol_information;
                    u32 byte_size_of_c11_line_information;
                    u32 byte_size_of_c13_line_information;
                    u16 amount_of_source_files;
                    u16 padding;
                    u32 ignored;
                    u32 offset_in_module_name;
                    u32 offset_in_obj_file_name;
                    
                    // char module_name[];
                    // char object_file_name[];
                } module_information;
                
                if(pdb_read_from_stream(context, &module_information_substream, &module_information, sizeof(module_information))){
                    return pdb_error(context, "Error: The module info substream inside of the DBI stream is malformed.");
                }
                
                // skip the module name
                if(pdb_skip_string(context, &module_information_substream)){
                    return pdb_error(context, "Error: Module %d inside the module information substream has an invalid module name.", module_index);
                }
                
                // skip the object file name
                if(pdb_skip_string(context, &module_information_substream)){
                    return pdb_error(context, "Error: Module %d inside the module information substream has an invalid object file name.", module_index);
                }
                
                if(pdb_align_stream(&module_information_substream, 4)){
                    return pdb_error(context, "Error: The size of module %d inside the module information substream has invalid alignment, expected 4-byte alignment.", module_index);
                }
                
                if(module_information.module_symbol_stream_index != (u16)-1){
                    struct pdb_stream module_symbol_stream;
                    if(pdb_get_stream_from_index(context, module_information.module_symbol_stream_index, &module_symbol_stream)){
                        return pdb_error(context, "Error: The module symbol stream index for module %d specified by the module info substream inside the DBI stream is invalid.", module_index);
                    }
                    
                    //
                    // Validate the 'module symbol stream'
                    //
                    
                    // @note: cannot check '==' as there are global references at the end of the 'module_symbol_stream'
                    if(module_symbol_stream.stream_size < (u64)module_information.byte_size_of_symbol_information + (u64)module_information.byte_size_of_c11_line_information + (u64)module_information.byte_size_of_c13_line_information){
                        return pdb_error(context, "Error: The size of a module symbol stream of module %d is too small to the size specified for the symbol and line information.", module_index);
                    }
                    
                    if(module_information.byte_size_of_symbol_information & 3){
                        return pdb_error(context, "Error: The symbol information size for module %d is not 4 byte aligned.", module_index);
                    }
                    
                    if(module_information.byte_size_of_c11_line_information & 3){
                        return pdb_error(context, "Error: The c11 line information size for module %d is not 4 byte aligned.", module_index);
                    }
                    
                    if(module_information.byte_size_of_c13_line_information & 3){
                        return pdb_error(context, "Error: The c13 line informatio size for module %d is not 4 byte aligned.", module_index);
                    }
                    
                    char *error = pdb_validate_module_symbol_stream(context, module_symbol_stream, module_index,
                            module_information.byte_size_of_symbol_information, module_information.byte_size_of_c11_line_information, module_information.byte_size_of_c13_line_information);
                    
                    if(error) return error;
                }
                
                module_index += 1;
                total_amount_of_source_files += module_information.amount_of_source_files;
            }
            
            context->amount_of_modules = module_index;
            context->total_amount_of_source_files = total_amount_of_source_files;
        }
        
        {
            struct pdb_stream section_contribution_substream = context->section_contribution_substream;
            
            //
            // The section contribution substream contains a u32-version followed by
            // an array of either 'pdb_section_contribution' or 'pdb_section_contribution_v2'.
            // These section_contributions define a link between modules and sections.
            //
            
            // v1 = 0xeffe0000 + 19970605
            // v2 = 0xeffe0000 + 20140516
            if(dbi_stream_header.byte_size_of_the_section_contribution_substream < 4){
                return pdb_error(context, "Error: The section contribution substream inside the DBI stream is too small.");
            }
            
            u32 version;
            pdb_read_from_stream(context, &section_contribution_substream, &version, sizeof(version));
            
            u32 section_contribution_size = 0;
            if(version == /* V1 */0xeffe0000 + 19970605){
                section_contribution_size = sizeof(struct pdb_section_contribution);
            }else if(version == /* V2 */0xeffe0000 + 20140516){
                section_contribution_size = sizeof(struct pdb_section_contribution_v2);
            }else{
                return pdb_error(context, "Error: Unknown version of the section contribution substream of the DBI stream.");
            }
            
            u32 bytes_of_section_contributions = (dbi_stream_header.byte_size_of_the_section_contribution_substream - 4);
            if(bytes_of_section_contributions % section_contribution_size != 0){
                return pdb_error(context, "Error: The size of the section contribution substream inside of the DBI stream is not a multiple of the size of a section contribution structure.");
            }
            
            u32 amount_of_contributions = bytes_of_section_contributions / section_contribution_size;
            context->amount_of_section_contributions = amount_of_contributions;
            
            struct pdb_section_contribution_v2 last_section_contribution = {
                .section_id = -1,
                .size = -1,
                .module_index = -1,
            };
            
            struct pdb_image_section_header section_header;
            
            for(u32 section_contribution_index = 0; section_contribution_index < amount_of_contributions; section_contribution_index++){
                struct pdb_section_contribution_v2 contribution = {0};
                pdb_read_from_stream(context, &section_contribution_substream, &contribution, section_contribution_size);
                
                print("{:#}\n", contribution);
                
                // the id is one indexed
                u16 section_index = contribution.section_id - 1;
                if(section_index >= context->amount_of_sections){
                    return pdb_error(context, "Error: A section contribution has an invalid section id. They are one based index of the section table.");
                }
                
                // make sure the sections are in acending order in terms of section id
                if(last_section_contribution.section_id > contribution.section_id){
                    return pdb_error(context, "Error: The section contributions are not sorted in therms of section:offset.");
                }
                
                if(last_section_contribution.section_id == contribution.section_id){
                    if(last_section_contribution.offset > contribution.offset){
                        // if there was not a change in the section_id, make sure they are in acending order in terms of offset.
                        return pdb_error(context, "Error: The section contributions are not sorted in therms of section:offset.");
                    }
                    
                    if(last_section_contribution.offset + last_section_contribution.size > contribution.offset){
                        return pdb_error(context, "Error: The section contributions are overlapping.");
                    }
                }else{
                    //
                    // Read the section header from the section header dump stream.
                    //
                    context->section_header_dump_stream.current_offset = sizeof(struct pdb_image_section_header) * section_index;
                    pdb_read_from_stream(context, &context->section_header_dump_stream, &section_header, sizeof(section_header));
                }
                
                //
                // Ensure the contribution fits within the section
                //
                if(contribution.offset + contribution.size > section_header.virtual_size){
                    return pdb_error(context, "Error: A section contribution does not fit inside the containing section.");
                }
                
                if(contribution.module_index >= context->amount_of_modules){
                    return pdb_error(context, "Error: A section contribution has an invalid module index.");
                }
                
                last_section_contribution = contribution;
            }
        }
        
        {
            struct pdb_stream source_info_substream = context->source_info_substream;
            
            //
            // The source information substream contains the file names of the files
            // used by each module. It has the following layout:
            //     u16 amount_of_modules;
            //     u16 truncated_amount_of_source_files;
            //     u16 truncated_source_file_base_per_module[amount_of_modules];
            //     u16 amount_of_source_files_per_module[amount_of_modules];
            //     u32 source_file_name_offset_in_the_name_buffer[amount_of_source_files];
            //     char name_buffer[];
            //
            // The 'truncated_amount_of_source_files' is not used anymore as this would limit a
            // program to only use 65536 source files.
            // Similarly, the first array was supposed to speed up searching the
            // 'source_file_name_offset_in_the_name_buffer' array, allowing for 'base + file_name_index in module'
            // lookup, but if the file name count is bigger then '65536' this mapping does not work anymore.
            //
            // Currently, the 'amount_of_modules' field is still used but one could see instead
            // calculating it from the 'module information substream'.
            //
            
            u64 size_needed = 4;
            if(dbi_stream_header.byte_size_of_the_source_info_substream < size_needed){
                return pdb_error(context, "Error: The source info substream of the DBI stream is too small.");
            }
            
            if(dbi_stream_header.byte_size_of_the_source_info_substream & 3){
                return pdb_error(context, "Error: The size of the source info substream needs to be 4-byte aligned.");
            }
            
            u16 amount_of_modules = pdb_read_type_from_stream(context, &source_info_substream, u16);
            if(amount_of_modules != context->amount_of_modules){
                return pdb_error(context, "Error: The source info substream specifies a different amount of modules then the module information substream contains.");
            }
            
            u16 truncated_amount_of_source_files = pdb_read_type_from_stream(context, &source_info_substream, u16);
            if(truncated_amount_of_source_files != (u16)context->total_amount_of_source_files){
                return pdb_error(context, "Error: The source info substream should specify the truncated (u16) version of the amount of source files.");
            }
            
            size_needed += 2 * sizeof(u16) * (u64)amount_of_modules;
            
            if((u64)dbi_stream_header.byte_size_of_the_source_info_substream < size_needed){
                return pdb_error(context, "Error: The source info substream is too small to contain the arrays specifying the file counts for each module.");
            }
            
            u64 amount_of_source_files = 0;
            
            struct pdb_stream accumulated_stream       = pdb_substream(&source_info_substream, sizeof(u16) * amount_of_modules);
            struct pdb_stream source_file_count_stream = pdb_substream(&source_info_substream, sizeof(u16) * amount_of_modules);
            
            for(u32 module_index = 0; module_index < amount_of_modules; module_index++){
                u16 accumulated = pdb_read_type_from_stream(context, &accumulated_stream,       u16);
                u16 count       = pdb_read_type_from_stream(context, &source_file_count_stream, u16);
                
                if(accumulated != (u16)amount_of_source_files){
                    return pdb_error(context, "Error: The first array contained in the source info substream should contain a truncated accumulated amount of source files.");
                }
                
                // @note: because we don't want to walk the modules again, we cannot check that this value is accurate.
                //        We could Walk this first... Then we could check.
                amount_of_source_files += count;
            }
            
            if(amount_of_source_files != context->total_amount_of_source_files){
                return pdb_error(context, "Error: The source info substream disagrees with the module information substream on how many source files there are.");
            }
            
            size_needed += sizeof(u32) * amount_of_source_files;
            if((u64)dbi_stream_header.byte_size_of_the_source_info_substream < size_needed){
                return pdb_error(context, "Error: The source info substream is too small to contain the array specifying the file name offset for each file.");
            }
            
            struct pdb_stream source_file_stream = pdb_substream(&source_info_substream, sizeof(u32) * amount_of_source_files);
            
            u32 size_left = dbi_stream_header.byte_size_of_the_source_info_substream - size_needed;
            struct pdb_stream source_file_buffer_stream = pdb_substream(&source_info_substream, size_left);
            
            u64 size_of_names_buffer = dbi_stream_header.byte_size_of_the_source_info_substream - size_needed;
            
            for(u16 source_file_index = 0; source_file_index < amount_of_source_files; source_file_index++){
                u32 file_name_offset = pdb_read_type_from_stream(context, &source_file_stream, u32);
                
                if(file_name_offset >= size_of_names_buffer){
                    return pdb_error(context, "Error: An entry of the file offset array in the source info substream specifies an invalid offset into the names buffer.");
                }
                
                if(file_name_offset > 0){
                    //
                    // Check that the byte just before 'file_name_offset' was a zero byte.
                    // I.e the offset does actually point to the start of a string.
                    //
                    
                    source_file_buffer_stream.current_offset = file_name_offset - 1;
                    char byte = pdb_read_type_from_stream(context, &source_file_buffer_stream, char);
                    
                    if(byte != 0){
                        return pdb_error(context, "Error: An entry of the file offset array in the source info substream specifies an offset which does not appear to be the start of a string.");
                    }
                    
                    if(pdb_skip_string(context, &source_file_buffer_stream)){
                        return pdb_error(context, "Error: The last entry in the string buffer is not zero terminated.");
                    }
                    
#if 0
                    u64 offset = file_name_offset;
                    u64 size   = source_file_buffer_stream.current_offset - offset;
                    print_stream_range(context, &source_file_buffer_stream, offset, size);
#endif
                }
            }
        }
        
        {
            //
            // Edit and Continue Substream
            //
            // This stream is a version of the /names stream (string table stream) 
            // only containing the .pdb and .obj names for edit and continue .pdbs and .objs
            // @cleanup: figure out how EnC works...
            print("\nEdit and continue:\n");
            
            char *error = pdb_validate_string_table_stream(context, context->edit_and_continue_substream, "edit and continue");
            if(error) return error;
        }
        
        {
            //
            // Section Map Substream
            //
            
            struct pdb_stream section_map_stream = context->section_map_substream;
            
            struct pdb_section_map_stream_header{
                u16 number_of_section_descriptors;
                u16 number_of_logical_section_descriptors;
            } header;
            
            if(pdb_read_from_stream(context, &section_map_stream, &header, sizeof(header))){
                return pdb_error(context, "Error: Could not read the header of the Section Map Substream.");
            }
            
            if(header.number_of_section_descriptors != context->amount_of_sections + 1){
                return pdb_error(context, "Error: Section map substream has unexpected section description count.");
            }
            
            if(header.number_of_logical_section_descriptors != context->amount_of_sections + 1){
                return pdb_error(context, "Error: Section map substream has unexpected logical section description count.");
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
            } entry;
            
            u64 section_map_size = (context->amount_of_sections + 1) * sizeof(struct pdb_section_map_entry);
            
            if(section_map_stream.current_offset + section_map_size != section_map_stream.stream_size){
                return pdb_error(context, "Error: Section map substream has unexpected size.");
            }
            
            for(u32 index = 0; index < header.number_of_section_descriptors; index++){
                entry = pdb_read_type_from_stream(context, &section_map_stream, struct pdb_section_map_entry);
                
                if(index == header.number_of_section_descriptors - 1){
                    if(entry.section_size != (u32)-1){
                        return pdb_error(context, "Error: Expected the last section map entry to be the invalid section map entry (size = (u32)-1) but found size = 0xllx.", entry.section_size);
                    }
                    continue;
                }
                
                if(entry.frame != index + 1){
                    return pdb_error(context, "Error: Expected section map entry %d to have frame index %d, but has %d.", index + 1, index + 1, entry.frame);
                }
                
                struct pdb_image_section_header section_header;
                context->section_header_dump_stream.current_offset = sizeof(struct pdb_image_section_header) * index;
                pdb_read_from_stream(context, &context->section_header_dump_stream, &section_header, sizeof(section_header));
                
                if(entry.section_size != section_header.virtual_size){
                    return pdb_error(context, "Error: Section map entry %d has invalid section size. Got 0x%x but section is 0x%x.", index, entry.section_size, section_header.virtual_size); 
                }
                
            }
        }
    }
    
    if(context->ipi_stream.stream_index){
        char *error = pdb_parse_and_validate_tpi_or_ipi_stream(context, context->ipi_stream, /*is_ipi*/1);
        if(error) return error;
    }
    
    if(context->TMCache_stream.stream_index && context->TMCache_stream.stream_size){
        
        struct {
            u32 version;
            u32 header_size;
            u32 stream_indices_byte_size;
            u32 checksum_offset;
            u32 checksum_byte_size;
            
            // u16 module_indices[stream_indices_byte_size/2];
            // struct {u32 module; u32 not_sure; u8 checksum[8]; } checksums[checksums_byte_size/0x10];
            
        } type_map_cache_header;
        
        if(pdb_read_from_stream(context, &context->TMCache_stream, &type_map_cache_header, sizeof(type_map_cache_header))){
            return pdb_error(context, "Error: The /TMCache stream is not large enough for its header.");
        }
        
        if(type_map_cache_header.version != 0x20200229){
            return pdb_error(context, "Error: The /TMCache stream has unexpected version 0x%x (%d). Expected 0x20200229.", type_map_cache_header.version, type_map_cache_header.version);
        }
        
        if(type_map_cache_header.header_size != sizeof(type_map_cache_header)){
            return pdb_error(context, "Error: The /TMCache stream specifies unexpected header size 0x%x. Expected 0x%x.", type_map_cache_header.header_size, sizeof(type_map_cache_header));
        }
        
        if((type_map_cache_header.checksum_byte_size % 0x10) != 0){
            return pdb_error(context, "Error: The /TMCache stream specifies a checksum size which is not divisible by 0x10.");
        }
        
        if((type_map_cache_header.stream_indices_byte_size % 2) != 0){
            return pdb_error(context, "Error: The /TMCache stream specifies a stream index size which is not divisible by 2.");
        }
        
        u64 padding_size = (type_map_cache_header.stream_indices_byte_size % 4) ? 2 : 0;
        if(type_map_cache_header.checksum_offset != type_map_cache_header.header_size + type_map_cache_header.stream_indices_byte_size + padding_size){
            return pdb_error(context, "Error: The /TMCache stream specifies an unexpected 'checksum_offset'. Expected it to be the 4-byte aligned from the stream_indices.");
        }
        
        if(type_map_cache_header.checksum_offset + type_map_cache_header.checksum_byte_size != context->TMCache_stream.stream_size){
            return pdb_error(context, "Error: The /TMCache stream has an unexpected size based on his header.");
        }
        
        struct pdb_stream stream_indices = pdb_substream(&context->TMCache_stream, type_map_cache_header.stream_indices_byte_size);
        pdb_align_stream(&context->TMCache_stream, 4);
        
        struct pdb_stream checksums = pdb_substream(&context->TMCache_stream, type_map_cache_header.checksum_byte_size);
        
        while(checksums.current_offset < checksums.stream_size){
            struct pdb_tm_cache_mod_info{ // DBI1::TMCacheModInfo
                u32 module_index;
                u32 not_sure;
                u64 checksum;
            } cache_mod_info = pdb_read_type_from_stream(context, &checksums, struct pdb_tm_cache_mod_info);
            
            if(cache_mod_info.module_index * 2 >= stream_indices.stream_size){
                return pdb_error(context, "Error: The /TMCache specifies invalid module index %d. This should be an index into the stream index array.", cache_mod_info.module_index);
            }
            
            stream_indices.current_offset = cache_mod_info.module_index * 2;
            u16 stream_index = pdb_read_type_from_stream(context, &stream_indices, u16);
            
            struct pdb_stream cache_stream = {};
            if(pdb_get_stream_from_index(context, stream_index, &cache_stream)){
                return pdb_error(context, "Error: The /TMCache specifies invalid stream %d.", stream_index);
            }
            
            // print("%#?\n", cache_mod_info);
            // print_stream_range(context, &cache_stream, 0, cache_stream.stream_size);
            
            u32 version;
            if(pdb_read_from_stream(context, &cache_stream, &version, sizeof(version))){
                return pdb_error(context, "Error: /TMCache stream %d is to small for its header.", cache_mod_info.module_index);
            }
            
            if(version == 1){
                
                struct{
                    u32 amount_of_type_indices;
                    u32 amount_of_offsets;
                } cache_header;
                
                if(pdb_read_from_stream(context, &cache_stream, &cache_header, sizeof(cache_header))){
                    return pdb_error(context, "Error: /TMCache stream %d is to small for its header.", cache_mod_info.module_index);
                }
                
#if 0
                print("cache_header %#?\n", cache_header);
                
                struct pdb_stream type_index_stream  = pdb_substream(&cache_stream, 4 * cache_header.amount_of_type_indices);
                struct pdb_stream offset_stream      = pdb_substream(&cache_stream, 4 * cache_header.amount_of_offsets);
                
                print("\ntypes: 0x%x\n", cache_header.amount_of_type_indices);
                while(type_index_stream.current_offset < type_index_stream.stream_size){
                    u32 type_index = pdb_read_type_from_stream(context, &type_index_stream, u32);
                    print("    0x%x\n", type_index);
                }
                print("\n");
                print("offsets: 0x%x\n", cache_header.amount_of_offsets);
                while(offset_stream.current_offset < offset_stream.stream_size){
                    u32 offset = pdb_read_type_from_stream(context, &offset_stream, u32);
                    print("    0x%x\n", offset);
                }
                print("\n");
#endif
            }else{
                if(version != 2){
                    return pdb_error(context, "Internal Error: /TMCache stream %d has unsupported version %d.", cache_mod_info.module_index, version);
                }
                
                struct{
                    u16 PCH_TMCache_stream_index;
                    u16 padding;
                    u32 signature;
                    u32 minimal_type_index;
                    u32 amount_of_type_indices_following_the_header;
                } cache_header;
                
                if(pdb_read_from_stream(context, &cache_stream, &cache_header, sizeof(cache_header))){
                    return pdb_error(context, "Error: /TMCache stream %d is to small for its header.", cache_mod_info.module_index);
                }
                
                if(cache_header.PCH_TMCache_stream_index != (u16)-1){
                    return pdb_error(context, "Internal Error: /TMCache stream %d has PCH TMCache. Currently unsupported.", cache_mod_info.module_index);
                }
                
                u32 size_expected = 2 * cache_header.amount_of_type_indices_following_the_header * 4 + 4;
                if(cache_stream.current_offset + size_expected > cache_stream.stream_size){
                    return pdb_error(context, "Error: /TMCache stream %d has unexpected size based on its header.");
                }
#if 0
                struct pdb_stream type_index_stream  = pdb_substream(&cache_stream, 4 * cache_header.amount_of_type_indices_following_the_header);
                struct pdb_stream type_index_offsets = pdb_substream(&cache_stream, 4 * cache_header.amount_of_type_indices_following_the_header + 4);
                
                
                u32 offset = pdb_read_type_from_stream(context, &type_index_offsets, u32);
                
                u32 tpi_at = cache_header.minimal_type_index;
                u32 ipi_at = cache_header.minimal_type_index;
                
                
                for(u32 index = 0; index < cache_header.amount_of_type_indices_following_the_header; index++){
                    u32 type_index  = pdb_read_type_from_stream(context, &type_index_stream,  u32);
                    u32 next_offset = pdb_read_type_from_stream(context, &type_index_offsets, u32);
                    
                    if(type_index == 0){
                        
                    }else if(tpi_at <= type_index){
                        tpi_at = type_index + 1;
                    }else if(ipi_at <= type_index){
                        ipi_at = type_index + 1;
                    }else{
                        // return pdb_error(context, "wat.");
                    }
                    
                    print("type_index 0x%x, offset 0x%x, size 0x%x\n", type_index, offset, next_offset - offset);
                    offset = next_offset;
                }
                
                while(cache_stream.current_offset < cache_stream.stream_size){
                    u32 function_id = pdb_read_type_from_stream(context, &cache_stream, u32);
                    u32 type_index  = pdb_read_type_from_stream(context, &cache_stream, u32);
                    
                    print("0x%x-> 0x%x\n", function_id, type_index);
                }
#endif
            }
            
            // 02 00 00 00
            // ff ff -> PCH TM Cache stream index (?)
            // 00 00
            // 00 00 00 00 Signature
            // 00 10 00 00
            // 0c 00 00 00
            //                                     (0x00)
            // 00 10 00 00 (LF_ARGLIST)     (0x0c) (0x0c)
            // 01 10 00 00 (LF_PROCEDURE)   (0x10) (0x1c)
            //
            // 00 10 00 00 (LF_FUNC_ID)     (0x14) (0x30)
            // 01 10 00 00 (LF_STRING_ID)   (0x18) (0x48)
            // 02 10 00 00 (LF_STRING_ID)   (0x78) (0xc0)
            // 03 10 00 00 (LF_STRING_ID)   (0x10) (0xd0)
            // 04 10 00 00 (LF_STRING_ID)   (0x24) (0xf4)
            // 05 10 00 00 (LF_STRING_ID)   (0xfc) (0x1f0)
            // 06 10 00 00 (LF_STRING_ID)   (0xf0) (0x2e0)
            // 07 10 00 00 (LF_SUBSTR_LIST) (0x10) (0x2f0)
            // 08 10 00 00 (LF_STRING_ID)   (0x48) (0x338)
            // 09 10 00 00 (LF_BUILDINFO)   (0x1c) (0x354)
            //
            // 00 00 00 00
            // 0c 00 00 00
            // 1c 00 00 00
            // 30 00 00 00
            // 48 00 00 00
            // c0 00 00 00
            // d0 00 00 00
            // f4 00 00 00
            // f0 01 00 00
            // e0 02 00 00
            // f0 02 00 00
            // 38 03 00 00
            // 54 03 00 00
            //
            // 02 10 00 00 -> 01 10 00 00
        }
        
    }
    
    if(context->symbol_record_stream.stream_index){
        //
        // Symbol record stream
        //
        
        struct pdb_stream symbol_record_stream = context->symbol_record_stream;
        
        if((symbol_record_stream.stream_size % 4) != 0){
            return pdb_error(context, "Error: The symbol record stream has invalidly aligned size. Must be 4-byte aligned.");
        }
        
        u32 symbol_index = 0;
        while(symbol_record_stream.current_offset < symbol_record_stream.stream_size){
            u64 start_offset = symbol_record_stream.current_offset;
            
            //
            // @note: the header always fits because of 4-byte alignment.
            //
            struct codeview_symbol_header{
                u16 record_length;
                u16 record_kind;
            } symbol = pdb_read_type_from_stream(context, &symbol_record_stream, struct codeview_symbol_header);
            
            if((symbol.record_length % 4) != 2){
                return pdb_error(context, "Error: Symbol %d (offset 0x%x) in the symbol record stream specifies invalid length. Entry must be 4-byte aligned.", symbol_index, start_offset);
            }
            
            if((symbol_record_stream.current_offset - 2) + symbol.record_length > symbol_record_stream.stream_size){
                return pdb_error(context, "Error: Symbol %d (offset 0x%x) in the symbol record stream specifies a length (0x%x) which is too large to fit in the stream.", symbol_index, start_offset, symbol.record_length);
            }
            
            //
            // Read the symbol into a 'symbol_buffer'. The length is always a bound to at most '0xffff',
            // because it is a u16.
            // @cleanup: figure out what to do about longer symbols.
            //
            u32 length = symbol.record_length - 2;
            u32 kind   = symbol.record_kind;
            
            static u8 symbol_buffer[0x10000];
            {
                int error = pdb_read_from_stream(context, &symbol_record_stream, symbol_buffer, length);
                assert(!error);
                
                //
                // make sure we are save to 'strlen()'
                //
                symbol_buffer[length] = 0;
            }
            
            switch(kind){
                
                char *codeview_symbol_check_name_field(struct pdb_context *context, u8 *name, u8 *symbol_end, u32 symbol_index, u8 *symbol_buffer, u16 length, u16 kind){
                    
                    size_t name_length = strlen((char *)name) + 1;
                    
                    if(name + name_length > symbol_end){
                        return pdb_error(context, "Error: Symbol %d in the symbol record stream has a name which is not zero-terminated. (name starts %s)", symbol_index, name);
                    }
                    
                    if(name + name_length + 3 < symbol_end){
                        return pdb_error(context, "Error: Symbol %d in the symbol record stream has more padding then expected.", symbol_index);
                    }
                    
                    if(kind != /*S_PUB32*/0x110e){ // Apperanlty this happens for Kernelbase.pdb ?
                        for(u8 *it = name + name_length; it < symbol_end; it++){
                            if(*it != 0 && *it != 0xf0 + (symbol_end - it)){
                                print_memory_range(symbol_buffer, length, 0);
                                return pdb_error(context, "Error: Symbol %d (0x%x: %s) in the symbol record stream has unexpected padding. Expected zero or F3-F2-F1-padding.", symbol_index, kind, name);
                            }
                        }
                    }
                    return 0;
                }
                
                case /*S_PUB32*/0x110e:{
                    struct codeview_public_symbol_body{
                        u32 flags;
                        u32 offset;
                        u16 section_id;
                        u8 name[];
                    } *public_symbol = (void *)symbol_buffer;
                    
                    if(sizeof(*public_symbol) > length){
                        return pdb_error(context, "Error: S_PUB32 (symbol index %d) symbol in the symbol record stream is too small.", symbol_index);
                    }
                    
                    char *error = codeview_symbol_check_name_field(context, public_symbol->name, symbol_buffer + length, symbol_index, symbol_buffer, length, kind);
                    if(error) return error;
                    
                    u32 section_index = public_symbol->section_id - 1;
                    if(section_index == context->amount_of_sections){
                        // @cleanup: this can apperently happen...
                        //           symbols here are:
                        //               __guard_longjmp_table
                        //               __enclave_config
                        //               __guard_flags
                        //               __guard_longjmp_count
                        //               __guard_iat_table
                        //               __guard_fids_count
                        //               __guard_fids_table
                        //               __guard_iat_count
                        
                        break;
                    }
                    
                    if(section_index >= context->amount_of_sections){
                        return pdb_error(context, "Error: The S_PUB32 at offset 0x%x (symbol %d) in the symbol record stream specifies invalid section_id %d. (symbol name %s)", start_offset, symbol_index, public_symbol->section_id, public_symbol->name);
                    }
                    
                    struct pdb_image_section_header section_header = {0};
                    context->section_header_dump_stream.current_offset = sizeof(struct pdb_image_section_header) * section_index;
                    pdb_read_from_stream(context, &context->section_header_dump_stream, &section_header, sizeof(section_header));
                    
                    if(public_symbol->offset > section_header.virtual_size){
                        return pdb_error(context, "Error: The S_PUB32 at offset 0x%x (symbol %d) in the symbol record stream specifies an invalid offset (0x%x) for its section (%d). (symbol name %s)", start_offset, symbol_index, public_symbol->offset, public_symbol->section_id, public_symbol->name);
                    }
                    
                }break;
                
                case /*S_ANNOTATIONREF*/0x1128:
                case /*S_LPROCREF*/0x1127:
                case /*S_DATAREF*/0x1126:
                case /*S_PROCREF*/0x1125:{
                    assert(kind != 0x1126);
                    
                    struct codeview_symbol_reference{
                        u32 SUC_of_the_name; // (?)
                        u32 symbol_offset_in_module_symbol_record_stream;
                        u16 module_index;
                        u8  name[]; // they say "hidden name made a first class member" which is maybe supposed to tell me something?
                    } *symbol_reference = (void *)symbol_buffer;
                    
                    char *symbol_string = "S_LPROCREF";
                    if(kind == 0x1126) symbol_string = "S_DATAREF";
                    if(kind == 0x1125) symbol_string = "S_PROCREF";
                    
                    if(sizeof(*symbol_reference) > length){
                        return pdb_error(context, "Error: %s (symbol index %d) symbol in the symbol record stream is too small.", symbol_string, symbol_index);
                    }
                    
                    char *error = codeview_symbol_check_name_field(context, symbol_reference->name, symbol_buffer + length, symbol_index, symbol_buffer, length, kind);
                    if(error) return error;
                }break;
                
                case /*S_GDATA32*/0x110d:
                case /*S_LDATA32*/0x110c:{
                    struct codeview_data32{
                        u32 type_index;
                        u32 offset_in_section;
                        u16 section_id;
                        u8 name[];
                    } *data32 = (void *)symbol_buffer;
                    
                    char *gdata32_ldata32 = (kind == 0x110c) ? "S_LDATA32" : "S_GDATA32";
                    
                    if(sizeof(*data32) > length){
                        return pdb_error(context, "Error: %s (symbol index %d) symbol in the symbol record stream is too small.", gdata32_ldata32, symbol_index);
                    }
                    
                    char *error = codeview_symbol_check_name_field(context, data32->name, symbol_buffer + length, symbol_index, symbol_buffer, length, kind);
                    if(error) return error;
                }break;
                
                case /*S_CONSTANT*/0x1107:{
                    //
                    // constants are sort of weird they contain a _numeric leaf_,
                    // which is like a typed value.
                    //
                    
                    struct codeview_constant{
                        u32 type_index;
                        u16 numeric_leaf;
                    } *constant = (void *)symbol_buffer;
                    
                    int numeric_leaf_size = pdb_numeric_leaf_size_or_error(constant->numeric_leaf);
                    if(numeric_leaf_size == -1){
                        return pdb_error(context, "Error: Could not parse numeric leaf for S_CONSTANT at symbol index %d in the symbol record stream.", symbol_index);
                    }
                    
                    if(6 + numeric_leaf_size > length){
                        return pdb_error(context, "Error: Numeric leaf for S_CONSTANT at symbol index %d in symbol record stream speicifies a size which exceeds the symbol size.", symbol_index);
                    }
                    
                    u8 *name = symbol_buffer + 6 + numeric_leaf_size;
                    
                    //
                    // @cleanup: maybe try to search up this constant as a way to check the name.
                    //
                    
                    char *error = codeview_symbol_check_name_field(context, name, symbol_buffer + length, symbol_index, symbol_buffer, length, kind);
                    if(error) return error;
                }break;
                
                case /*S_UDT*/0x1108:{
                    struct codeview_udt{
                        u32 type_index;
                        u8 name[];
                    } *udt = (void *)symbol_buffer;
                    
                    if(sizeof(*udt) > length){
                        return pdb_error(context, "Error: S_UDT (symbol index %d) symbol in the symbol record stream is too small.", symbol_index);
                    }
                    
                    char *error = codeview_symbol_check_name_field(context, udt->name, symbol_buffer + length, symbol_index, symbol_buffer, length, kind);
                    if(error) return error;
                }break;
                
                default:{
                    return pdb_error(context, "Internal Error: Unknown symbol 0x%x in the symbol record stream.", symbol.record_kind);
                }break;
            }
        }
    }
    
    if(context->global_symbol_index_stream.stream_index){
        char *error = pdb_parse_and_validate_public_or_global_symbol_index_stream(context, context->global_symbol_index_stream, /*is_public_symbol_index_stream*/0);
        if(error) return error;
    }
    
    if(context->public_symbol_index_stream.stream_index){
        //
        // public symbol stream
        //
        struct pdb_stream public_symbol_index_stream = context->public_symbol_index_stream;
        
        struct codeview_public_symbol{
            u16 record_length;
            u16 record_kind;
            u32 flags;
            u32 offset;
            u16 section_id;
            u8 name[2];
        };
        
        struct public_symbol_stream_header{
            
            // The version of the 'global_symbol_index_stream' for only 'S_PUB32'
            u32 symbol_hash_table_information_byte_size;
            
            //
            // A sorted list of symbol offsets, this allows for binary searching by rva.
            // One should look at this array as a sorted list of pointers.
            // An entry in this array can be converted to a 'S_PUB32' by adding the offset to
            // the symbol record stream.
            //
            u32 address_map_byte_size;
            
            //
            // Thunks are small pieces of codes, which are emitted to transition to a function, for example:
            //    @ILT+120(wcsncpy_s):
            //      000000014000107D: E9 8A 74 04 00     jmp         wcsncpy_s
            // Why these are emitted? It seems they are related to Incremental linking,
            // the implementation of 'DBI1::IsLinkedIncrementally' checks if the size of the chunk map is
            // non-zero to determine if it was incrementally linked, for older versions (now there is a flag).
            //
            
            // The number of these thunks
            u32 number_of_thunks;
            
            // the size of one of one of these thunks
            u32 thunk_byte_size;
            
            // the section id, these thunks are located in
            u16 thunk_table_section_id; u16 padding;
            
            // the offset within the section, these sections are located.
            u32 thunk_table_offset;
            
            //
            // There is a 'thunk map' contained in the public symbol hash stream.
            // It is '4 * number_of_thunks' big and is used to map thunk-addresses
            // indices to their non-thunk functions.
            //     thunk_map[(thunk_rva - thunk_map_rva)/thunk_byte_size] = function_rva.
            //
            
            //
            // Number of sections in the Section map.
            // It seems that '1' is always enough as this section map is only used
            // to check if an address is inside the 'thunk_map'.
            // The section map is presumably used to map address to sections.
            //
            u32 number_of_sections;
        } public_symbol_stream_header;
        
        if(pdb_read_from_stream(context, &public_symbol_index_stream, &public_symbol_stream_header, sizeof(public_symbol_stream_header))){
            return pdb_error(context, "Error: The public symbol hash stream is to small to contain its header.");
        }
        
        u64 hash_table_size  = public_symbol_stream_header.symbol_hash_table_information_byte_size;
        u64 address_map_size = public_symbol_stream_header.address_map_byte_size;
        u64 thunk_map_size   = 4 * (u64)public_symbol_stream_header.number_of_thunks;
        u64 section_map_size = 8 * (u64)public_symbol_stream_header.number_of_sections;
        
        if(public_symbol_index_stream.stream_size != sizeof(struct public_symbol_stream_header) + hash_table_size + address_map_size + thunk_map_size + section_map_size){
            return pdb_error(context, "Error: The public symbol hash stream size differs from the size expected by parsing its header.");
        }
        
        if((address_map_size & 3) != 0){
            return pdb_error(context, "Error: The address map size specified in the public symbol hash stream is not 4 byte aligned.");
        }
        
        struct pdb_stream hash_substream        = pdb_substream(&public_symbol_index_stream, hash_table_size);
        struct pdb_stream address_map_substream = pdb_substream(&public_symbol_index_stream, address_map_size);
        struct pdb_stream thunk_map_substream   = pdb_substream(&public_symbol_index_stream, thunk_map_size);
        struct pdb_stream section_map_substream = pdb_substream(&public_symbol_index_stream, section_map_size);
        
        {
            char *error = pdb_parse_and_validate_public_or_global_symbol_index_stream(context, hash_substream, /*is_public_symbol_index_stream*/1);
            if(error) return error;
        }
        
        u32 amount_of_address_map_entries = address_map_size / 4;
        
        // @note: there are certain symbols which have a section index past the end of the section header.
        //        these seem to correspond to the load configuration entries, so I am gonna call them
        //        "load configuration entries".
        //        Most likely this is just a quirk of how microsoft does things.
        int had_load_configuration_symbol = 0;
        u32 first_load_configuration_entry = amount_of_address_map_entries;
        
        u32 current_section = (u16)-1;
        struct pdb_image_section_header section_header = {0};
        
        for(u32 address_map_entry_index = 0, last_rva = 0; address_map_entry_index < amount_of_address_map_entries; address_map_entry_index++){
            u32 symbol_offset = pdb_read_type_from_stream(context, &address_map_substream, u32);
            
            if((symbol_offset & 3) != 0){
                return pdb_error(context, "Error: The %d entry of the address map inside the public symbol hash stream is a offset into the symbol record stream which has incorrect alignment. Expected 4 byte alignment.", address_map_entry_index);
            }
            
            if(symbol_offset >= context->symbol_record_stream.stream_size){
                return pdb_error(context, "Error: The %d entry of the address map inside the public symbol hash stream is an invalid offset into the symbol record stream.", address_map_entry_index);
            }
            
            //
            // Read the public symbol from the 'symbol_record_stream'
            // and validate that it looks sensable.
            //
            struct pdb_stream symbol_stream = context->symbol_record_stream;
            symbol_stream.current_offset = symbol_offset;
            
            struct codeview_public_symbol public_symbol;
            
            if(pdb_read_from_stream(context, &symbol_stream, &public_symbol, sizeof(public_symbol))){
                return pdb_error(context, "Error: The %d entry of the address map inside the public symbol hash stream is not an offset to an S_PUB32 symbol record.", address_map_entry_index);
            }
            
            if(public_symbol.record_length < sizeof(public_symbol) - 2 || (public_symbol.record_length % 4) != 2 || public_symbol.record_kind != /*S_PUB32*/0x110e){
                return pdb_error(context, "Error: The %d entry of the address map inside the public symbol hash stream is not an offset to an S_PUB32 symbol record.", address_map_entry_index);
            }
            
            //
            // resolve the rva of the 'public_symbol' to check that they are indeed ordered by rva.
            //
            
            if(current_section != public_symbol.section_id){
                u16 section_index = public_symbol.section_id - 1;
                
                if(section_index == context->amount_of_sections){
                    // @cleanup: this can apperently happen...
                    //           symbols here are:
                    //               __guard_longjmp_table
                    //               __enclave_config
                    //               __guard_flags
                    //               __guard_longjmp_count
                    //               __guard_iat_table
                    //               __guard_fids_count
                    //               __guard_fids_table
                    //               __guard_iat_count
                    
                    if(!had_load_configuration_symbol){
                        had_load_configuration_symbol = 1;
                        first_load_configuration_entry = address_map_entry_index;
                    }
                    
                    // So we make sure that these symbols are '__' prefixed I guess...
                    // and then skip them.
                    
                    if(public_symbol.name[0] == '_' && public_symbol.name[1] == '_'){
                        continue;
                    }
                }else{
                    if(had_load_configuration_symbol){
                        return pdb_error(context, "Error: The address map inside of the public symbol hash stream contains a normal symbol after the first load configuration symbol. This should not be possible as load configuration symbols are supposed to be loaded, after the image.");
                    }
                }
                
                if(section_index >= context->amount_of_sections){
                    return pdb_error(context, "Error: The %d entry of the address map inside the public symbol hash stream point to a public symbol which has an invalid section id.", address_map_entry_index);
                }
                
                context->section_header_dump_stream.current_offset = sizeof(struct pdb_image_section_header) * section_index;
                pdb_read_from_stream(context, &context->section_header_dump_stream, &section_header, sizeof(section_header));
                
                current_section = public_symbol.section_id;
            }
            
            if(public_symbol.offset > section_header.virtual_size){
                return pdb_error(context, "Error: The %d entry of the address map inside the public symbol hash stream point to a public symbol which has an invalid offset.", address_map_entry_index);
            }
            
            u32 rva = section_header.virtual_address + public_symbol.offset;
            
            if(last_rva > rva){
                return pdb_error(context, "Error: The %d entry of the address map inside the public symbol hash stream is out of order. These entries are supposed to be sorted by relative virtual address.", address_map_entry_index);
            }
            
            last_rva = rva;
        }
        
        if(public_symbol_stream_header.number_of_thunks){
            if(public_symbol_stream_header.thunk_byte_size == 0){
                return pdb_error(context, "Error: The thunk map inside of the public symbol hash stream is non-zero, but the size of a thunk is zero.");
            }
            
            u16 section_index = public_symbol_stream_header.thunk_table_section_id - 1;
            if(section_index >= context->amount_of_sections){
                return pdb_error(context, "Error: The thunk map inside of the public symbol hash stream is non-zero, but the thunk map section id is invalid. Section ids are one indexed.");
            }
            
            current_section = public_symbol_stream_header.thunk_table_section_id;
            context->section_header_dump_stream.current_offset = sizeof(struct pdb_image_section_header) * section_index;
            pdb_read_from_stream(context, &context->section_header_dump_stream, &section_header, sizeof(section_header));
            
            u64 thunk_table_offset = public_symbol_stream_header.thunk_table_offset;
            u64 thunk_table_size   = (u64)public_symbol_stream_header.thunk_byte_size * (u64)public_symbol_stream_header.number_of_thunks;
            
            // @note: check both ends to prevent overflow issues
            if(thunk_table_offset > section_header.virtual_size || thunk_table_offset + thunk_table_size > section_header.virtual_size){
                return pdb_error(context, "Error: The thunk map inside of the public symbol hash stream specifies an thunk table which does not fit inside of the corresponding section.");
            }
        }
        
        for(u32 thunk_index = 0; thunk_index < public_symbol_stream_header.number_of_thunks; thunk_index++){
            u32 function_rva = pdb_read_type_from_stream(context, &thunk_map_substream, u32);
            
            //
            // Binary search the 'function_rva' to find its public symbol.
            //
            
            s64 min_index = 0;
            s64 max_index = first_load_configuration_entry - 1;
            
            int found = 0;
            
            while(min_index <= max_index){
                u32 index = min_index + (max_index - min_index)/2;
                
                address_map_substream.current_offset = (u64)index * 4;
                
                u32 public_symbol_rva = 0;
                {
                    //
                    // Figure out he public symbol rva.
                    //
                    
                    u32 symbol_offset = pdb_read_type_from_stream(context, &address_map_substream, u32);
                    
                    struct pdb_stream symbol_stream = context->symbol_record_stream;
                    symbol_stream.current_offset = symbol_offset;
                    
                    struct codeview_public_symbol public_symbol = pdb_read_type_from_stream(context, &symbol_stream, struct codeview_public_symbol);
                    
                    u16 section_index = public_symbol.section_id - 1;
                    
                    if(current_section != public_symbol.section_id){
                        context->section_header_dump_stream.current_offset = sizeof(struct pdb_image_section_header) * section_index;
                        pdb_read_from_stream(context, &context->section_header_dump_stream, &section_header, sizeof(section_header));
                        
                        current_section = public_symbol.section_id;
                    }
                    
                    public_symbol_rva = section_header.virtual_address + public_symbol.offset;
                }
                
                if(public_symbol_rva < function_rva){
                    min_index = index + 1;
                }else if(public_symbol_rva > function_rva){
                    max_index = index - 1;
                }else{
                    found = 1;
                    break;
                }
            }
            
            if(!found){
                return pdb_error(context, "Error: The %d entry of the thunk map inside the public symbol hash stream does not map to the rva of a public symbol.", thunk_index);
            }
        }
        
        for(u32 section_map_entry_index = 0; section_map_entry_index < public_symbol_stream_header.number_of_sections; section_map_entry_index++){
            struct pdb_thunk_section_map_entry{
                u32 rva;
                u16 section_id;
            } section_map_entry = pdb_read_type_from_stream(context, &section_map_substream, struct pdb_thunk_section_map_entry);
            
            u32 section_index = section_map_entry.section_id - 1;
            if(section_index >= context->amount_of_sections){
                return pdb_error(context, "Error: Entry %d of the section map of the thunk map contained in the public symbol hash stream specifies an invalid section id.", section_map_entry_index);
            }
            
            context->section_header_dump_stream.current_offset = sizeof(struct pdb_image_section_header) * section_index;
            pdb_read_from_stream(context, &context->section_header_dump_stream, &section_header, sizeof(section_header));
            
            if(section_header.virtual_address != section_map_entry.rva){
                return pdb_error(context, "Error: Entry %d of the section map of the thunk map contained in the public symbol hash stream specifies a relative virtual address which does not map the sections relative virtual address.", section_map_entry_index);
            }
        }
    }
    
    return 0;
}

struct file{
    u8 *memory;
    size_t size;
};

struct file load_file(char *file_name){
    struct file file = {};
    
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
    
    u8 *memory = malloc(size + 1);
    if(!memory){
        print("Could not allocate memory for %s\n", file_name);
        return file;
    }
    
    fread(memory, 1, size, handle);
    fclose(handle);
    
    return (struct file){ .memory = memory, .size = size };
}

int main(int argc, char *argv[]){
    if(argc != 2){
        print("usage: %s <pdb>\n", argv[0]);
        return 1;
    }
    
    struct file pdb = load_file(argv[1]);
    if(!pdb.memory) return 1;
    
    struct pdb_context pdb_context;
    char *error = pdb_initialize_context(&pdb_context, pdb.memory, pdb.size);
    
    if(error){
        print("%s\n", error);
    }else{
        print("success!\n");
    }
    
    return 0;
}
