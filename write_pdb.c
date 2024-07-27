
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
    
    PDB_CURRENT_AMOUNT_OF_STREAMS, // @incomplete:
    
    PDB_STREAM_tpi_hash,
    PDB_STREAM_ipi_hash,
    
    PDB_STREAM_section_header_dump,
    
    PDB_STREAM_symbol_record,
    PDB_STREAM_global_symbol_index,
    PDB_STREAM_public_symbol_index,
    
    PBB_STREAM_module_symbol_stream_base,
};

// For reference see `HashPbCb` in `microsoft-pdb/PDB/include/misc.h`.
u16 pdb_hash_index(u8 *bytes, size_t size, u32 modulus){
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
    return (u16)(hash % modulus);
}

u16 hash_string(char *string){
    return pdb_hash_index((u8 *)string, strlen(string), (u32)-1);
}


struct write_pdb_information{
    u32 amount_of_object_files;
    struct stream *type_information_per_object;
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
            struct guid{
                u32 data1;
                u16 data2;
                u16 data3;
                u8 data4[8];
            } guid;
        } *pdb_information_stream_header = push_struct(&pdb_information_stream, struct pdb_information_stream_header);
        pdb_information_stream_header->version = 20000404;
        pdb_information_stream_header->timestamp = time(NULL);
        pdb_information_stream_header->age = 1;
        pdb_information_stream_header->guid = (struct guid){0x13371337, 0x1337, 0x1337, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37};
        
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
    
    
    struct memory_arena names_stream = create_memory_arena(giga_bytes(8));
    {
        // 
        // Fill out the /names stream.
        // Layout:
        //     u32 signature;
        //     u32 hash_version;
        //     u32 string_buffer_byte_size;
        //     u8  string_buffer[string_buffer_byte_size];
        //     u32 bucket_count;
        //     u32 buckets[bucket_count];
        //     u32 amount_of_strings;
        // 
        
        *push_struct(&names_stream, u32) = /*signature*/0xEFFEEFFE;
        *push_struct(&names_stream, u32) = /*hash_version*/1;
        
        u32 *string_buffer_byte_size = push_struct(&names_stream, u32);
        u8 *string_buffer = push_array(&names_stream, u8, 0);
        
        // "The first string inside the string buffer always has to be the zero-sized string, 
        //  as a zero offset is also used as an invalid offset in the hash table."
        push_struct(&names_stream, u8); // zero-sized string!
        
        *string_buffer_byte_size = push_array(&names_stream, u8, 0) - string_buffer;
        
        // @WARNING: "Importantly, the size of the string buffer is not aligned, 
        //            thus usually the rest of the stream is unaligned."
        
        *push_struct_unaligned(&names_stream, u32) = /*bucket_count*/1;
        *push_struct_unaligned(&names_stream, u32) = /*bucket[0]*/0;
        
        *push_struct_unaligned(&names_stream, u32) = /*amount_of_strings*/0;
    }
    
    struct memory_arena tpi_stream = create_memory_arena(giga_bytes(8));
    struct memory_arena ipi_stream = create_memory_arena(giga_bytes(8));
    
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
        
        u32 ipi_type_index_at = 0x1000;
        u32 tpi_type_index_at = 0x1000;
        
        for(u32 object_file_index = 0; object_file_index < write_pdb_information->amount_of_object_files; object_file_index++){
            
            struct stream type_information = write_pdb_information->type_information_per_object[object_file_index];
            
            u32 signature;
            if(stream_read(&type_information, &signature, sizeof(signature)) || signature != /*CV_SIGNATURE_C13*/4) continue;
            
            // We daisy chain this map into 'arena', whenever we handle a type record below.
            u32 *object_file_type_index_to_pdb_file_type_index_map = push_array(&arena, u32, 0);
            
            struct codeview_type_record_header{
                u16 length;
                u16 kind;
            } type_record_header;
            
            u32 type_index = 0x1000;
            
            while(!stream_read(&type_information, &type_record_header, sizeof(type_record_header))){
                
                int record_size = type_record_header.length - sizeof(type_record_header.kind);
                if(record_size < 0) break;
                
                u8 *record_data = stream_read_array_by_pointer(&type_information, 1, record_size);
                if(!record_data) break;
                
                // 
                // We need to remap all of the type indices used by the type records,
                // from the object file local ones to the pdb ones.
                // 
                
#define remap_type_index(v) (v) = ((v) < 0x1000 ? (v) : ((v >= type_index) ? 0 : object_file_type_index_to_pdb_file_type_index_map[v-0x1000]))
                
                switch(type_record_header.kind){
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
                }
                
                // 
                // Push the type record to the stream and insert an element into the map.
                // 
                
                u32 pdb_type_index;
                
                if(0x1600 <= type_record_header.kind && type_record_header.kind < 0x1700){
                    // This is an Id record and needs to go into the ipi stream.
                    
                    *push_struct(&ipi_stream, struct codeview_type_record_header) = type_record_header;
                    memcpy(push_array(&ipi_stream, u8, record_size), record_data, record_size);
                    
                    pdb_type_index = ipi_type_index_at++;
                }else{
                    // This is a Type record and needs to go into the tpi stream.
                    
                    *push_struct(&tpi_stream, struct codeview_type_record_header) = type_record_header;
                    memcpy(push_array(&tpi_stream, u8, record_size), record_data, record_size);
                    
                    pdb_type_index = tpi_type_index_at++;
                }
                
                /*object_file_type_index_to_pdb_file_type_index_map = */
                *push_struct(&arena, u32) = pdb_type_index;
            }
        }
        
        tpi_header->version = 20040203;
        tpi_header->header_size = sizeof(*tpi_header);
        tpi_header->minimal_type_index = 0x1000;
        tpi_header->one_past_last_type_index = tpi_type_index_at;
        tpi_header->byte_count_of_type_record_data_following_the_header = arena_current(&tpi_stream) - (u8 *)(tpi_header + 1);
        tpi_header->stream_index_of_hash_stream = (u16)-1;
        tpi_header->stream_index_of_auxiliary_hash_stream = (u16)-1;
        
        // @incomplete:
        tpi_header->hash_key_size = 4;
        tpi_header->number_of_hash_buckets = 0x1000;
        tpi_header->hash_table_index_buffer_offset = 0;
        tpi_header->hash_table_index_buffer_length = 0;
        
        tpi_header->index_offset_buffer_offset = 0;
        tpi_header->index_offset_buffer_length = 0;
        
        tpi_header->udt_order_adjust_table_offset = 0;
        tpi_header->udt_order_adjust_table_length = 0;
        
        ipi_header->version = 20040203;
        ipi_header->header_size = sizeof(*ipi_header);
        ipi_header->minimal_type_index = 0x1000;
        ipi_header->one_past_last_type_index = ipi_type_index_at;
        ipi_header->byte_count_of_type_record_data_following_the_header = arena_current(&ipi_stream) - (u8 *)(ipi_header + 1);
        ipi_header->stream_index_of_hash_stream = (u16)-1;
        ipi_header->stream_index_of_auxiliary_hash_stream = (u16)-1;
        
        // @incomplete:
        ipi_header->hash_key_size = 4;
        ipi_header->number_of_hash_buckets = 0x1000;
        ipi_header->hash_table_index_buffer_offset = 0;
        ipi_header->hash_table_index_buffer_length = 0;
        
        ipi_header->index_offset_buffer_offset = 0;
        ipi_header->index_offset_buffer_length = 0;
        
        ipi_header->udt_order_adjust_table_offset = 0;
        ipi_header->udt_order_adjust_table_length = 0;
    }
    
    
    struct msf_stream streams[PDB_CURRENT_AMOUNT_OF_STREAMS] = {0};
    streams[PDB_STREAM_pdb_information].data = pdb_information_stream.base;
    streams[PDB_STREAM_pdb_information].size = arena_current(&pdb_information_stream) - pdb_information_stream.base;
    
    streams[PDB_STREAM_tpi].data = tpi_stream.base,
    streams[PDB_STREAM_tpi].size = arena_current(&tpi_stream) - tpi_stream.base,
    
    streams[PDB_STREAM_ipi].data = ipi_stream.base,
    streams[PDB_STREAM_ipi].size = arena_current(&ipi_stream) - ipi_stream.base,
    
    streams[PDB_STREAM_names].data = names_stream.base;
    streams[PDB_STREAM_names].size = arena_current(&names_stream) - names_stream.base;
    
    // @note: The 0-th stream is added by the write_msf function implicitly.
    write_msf("a.pdb", streams + 1, array_count(streams) - 1);
}

