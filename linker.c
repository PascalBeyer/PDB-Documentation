
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <mbstring.h>

typedef unsigned __int8  u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;

typedef __int8  s8;
typedef __int16 s16;
typedef __int32 s32;
typedef __int64 s64;

#define kilo_bytes(a) ((a) * 1024ULL)
#define mega_bytes(a) ((kilo_bytes(a)) * 1024ULL)
#define giga_bytes(a) ((mega_bytes(a)) * 1024ULL)

#define array_count(a) (sizeof(a)/sizeof(*a))

#include "memory_arena.c"

__declspec(printlike) int print(char *format, ...){
    va_list va;
    va_start(va, format);
    int ret = vprintf(format, va);
    va_end(va);
    
    fflush(0);
    return ret;
}

void print_memory_range(void *_memory, u64 size, u64 offset){
    
    u8 *memory = _memory;
    
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
    
    u8 *memory = malloc(size);
    if(!memory){
        print("Could not allocate memory for %s\n", file_name);
        return file;
    }
    
    fread(memory, 1, size, handle);
    fclose(handle);
    
    return (struct file){ .memory = memory, .size = size };
}

u64 dbj2(char *name, size_t name_length){
    // Good ol' dbj2.
    u64 name_hash = 5381;
    for(u32 i = 0; i < name_length; i++){
        name_hash = (name_hash << 5) + name_hash + name[i];
    }
    return name_hash;
}

//_____________________________________________________________________________________________________________________
// Streams

struct stream{
    u8 *data;
    u64 size;
    u64 offset;
};

int stream_read(struct stream *stream, void *data, size_t size){
    
    if(size + stream->offset > stream->size){
        stream->offset = stream->size;
        return 1;
    }
    
    memcpy(data, stream->data + stream->offset, size);
    stream->offset += size;
    return 0;
}

int stream_peek(struct stream *stream, void *data, size_t size){
    
    if(size + stream->offset > stream->size){
        return 1;
    }
    
    memcpy(data, stream->data + stream->offset, size);
    return 0;
}

int stream_skip(struct stream *stream, size_t size){
    
    if(size + stream->offset > stream->size){
        stream->offset = stream->size;
        return 1;
    }
    
    stream->offset += size;
    return 0;
}

void *stream_read_array_by_pointer(struct stream *stream, u64 member_size, u64 count){
    
    // @cleanup: Overflow.
    u64 size = member_size * count;
    
    if(size + stream->offset > stream->size){
        stream->offset = stream->size;
        return 0;
    }
    
    void *ret = (stream->data + stream->offset);
    stream->offset += size;
    return ret;
}

void *stream_read_range_by_pointer(struct stream *stream, u64 start, u64 size, u64 count){
    
    // @cleanup: Overflow.
    u64 end = start + size * count;
    
    if(start > stream->size || end > stream->size) return 0;
    
    return stream->data + start;
}

//_____________________________________________________________________________________________________________________
// Strings

struct string{
    char *data;
    size_t size;
};

#define string(a) (struct string){ .data = (a), .size = sizeof(a)-1 }

int string_match(struct string a, struct string b){
    if(a.size != b.size) return 0;
    return strncmp(a.data, b.data, a.size) == 0;
}

struct string string_strip_whitespace(struct string string){
    
    while(string.size && string.data[string.size-1] == ' '){
        string.size -= 1;
    }
    
    while(string.size && string.data[0] == ' '){
        string.size -= 1;
        string.data += 1;
    }
    
    return string;
}

//_____________________________________________________________________________________________________________________
// Object files

struct coff_file_header{
    u16 machine;
    u16 number_of_sections;
    u32 timestamp;
    u32 pointer_to_symbol_table;
    u32 number_of_symbols;
    u16 size_of_optional_header;
    u16 file_characteristics;
};

struct image_optional_header64{
    u16 magic;
    u8  major_linker_version;
    u8  minor_linker_version;
    u32 size_of_code;
    u32 size_of_initialized_data;
    u32 size_of_uninitialized_data;
    u32 address_of_entry_point;
    u32 base_of_code;
    u64 image_base;
    u32 section_alignment;
    u32 file_alignment;
    u16 major_operating_system_version;
    u16 minor_operating_system_version;
    u16 major_image_version;
    u16 minor_image_version;
    u16 major_subsystem_version;
    u16 minor_subsystem_version;
    u32 win32_version_value;
    u32 size_of_image;
    u32 size_of_headers;
    u32 checksum;
    u16 subsystem;
    u16 dll_characteristics;
    u64 size_of_stack_reserve;
    u64 size_of_stack_commit;
    u64 size_of_heap_reserve;
    u64 size_of_heap_commit;
    u32 loader_flags;
    u32 number_of_rva_and_sizes;
    
    struct image_data_directory{
        u32 virtual_address;
        u32 size;
    } data_directory[16];
};

struct coff_section_header{
    char name[8];
    u32 virtual_size;
    u32 virtual_address;
    u32 size_of_raw_data;
    u32 pointer_to_raw_data;
    u32 pointer_to_relocations;
    u32 pointer_to_line_numbers;
    u16 number_of_relocations;
    u16 number_of_line_numbers;
    u32 characteristics;
};

struct __declspec(packed) coff_relocation {
    u32 relocation_address;
    u32 symbol_table_index;
    u16 relocation_type;
};

_Static_assert(sizeof(struct coff_relocation) == 10, "coff relocation size incorrect.");

struct __declspec(packed) coff_symbol {
    union{
        char short_name[8];
        struct{
            u32 zeroes;
            u32 offset;
        } long_name;
    };
    
    u32 value;
    s16 section_number;
    u16 symbol_type;
    u8 storage_class;
    u8 number_of_auxiliary_symbol_records;
};

_Static_assert(sizeof(struct coff_symbol) == 18, "coff symbol size incorrect.");

struct object_file{
    char *file_name;
    struct stream stream;
    
    u16 number_of_sections;
    u32 number_of_symbols;
    u32 string_table_size;
    struct coff_section_header *section_headers;
    struct coff_symbol *symbol_table;
    u8 *string_table;
};

int parse_object_file(struct object_file *object_file){
    
    struct stream stream = object_file->stream;
    
    struct coff_file_header file_header;
    
    if(stream_read(&stream, &file_header, sizeof(file_header))) return 0;
    
    if(file_header.machine != 0x8664) return 0;
    
    // 
    // Get the symbol table.
    // 
    struct coff_symbol *symbol_table = stream_read_range_by_pointer(&stream, file_header.pointer_to_symbol_table, sizeof(struct coff_symbol), file_header.number_of_symbols);
    if(!symbol_table) return 0;
    
    stream_skip(&stream, file_header.size_of_optional_header);
    
    struct coff_section_header *section_headers = stream_read_array_by_pointer(&stream, sizeof(*section_headers), file_header.number_of_sections);
    if(!section_headers) return 1;
    
    for(u32 index = 0; index < file_header.number_of_sections; index++){
        struct coff_section_header *section_header = &section_headers[index];
        
        // 
        // Check that the contents are in bounds.
        // 
        
        if(section_header->characteristics & /*UNINITIALIZED_DATA*/0x00000080){
            if(section_header->number_of_relocations) return 0; // @paranoid
            if(section_header->pointer_to_raw_data)   return 0;
            continue;
        }
        
        void *section_data = stream_read_range_by_pointer(&stream, section_header->pointer_to_raw_data, 1, section_header->size_of_raw_data);
        if(!section_data) return 0;
        
        // @cleanup: Do the relocation overflow thing.
        struct coff_relocation *relocations = stream_read_range_by_pointer(&stream, section_header->pointer_to_relocations, sizeof(struct coff_relocation), section_header->number_of_relocations);
        if(!relocations) return 0;
    }
    
    stream.offset = file_header.pointer_to_symbol_table + sizeof(struct coff_symbol) * file_header.number_of_symbols;
    
    u32 string_table_size; // @note: Contains this 'string_table_size' field.
    if(stream_peek(&stream, &string_table_size, sizeof(string_table_size))) return 0;
    if(string_table_size < 4) return 0;
    
    u8 *string_table = stream_read_array_by_pointer(&stream, 1, string_table_size);
    if(!string_table || string_table[string_table_size-1] != 0) return 0;
    
    object_file->number_of_symbols = file_header.number_of_symbols;
    object_file->symbol_table = symbol_table;
    
    object_file->number_of_sections = file_header.number_of_sections;
    object_file->section_headers = section_headers;
    
    object_file->string_table_size = string_table_size;
    object_file->string_table = string_table;
    
    return 1;
}

//_____________________________________________________________________________________________________________________
// Ar files.

struct ar_file{
    char *file_name;
    struct stream stream;
    
    u32 amount_of_members;
    u32 amount_of_symbols;
    u32 *member_offsets;
    u16 *symbol_member_indices;
    char **import_symbol_string_table;
    u32 amount_of_import_symbols;
    u32 import_symbol_base;
};

struct ar_file_header{
    // 
    // An ASCII file-identifier.
    // 
    u8 file_identifier[16];
    
    // 
    // The modification time in seconds, as ASCII-decimal. 
    // 
    u8 file_modification_timestamp[12];
    
    // 
    // Owner and group ID as ASCII-decimal.
    // 
    u8 owner_identifier[6];
    u8 group_identifier[6];
    
    // 
    // The file type and permissions as ASCII-octal.
    // 
    u8 file_mode[8];
    
    // 
    // The size of the file in bytes as ASCII-decimal.
    // 
    u8 file_size_in_bytes[10];
    
    // 
    // The characters '`\n`
    // 
    u8 ending_characters[2];
};

// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#archive-library-file-format
// 
// The ar (or archiver) file-format is used by .lib-files
// and combines multiple .obj-files into one .lib-file.
// 
// The file begins with the signature '!<arch>\n'.
// After this the file is a sequence of file sections.
// Each file section starts with a header which specifies the size 
// and name of the file section.
// The header is followed by the data of the file-section.
// 
// The first two or three file-sections are special.
// The first and second one are a symbol index and have the name '/'.
// The first one in big-endian, the second one in little-endian.
// The third section is optionally '//', the long name data.
// 

int parse_ar_file(struct memory_arena *arena, struct ar_file *ar_file){
    struct stream stream = ar_file->stream;
    
    char *file_name = ar_file->file_name;
    
    char signature[8];
    if(stream_read(&stream, signature, sizeof(signature))) return 0;
    if(memcmp(signature, "!<arch>\n", 8) != 0) return 0;
    
    struct stream little_endian_symbol_index = {0};
    struct ar_file_header ar_file_header;
    
    for(u32 file_header_index = 0; !stream_read(&stream, &ar_file_header, sizeof(ar_file_header)); file_header_index++){
        
        struct string file_identifier  = string_strip_whitespace((struct string){.data = (char *)ar_file_header.file_identifier,    .size = sizeof(ar_file_header.file_identifier)});
        struct string file_size_string = string_strip_whitespace((struct string){.data = (char *)ar_file_header.file_size_in_bytes, .size = sizeof(ar_file_header.file_size_in_bytes)});
        
        // Hack: We overwrite the file header here to make sure the file size string is zero-terminated.
        file_size_string.data[file_size_string.size] = 0;
        
        u64 file_size = strtoull(file_size_string.data, NULL, 10);
        if(file_size == (u64)-1) return 0;
        
        u8 *file_data = stream_read_array_by_pointer(&stream, 1, file_size);
        
        // Each data section has two-byte alignment.
        if(stream_skip(&stream, (file_size & 1)) || !file_data) return 0;
        
        if(file_header_index == 0 && string_match(file_identifier, string("/"))){
            // The first file section should be the first linker member.
            // We only use the Microsoft-specific second linker member.
            continue;
        }
        
        if(file_header_index == 1 && string_match(file_identifier, string("/"))){
            // The first file section should be the second linker member.
            // This is a Microsoft-specific thing.
            little_endian_symbol_index = (struct stream){.data = file_data, .size = file_size};
            continue;
        }
        
        if(string_match(file_identifier, string("//"))){
            // Optionally, the long name data member should be immediately after the headers.
            // This is only used by the first file header to store longer strings.
        }
        
        break;
    }
    
    if(!little_endian_symbol_index.data){
        print("Error: Failed to parse library '%s', currently only Windows-style import libraries are supported.\n", file_name);
        return 0;
    }
    
    // 
    // The second linker member, or Microsoft specific symbol index, has the following layout:
    //     
    //     u32 amount_of_members;
    //     u32 member_offsets[amount_of_members];
    //     u32 amount_of_symbols;
    //     u16 symbol_member_indices[amount_of_symbols];
    //     char string_table[]; // 'amount_of_symbols' many zero-terminated strings.
    //     
    // The algorithm goes as follows:
    //     
    //     u32 symbol_index  = binary_search(string_table, <identifier>);
    //     u16 member_index  = symbol_member_indices[symbol_index];
    //     u32 member_offset = member_offsets[member_index - 1];
    //     
    //     struct ar_file_header *file_header = (void *)(file.data + member_offset);
    //     <parse the .obj or import-header>
    // 
    
    // Ensure the string table is zero-terminated.
    if(little_endian_symbol_index.data[little_endian_symbol_index.size-1] != 0) return 0;
    
    u32 amount_of_members;
    if(stream_read(&little_endian_symbol_index, &amount_of_members, sizeof(amount_of_members))) return 0;
    
    u32 *member_offsets = stream_read_array_by_pointer(&little_endian_symbol_index, sizeof(u32), amount_of_members);
    if(!member_offsets) return 0;
    
    u32 amount_of_symbols;
    if(stream_read(&little_endian_symbol_index, &amount_of_symbols, sizeof(amount_of_symbols))) return 0;
    
    u16 *symbol_member_indices = stream_read_array_by_pointer(&little_endian_symbol_index, sizeof(u16), amount_of_symbols);
    if(!symbol_member_indices) return 0;
    
    char *string_buffer = (char *)(little_endian_symbol_index.data + little_endian_symbol_index.offset);
    char *string_buffer_end = (char *)(little_endian_symbol_index.data + little_endian_symbol_index.size);
    
    char **import_symbol_string_table = push_array(arena, char *, 0);
    
    u64 amount_of_strings  = 0;
    s64 import_symbol_base = -1;
    
    for(char *it = string_buffer; it < string_buffer_end; it += strlen(it) + 1){
        
        if(strncmp(it, "__imp_", 6) == 0){
            if(import_symbol_base == -1) import_symbol_base = amount_of_strings;
            *push_struct(arena, char *) = it + 6; // skipping the "__imp_".
        }
        
        amount_of_strings++;
    }
    
    if(amount_of_strings != amount_of_symbols) return 0;
    
    u64 amount_of_import_symbols = push_array(arena, char *, 0) - import_symbol_string_table;
    
    ar_file->amount_of_members          = amount_of_members;
    ar_file->amount_of_symbols          = amount_of_symbols;
    ar_file->member_offsets             = member_offsets;
    ar_file->symbol_member_indices      = symbol_member_indices;
    ar_file->import_symbol_string_table = import_symbol_string_table;
    ar_file->amount_of_import_symbols   = amount_of_import_symbols;
    ar_file->import_symbol_base         = import_symbol_base;
    
    return 1;
}

struct dll_list{
    struct dll_import_node *first;
    struct dll_import_node *last;
    u64 size;
};

struct dll_import_node{
    struct dll_import_node *next;
    char *name;
    u64 dllimport_index;
    
    u64 *import_address_table;
    u64 *import_lookup_table;
    u32 import_address_table_relative_virtual_address;
};

struct dll_import_node *ar_lookup_symbol(struct dll_list *dll_list, struct memory_arena *arena, struct ar_file *ar_file, char *symbol_name, u16 *hint){
    
    // The algorithm goes as follows:
    //     
    //     u32 symbol_index  = binary_search(string_table, <identifier>);
    //     u16 member_index  = symbol_member_indices[symbol_index];
    //     u32 member_offset = member_offsets[member_index - 1];
    //     
    //     struct ar_file_header *file_header = (void *)(file.data + member_offset);
    //     <parse the .obj or import-header>
    
    int strcmp_wrapper(void *a, void *b){
        char **_a = a;
        char **_b = b;
        return strcmp(*_a, *_b);
    }
    
    char **found = bsearch(&symbol_name, ar_file->import_symbol_string_table, ar_file->amount_of_import_symbols, sizeof(*ar_file->import_symbol_string_table), strcmp_wrapper);
    if(!found) return 0;
    
    u32 symbol_index = (u32)(found - ar_file->import_symbol_string_table);
    u16 member_index = ar_file->symbol_member_indices[ar_file->import_symbol_base + symbol_index];
    if(member_index - 1 > ar_file->amount_of_members) return 0;
    
    u32 member_offset = ar_file->member_offsets[member_index-1];
    
    struct ar_file_header *ar_file_header = stream_read_range_by_pointer(&ar_file->stream, member_offset, sizeof(struct ar_file_header), 1);
    if(!ar_file_header) return 0;
    
    struct string file_size_string = string_strip_whitespace((struct string){.data = (char *)ar_file_header->file_size_in_bytes, .size = sizeof(ar_file_header->file_size_in_bytes)});
    
    // Hack: We overwrite the file header here to make sure the file size string is zero-terminated.
    file_size_string.data[file_size_string.size] = 0;
    u64 file_size = strtoull(file_size_string.data, NULL, 10);
    file_size_string.data[file_size_string.size] = ' ';
    
    if(file_size == (u64)-1) return 0;
    
    u8 *file_data = stream_read_range_by_pointer(&ar_file->stream, member_offset + sizeof(*ar_file_header), 1, file_size);
    if(!file_data) return 0;
    
    struct ar_import_header{
        u16 signature_1;
        u16 signature_2;
        u16 version;
        u16 machine;
        u32 time_date_stamp;
        u32 size_of_data;
        u16 ordinal_hint;
        u16 type : 2;      // 0 - code, 1 - data, 2 - const
        u16 name_type : 3; // 0 - ordinal, 1 - name, 2 - noprefix, 3 - undecorated
        u16 reserved : 11;
    } *import_header = (void *)file_data;
    
    // Layout: 
    //    ar_import_header
    //    identifier (symbol)
    //    dll_name
    // 
    
    if(file_size < sizeof(*import_header) || file_data[file_size-1] != 0) return 0;
    
    // Ensure this is an import header.
    if(import_header->signature_1 != 0) return 0;
    if(import_header->signature_2 != 0xffff) return 0;
    if(import_header->name_type != 1) return 0;
    
    *hint = import_header->ordinal_hint;
    
    char *identifier = (char *)(import_header + 1);
    char *dll_name   = identifier + strlen(identifier) + 1;
    if(dll_name >= (char *)(file_data + file_size)) return 0;
    
    for(struct dll_import_node *it = dll_list->first; it; it = it->next){
        if(strcmp(it->name, dll_name) == 0) return it;
    }
    
    struct dll_import_node *node = push_struct(arena, struct dll_import_node);
    node->name = dll_name;
    
    if(dll_list->first){
        node->next = dll_list->first;
        dll_list->first = node;
    }else{
        dll_list->first = dll_list->last = node;
    }
    dll_list->size += 1;
    
    return node;
}

struct string get_symbol_name(struct coff_symbol *symbol, struct object_file *object_file){
    u8 *string_table = object_file->string_table;
    size_t string_table_size = object_file->string_table_size;
    
    char *name;
    size_t name_length;
    if(symbol->long_name.zeroes == 0){
        if(symbol->long_name.offset >= string_table_size){
            print("Error: Object file '%s' has corrupt symbol table.\n", object_file->file_name);
            return (struct string){0};
        }
        
        name = (char *)string_table + symbol->long_name.offset;
        name_length = strlen(name);
    }else{
        name = symbol->short_name;
        name_length = strnlen(name, sizeof(symbol->short_name));
    }
    
    return (struct string){.data = name, .size = name_length };
}

int main(int argc, char *argv[]){
    
    if(argc < 2){
        print("Usage: %s <obj-files...>\n", argv[0]);
        return 0;
    }
    
    struct memory_arena arena = create_memory_arena(giga_bytes(64));
    
    u32 amount_of_files = argc-1;
    u32 amount_of_ar_files = 0;
    u32 amount_of_object_files = 0;
    
    struct object_file *object_files = push_array(&arena, struct object_file, amount_of_files);
    struct ar_file     *ar_files     = push_array(&arena, struct ar_file,     amount_of_files);
    
    // 
    // Parse all the object files.
    // 
    for(u32 index = 0; index < amount_of_files; index++){
        char *file_name = argv[index + 1];
        
        struct file file = load_file(file_name);
        if(!file.memory) return 1;
        
        char *extension = (char *)_mbsrchr((u8 *)file_name, '.');
        
        int success = 0;
        
        if(strcmp(extension, ".obj") == 0){
            struct object_file object_file = {
                .file_name = file_name,
                .stream = {
                    .data = file.memory,
                    .size = file.size,
                    .offset = 0,
                },
            };
            
            success = parse_object_file(&object_file);
            
            object_files[amount_of_object_files++] = object_file;
        }else if(strcmp(extension, ".lib") == 0){
            struct ar_file ar_file = {
                .file_name = file_name,
                .stream = {
                    .data = file.memory,
                    .size = file.size,
                    .offset = 0,
                },
            };
            
            success = parse_ar_file(&arena, &ar_file);
            ar_files[amount_of_ar_files++] = ar_file;
        }
        
        if(!success){
            print("Error: Parsing object file '%s'.\n", file_name);
            return 1;
        }
    }
    
    // 
    // Figure out all external symbols and put them into a hash table for feature use.
    // 
    u64 external_symbols_capacity = 0x100;
    u64 external_symbols_size = 0;
    
    struct external_symbol{
        struct string name;
        u32 size;
        u32 is_defined;
        u32 object_file_index;
        u32 offset;
        u16 section_number;
        
        u32 is_ImageBase;
        
        u16 hint;
        u32 is_dllimport;
        u32 dllimport_index;
        struct dll_import_node *dll;
    } *external_symbols = push_array(&arena, struct external_symbol, external_symbols_capacity);
    
    for(u32 object_file_index = 0; object_file_index < amount_of_object_files; object_file_index++){
        struct object_file *object_file = &object_files[object_file_index];
        
        struct coff_symbol *symbol_table = object_file->symbol_table;
        u8 *string_table = object_file->string_table;
        
        u32 string_table_size = object_file->string_table_size;
        u32 number_of_symbols = object_file->number_of_symbols;
        
        for(u32 symbol_index = 0; symbol_index < number_of_symbols; symbol_index++){
            
            struct coff_symbol *symbol = symbol_table + symbol_index;
            
            if((symbol->storage_class != /*IMAGE_SYM_CLASS_EXTERNAL*/2) || (symbol->section_number < /*IMAGE_SYM_ABSOLUTE, IMAGE_SYM_DEBUG*/0)){
                symbol_index += symbol->number_of_auxiliary_symbol_records;
                continue;
            }
            
            // 
            // Grow the 'external_symbols' table if needed.
            // 
            
            if(2 *(external_symbols_size + 1) > external_symbols_capacity){
                
                u64 new_capacity = 2 * external_symbols_capacity;
                struct external_symbol *new_symbols = push_array(&arena, struct external_symbol, new_capacity);
                
                for(u64 old_index = 0; old_index < external_symbols_capacity; old_index++){
                    
                    u64 name_hash = dbj2(external_symbols[old_index].name.data, external_symbols[old_index].name.size);
                    
                    for(u64 new_index = 0; new_index < new_capacity; new_index++){
                        u64 hash_index = (name_hash + new_index) & (new_capacity - 1);
                        
                        if(!new_symbols[hash_index].name.data){
                            new_symbols[hash_index] = external_symbols[old_index];
                            break;
                        }
                    }
                }
                
                external_symbols_capacity = new_capacity;
                external_symbols = new_symbols;
            }
            
            char *name;
            size_t name_length;
            if(symbol->long_name.zeroes == 0){
                if(symbol->long_name.offset >= string_table_size){
                    print("Error: Object file '%s' has corrupt symbol table.\n", object_file->file_name);
                    return 1;
                }
                
                name = (char *)string_table + symbol->long_name.offset;
                name_length = strlen(name);
            }else{
                name = symbol->short_name;
                name_length = strnlen(name, sizeof(symbol->short_name));
            }
            
            u32 is_defined = symbol->section_number != 0;
            u32 size = is_defined ? 0 : symbol->value;
            
            u64 name_hash = dbj2(name, name_length);
            
            for(u64 table_index = 0; table_index < external_symbols_capacity; table_index++){
                u64 hash_index = (name_hash + table_index) & (external_symbols_capacity - 1);
                
                struct external_symbol *external_symbol = &external_symbols[hash_index];
                
                if(external_symbol->name.data == 0){
                    // Insert a new entry.
                    external_symbol->name.data = name;
                    external_symbol->name.size = name_length;
                    external_symbol->size = size;
                    
                    external_symbol->is_defined = is_defined;
                    external_symbol->offset = symbol->value;
                    external_symbol->section_number = symbol->section_number;
                    external_symbol->object_file_index = object_file_index;
                    
                    external_symbols_size += 1;
                    break;
                }
                
                if(external_symbol->name.size == name_length && strncmp(external_symbol->name.data, name, name_length) == 0){
                    // We found the entry in the table.
                    
                    if(external_symbol->is_defined && is_defined){
                        print("Warning: External symbol '%.*s' is defined more than once.\n", name_length, name);
                        break; // Just take the first one! This is a hack to get around `__declspec(selectany)`.
                    }
                    
                    if(size && external_symbol->size && size != external_symbol->size){
                        print("Error: External symbol '%.*s' is specified both with size 0x%x and 0x%x.\n", name_length, name, size, external_symbols->size);
                        return 1;
                    }
                    
                    if(is_defined){
                        external_symbol->is_defined = 1;
                        external_symbol->offset = symbol->value;
                        external_symbol->object_file_index = object_file_index;
                        external_symbol->section_number = symbol->section_number;
                    }
                    
                    if(size) external_symbol->size = size;
                    break;
                }
            }
            
            symbol_index += symbol->number_of_auxiliary_symbol_records;
        }
    }
    
    // 
    // Scan the external symbols and put them into a couple different buckets:
    // 
    //    1. defined symbols (we could find an external symbol with object file, section, offset)
    //    2. undefiend but sized symbols, these go into the .bss section later
    //    3. dll-imports
    //    4. special symbols like __ImageBase
    //    5. Undefined symbols (errors)
    // 
    
    struct dll_list dlls = {0};
    
    int reference_to_undefined_symbol = 0;
    
    u64 bss_size = 0;
    u64 size_of_name_hint_table = 0;
    
    for(u32 table_index = 0; table_index < external_symbols_capacity; table_index++){
        struct external_symbol *symbol = &external_symbols[table_index];
        if(!symbol->name.data) continue;
        
        if(!symbol->is_defined && !symbol->size){
            
            if((symbol->name.size > sizeof("__imp_") - 1) && strncmp(symbol->name.data, "__imp_", sizeof("__imp_") - 1) == 0){
                
                if(symbol->name.size == 8){
                    // Make sure the string is zero-terminated.
                    char *new_data = push_array(&arena, char, 9);
                    memcpy(new_data, symbol->name.data, 8);
                    new_data[8] = 0;
                    symbol->name.data = new_data;
                }
                
                char *cstring_symbol_name = symbol->name.data + sizeof("__imp_") - 1;
                
                u16 hint = 0;
                struct dll_import_node *dll = 0;
                for(u32 ar_index = 0; ar_index < amount_of_ar_files; ar_index++){
                    struct ar_file *ar = &ar_files[ar_index];
                    
                    dll = ar_lookup_symbol(&dlls, &arena, ar, cstring_symbol_name, &hint);
                    if(dll) break;
                }
                
                if(!dll){
                    print("Error: '%.*s' is not contained in any of the import libraries.\n", symbol->name.size, symbol->name.data);
                    reference_to_undefined_symbol = 1;
                    continue;
                }
                
                // This symbol is a dllimport.
                symbol->is_dllimport = 1;
                symbol->dllimport_index = dll->dllimport_index++;
                symbol->dll = dll;
                symbol->hint = hint;
                
                u32 symbol_size = symbol->name.size - (sizeof("__imp_") - 1);
                
                size_of_name_hint_table += 2 + (symbol_size + 1) + ((symbol_size + 1) & 1);
            }else if(string_match(symbol->name, string("__ImageBase"))){
                symbol->is_ImageBase = 1;
            }else{
                print("Error: Symbol '%.*s' was used but never defined.\n", symbol->name.size, symbol->name.data);
                reference_to_undefined_symbol = 1;
            }
        }
        
        if(!symbol->is_defined){
            symbol->offset = bss_size;
            bss_size += symbol->size;
            if(bss_size > 0xffffffff){
                print("Error: The combined size of all uninitialized variables exceeds 32-bit.\n");
                return 1;
            }
        }
    }
    
    if(reference_to_undefined_symbol) return 1;
    
    struct external_symbol *entry_point_symbol = 0;
    {
        // 
        // Make sure we can find the entry point symbol.
        // 
        struct string entry_point_name = (struct string){.data = "_start", .size = 6};
        u64 name_hash = dbj2(entry_point_name.data, entry_point_name.size);
        
        for(u64 table_index = 0; table_index < external_symbols_capacity; table_index++){
            u64 hash_index = (name_hash + table_index) & (external_symbols_capacity - 1);
            
            struct external_symbol *external_symbol = &external_symbols[hash_index];
            
            if(string_match(external_symbol->name, entry_point_name)){
                entry_point_symbol = external_symbol;
                break;
            }
        }
        
        if(!entry_point_symbol){
            print("Could not find entry point \"%.*s\".\n", entry_point_name.size, entry_point_name.data);
            return 1;
        }
    }
    
    struct section_information{
        struct coff_section_header *section_header;
        struct object_file *object_file;
        struct coff_section_header *image_section_header;
    } *sections_to_combine = push_array(&arena, struct section_information, 0);
    
    // 
    // Figure out all the sections which have to end up in the final executable.
    // 
    for(u32 object_file_index = 0; object_file_index < amount_of_object_files; object_file_index++){
        struct object_file *object_file = &object_files[object_file_index];
        
        for(u32 section_index = 0; section_index < object_file->number_of_sections; section_index++){
            
            struct coff_section_header *section_header = &object_file->section_headers[section_index];
            
            if(section_header->characteristics & (/*IMAGE_SCN_LNK_REMOVE*/0x00000800 | /*IMAGE_SCN_MEM_DISCARDABLE*/0x02000000)){
                continue;
            }
            
            struct section_information *section_information = push_struct(&arena, struct section_information);
            section_information->object_file = object_file;
            section_information->section_header = section_header;
        }
    }
    
    u64 amount_of_sections_to_combine = push_array(&arena, struct section_information, 0) - sections_to_combine;
    
    if(!amount_of_sections_to_combine){
        print("Error: Object files do not contain any non-discardable sections.\n");
        return 1;
    }
    
    int compare_sections_to_combine(void *a, void *b){
        
        struct section_information *a_section_information = a;
        struct section_information *b_section_information = b;
        
        // Most importantly sort by name.
        int diff = strncmp((char *)a_section_information->section_header->name, (char *)b_section_information->section_header->name, 8);
        if(diff) return diff;
        
        // If the name is the same, prefer earlier object files.
        diff = a_section_information->object_file - b_section_information->object_file;
        if(diff) return diff;
        
        // Lastly, if they are also in the same object file, compare the section headers.
        return a_section_information->section_header - b_section_information->section_header;
    }
    
    // 
    // Sort the sections by name.
    // 
    qsort(sections_to_combine, amount_of_sections_to_combine, sizeof(*sections_to_combine), compare_sections_to_combine);
    
    // 
    // Build the final executable:
    // 
    //    DOS Stub
    //    PE Header
    //    Optional Header
    //    Section Table
    //    Section Data
    // 
    
#define SECTION_ALIGNMENT 0x1000
#define FILE_ALIGNMENT    0x200
    
    static const u8 DOS_STUB[] = {
        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00,
        0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
        0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xfd, 0xa2, 0x09, 0x47, 0xb9, 0xc3, 0x67, 0x14, 0xb9, 0xc3, 0x67, 0x14, 0xb9, 0xc3, 0x67, 0x14,
        0x9b, 0xa3, 0x66, 0x15, 0xba, 0xc3, 0x67, 0x14, 0xb9, 0xc3, 0x66, 0x14, 0xb6, 0xc3, 0x67, 0x14,
        0x1b, 0xa0, 0x63, 0x15, 0xb8, 0xc3, 0x67, 0x14, 0x1b, 0xa0, 0x65, 0x15, 0xb8, 0xc3, 0x67, 0x14,
        0x52, 0x69, 0x63, 0x68, 0xb9, 0xc3, 0x67, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x44, 0x47,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        
        // Start of the PE Header.
        'P', 'E', 0x00, 0x00,
    };
    
    u8 *image_base = memory_arena_allocate_bytes(&arena, sizeof(DOS_STUB), 0x1000);
    memcpy(image_base, DOS_STUB, sizeof(DOS_STUB));
    
    struct coff_file_header *file_header = push_struct(&arena, struct coff_file_header);
    file_header->machine = 0x8664;
    file_header->timestamp = time(0);
    file_header->size_of_optional_header = sizeof(struct image_optional_header64);
    file_header->file_characteristics = /*EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE*/0x22;
    
    struct image_optional_header64 *optional_header = push_struct(&arena, struct image_optional_header64);
    optional_header->magic = 0x20b;
    optional_header->major_linker_version = 14;
    optional_header->minor_linker_version = 11;
    optional_header->image_base = 0x140000000;
    optional_header->section_alignment = SECTION_ALIGNMENT;
    optional_header->file_alignment    = FILE_ALIGNMENT;
    optional_header->major_operating_system_version = 6;
    optional_header->major_subsystem_version = 6;
    optional_header->subsystem = /*IMAGE_SUBSYSTEM_WINDOWS_CUI*/3;
    optional_header->dll_characteristics = /*DLL_HIGH_ENTROPY_VA*/0x20 | /*DLL_NX*/0x100 | /*DLL_TERMINAL_SERVER_AWARE*/0x8000; // /*DLL_DYNAMIC_BASE*/0x40 | 
    optional_header->size_of_stack_reserve = mega_bytes(1);
    optional_header->size_of_stack_commit  = mega_bytes(1);
    optional_header->size_of_heap_reserve = 0;
    optional_header->size_of_heap_commit  = 0;
    optional_header->number_of_rva_and_sizes = array_count(optional_header->data_directory);
    
    // 
    // Calculate the sections of the executable, by joining adjacent sections of the same name.
    // 
    
    struct coff_section_header *last_image_section = 0;
    struct coff_section_header *image_sections = push_array(&arena, struct coff_section_header, 0);
    
    for(u64 index = 0; index < amount_of_sections_to_combine; index++){
        struct coff_section_header *object_section_header = sections_to_combine[index].section_header;
        
        // Strip every thing past the '$' from the section name.
        char section_name[8] = {0};
        for(u32 section_name_index = 0; section_name_index < 8; section_name_index++){
            char character = object_section_header->name[section_name_index];
            if(character == 0 || character == '$') break;
            section_name[section_name_index] = character;
        }
        
        u32 characteristics = object_section_header->characteristics;
        u32 alignment = 1u << ((characteristics >> (5 * 4)) & 0xf);
        characteristics &= ~0xf00000 & /*comdat*/~0x1000; // We ignore comdat for now.
        
        if(last_image_section && *(u64 *)last_image_section->name == *(u64 *)section_name){
            
            if(last_image_section->characteristics != characteristics){
                print("Error: Section %.8s of %s and section %.8s of %s are supposed to end up in the same image section but have different characteristics.\n", 
                        sections_to_combine[index-1].section_header->name, sections_to_combine[index-1].object_file->file_name, 
                        sections_to_combine[index-0].section_header->name, sections_to_combine[index-0].object_file->file_name);
                return 1;
            }
            
            u64 start = ((u64)last_image_section->size_of_raw_data + alignment - 1) & ~(alignment - 1);
            u64 size  = object_section_header->size_of_raw_data;
            u64 end   = start + size;
            
            // @note: This is really hacky, we use this useless member to map 
            //        the "object_section_header" to the "image_section_header".
            object_section_header->pointer_to_line_numbers = last_image_section - image_sections;
            object_section_header->virtual_address = start;
            
            if(start + size != (u32)end){
                print("Error: Size of %.8s is too big for 32-bit integer.\n", section_name);
                return 1;
            }
            
            last_image_section->size_of_raw_data = end;
        }else{
            last_image_section = push_struct(&arena, struct coff_section_header);
            
            memcpy(last_image_section->name, section_name, sizeof(section_name));
            last_image_section->size_of_raw_data = object_section_header->size_of_raw_data;
            last_image_section->characteristics  = characteristics;
            
            
            // @note: This is really hacky, we use this useless member to map 
            //        the "object_section_header" to the "image_section_header".
            object_section_header->pointer_to_line_numbers = last_image_section - image_sections;
            object_section_header->virtual_address = 0;
        }
        
        sections_to_combine[index].image_section_header = last_image_section;
    }
    
    u64 amount_of_image_sections = push_array(&arena, struct coff_section_header, 0) - image_sections;
    
    // 
    // Allocate a .bss section, if it does not already exist and we need space for the uninitialized externals.
    // 
    
    struct coff_section_header *image_bss_section_header = 0;
    u32 uninitialized_externals_bss_start = 0;
    if(bss_size){
        for(u64 index = 0; index < amount_of_image_sections; index++){
            struct coff_section_header *section_header = &image_sections[index];
            if(strncmp(section_header->name, ".bss", 8) == 0){
                image_bss_section_header = section_header;
                break;
            }
        } 
        
        if(!image_bss_section_header){
            image_bss_section_header = push_struct(&arena, struct coff_section_header);
            memcpy(image_bss_section_header->name, ".bss\0\0\0\0", 8);
            image_bss_section_header->size_of_raw_data = bss_size;
            image_bss_section_header->characteristics  = 0xC0000080;
            
            amount_of_image_sections++;
        }else{
            uninitialized_externals_bss_start = image_bss_section_header->size_of_raw_data;
            image_bss_section_header->size_of_raw_data += bss_size;
        }
    }
    
    // 
    // Allocate a .rdata section, if it does not already exist and we need space for the dllimports.
    // We also need space for the debug directory and the RSDS debug data.
    // 
    
    struct coff_section_header *image_rdata_section_header = 0;
    u32 import_directory_rdata_start = 0;
    u32 debug_directory_rdata_start = 0;
    u32 dllimport_information_size = 0;
    u32 total_amount_of_dll_imports = 0;
    
    {
        for(u64 index = 0; index < amount_of_image_sections; index++){
            struct coff_section_header *section_header = &image_sections[index];
            if(strncmp(section_header->name, ".rdata", 8) == 0){
                image_rdata_section_header = section_header;
                break;
            }
        } 
        
        if(!image_rdata_section_header){
            image_rdata_section_header = push_struct(&arena, struct coff_section_header);
            memcpy(image_rdata_section_header->name, ".rdata\0\0", 8);
            image_rdata_section_header->characteristics  = 0x40000040;
            
            amount_of_image_sections++;
        }else{
            import_directory_rdata_start = image_rdata_section_header->size_of_raw_data;
        }
        
        
        {
            // 
            // Calculate dllimport size.
            // 
            image_rdata_section_header->size_of_raw_data = (image_rdata_section_header->size_of_raw_data + 3) & ~3;
            import_directory_rdata_start = image_rdata_section_header->size_of_raw_data;
            
            for(struct dll_import_node *it = dlls.first; it; it = it->next){
                
                dllimport_information_size += 1 * /*sizeof(import_directory_table_entry)*/20 + 
                2 * (/* import_lookup_table*/8 * (it->dllimport_index + /*zero-terminator*/1))
                + strlen(it->name) + 1;
                
                total_amount_of_dll_imports += it->dllimport_index;
            }
            
            dllimport_information_size += /*sizeof(null import_directory_table_entry)*/20 + size_of_name_hint_table;
            dllimport_information_size += ((dlls.size + 1) & 1) * 4;
            
            image_rdata_section_header->size_of_raw_data += dllimport_information_size;
        }
        
        {
            // 
            // Calculate debug information size.
            // 
            
            image_rdata_section_header->size_of_raw_data = (image_rdata_section_header->size_of_raw_data + 3) & ~3;
            
            debug_directory_rdata_start = image_rdata_section_header->size_of_raw_data;
            
            u64 debug_directory_entry_size = 28;
            u64 rsds_debug_information_size = /*rsds*/4 + /*guid*/16 + /*age*/4 + sizeof("C:/Projects/linker/brogueCE/a.pdb");
            
            image_rdata_section_header->size_of_raw_data += debug_directory_entry_size + rsds_debug_information_size;
        }
    }
    
    if(amount_of_image_sections > 0xffff){
        print("Error: Image contains too many sections.\n");
        return 1;
    }
    
    file_header->number_of_sections = (u16)amount_of_image_sections;
    
    u64 image_virtual_size  = 0;
    u64 image_physical_size = 0;
    
    {
        u64 header_size = (u8 *)memory_arena_allocate_bytes(&arena, 0, FILE_ALIGNMENT) - image_base;
        u64 section_rva = (header_size + (SECTION_ALIGNMENT - 1)) & ~(SECTION_ALIGNMENT - 1);
        u64 section_pointer_to_data = (header_size + (FILE_ALIGNMENT - 1)) & ~(FILE_ALIGNMENT - 1);
        
        assert(header_size < 0xffffffff); // Always true because we bounded the 'amount_of_sections'.
        optional_header->size_of_headers = (u32)header_size;
        
        // 
        // Allocate virtual addresses.
        // 
        for(u64 index = 0; index < amount_of_image_sections; index++){
            struct coff_section_header *image_section_header = &image_sections[index];
            image_section_header->virtual_address = section_rva;
            image_section_header->virtual_size = image_section_header->size_of_raw_data;
            
            u64 aligned_size = (image_section_header->size_of_raw_data + (FILE_ALIGNMENT-1)) & ~(FILE_ALIGNMENT-1);
            image_section_header->size_of_raw_data    = aligned_size;
            image_section_header->pointer_to_raw_data = section_pointer_to_data;
            
            section_pointer_to_data += aligned_size;
            section_rva += (image_section_header->virtual_size + (SECTION_ALIGNMENT-1)) & ~(SECTION_ALIGNMENT-1);
        }
        
        image_virtual_size  = section_rva;
        image_physical_size = section_pointer_to_data;
        
        push_array(&arena, u8, image_physical_size - header_size);
    } 
    
    u32 size_of_initialized_data   = 0;
    u32 size_of_uninitialized_data = 0;
    
    for(u64 index = 0; index < amount_of_image_sections; index++){
        struct coff_section_header *image_section_header = &image_sections[index];
        if(strncmp(image_section_header->name, ".text", 8) == 0){
            optional_header->size_of_code = image_section_header->size_of_raw_data;
            optional_header->base_of_code = image_section_header->virtual_address;
            
            memset(image_base + image_section_header->pointer_to_raw_data, 0xcc, image_section_header->size_of_raw_data);
        }
        
        if(image_section_header->characteristics & /*IMAGE_SCN_CNT_INITIALIZED_DATA*/0x40){
            size_of_initialized_data += image_section_header->size_of_raw_data;
        }
        
        if(image_section_header->characteristics & /*IMAGE_SCN_CNT_UNINITIALIZED_DATA*/0x80){
            size_of_uninitialized_data += image_section_header->size_of_raw_data;
        }
    }
    
    {
        // 
        // Write in the dllimport information.
        // 
        u32 dllimport_information_relative_virtual_address = image_rdata_section_header->virtual_address + import_directory_rdata_start;
        u8 *dllimport_information_base = image_base + image_rdata_section_header->pointer_to_raw_data + import_directory_rdata_start;
        
        // Layout:
        //    import directory tables     (0)
        //    null import directory table (20 * dlls.size)
        //    import lookup table         (20 * dlls.size + 20)
        //    import address table        (20 * dlls.size + 20 +  8 * (total_amount_of_dll_imports + dlls.size))
        //    name hint table             (20 * dlls.size + 20 + 16 * (total_amount_of_dll_imports + dlls.size))
        //    name rva ("kernel32.dll")   (20 * dlls.size + 20 + 16 * (total_amount_of_dll_imports + dlls.size) + size_of_name_hint_table)
        //    
        
        struct import_directory_table_entry{
            u32 import_lookup_table_rva;
            u32 time_date_stamp;
            u32 forwarder_chain;
            u32 name_rva;
            u32 import_address_table_rva;
        } *import_table_base = (void *)dllimport_information_base;
        
        u32 import_table_end = 20 * dlls.size + 20 + ((dlls.size + 1) & 1) * 4;
        
        u32 import_lookup_table_base_at  = import_table_end;
        u32 import_address_table_base_at = import_table_end + (total_amount_of_dll_imports + dlls.size) * 8;
        u32 import_name_rva_at = import_table_end + 16 * (total_amount_of_dll_imports + dlls.size) + size_of_name_hint_table;
        
        {
            struct dll_import_node *dll = dlls.first;
            for(u32 dll_index = 0; dll_index < dlls.size; dll_index++, dll = dll->next){
                import_table_base[dll_index].import_lookup_table_rva  = dllimport_information_relative_virtual_address + import_lookup_table_base_at;
                import_table_base[dll_index].import_address_table_rva = dllimport_information_relative_virtual_address + import_address_table_base_at;
                import_table_base[dll_index].name_rva                 = dllimport_information_relative_virtual_address + import_name_rva_at;
                
                u64 name_length = strlen(dll->name);
                u64 *import_lookup_table  = (void *)(dllimport_information_base + import_lookup_table_base_at);
                u64 *import_address_table = (void *)(dllimport_information_base + import_address_table_base_at);
                
                dll->import_address_table_relative_virtual_address = dllimport_information_relative_virtual_address + import_address_table_base_at;
                dll->import_address_table = import_address_table;
                dll->import_lookup_table  = import_lookup_table;
                
                u8 *dll_name = dllimport_information_base + import_name_rva_at;
                memcpy(dll_name, dll->name, name_length);
                
                import_lookup_table_base_at  += 8 * (dll->dllimport_index + 1);
                import_address_table_base_at += 8 * (dll->dllimport_index + 1);
                import_name_rva_at += name_length + 1;
            } 
        }
        
        u8 *name_hint_table_base = dllimport_information_base                     + 20 * dlls.size + 20 + 16 * (total_amount_of_dll_imports + dlls.size);
        u32 name_hint_table_rva  = dllimport_information_relative_virtual_address + 20 * dlls.size + 20 + 16 * (total_amount_of_dll_imports + dlls.size);
        u32 name_hint_table_entry_offset_at = 0;
        
        for(u32 table_index = 0; table_index < external_symbols_capacity; table_index++){
            struct external_symbol *symbol = &external_symbols[table_index];
            if(!symbol->is_dllimport) continue;
            
            u32 name_hint_table_entry_rva = name_hint_table_rva + name_hint_table_entry_offset_at;
            symbol->dll->import_lookup_table[symbol->dllimport_index] = name_hint_table_entry_rva;
            symbol->dll->import_address_table[symbol->dllimport_index] = name_hint_table_entry_rva;
            
            u16 *hint = (u16 *)(name_hint_table_base + name_hint_table_entry_offset_at + 0);
            u8  *name =        (name_hint_table_base + name_hint_table_entry_offset_at + 2);
            
            struct string non_import_name = {
                .data = symbol->name.data + (sizeof("__imp_") - 1),
                .size = symbol->name.size - (sizeof("__imp_") - 1),
            };
            
            *hint = symbol->hint;
            memcpy(name, non_import_name.data, non_import_name.size);
            
            name_hint_table_entry_offset_at += 2 + (non_import_name.size + 1) + ((non_import_name.size + 1) & 1);
        }
        
        optional_header->data_directory[1].virtual_address = dllimport_information_relative_virtual_address;
        optional_header->data_directory[1].size            = dllimport_information_size;
    }
    
    {
        // 
        // Write in the debug data.
        // 
        u32 debug_data_relative_virtual_address = image_rdata_section_header->virtual_address + debug_directory_rdata_start;
        u8 *debug_data_base = image_base + image_rdata_section_header->pointer_to_raw_data + debug_directory_rdata_start;
        
        u64 rsds_debug_information_size = /*rsds*/4 + /*guid*/16 + /*age*/4 + sizeof("C:/Projects/linker/brogueCE/a.pdb");
        
        struct{
            u32 characteristics;
            u32 time_date_stamp;
            u16 major_version;
            u16 minor_version;
            u32 type;
            u32 size_of_data;
            u32 data_rva;
            u32 pointer_to_raw_data;
        } *debug_directory_entry = (void *)debug_data_base;
        
        u32 rsds_pointer_to_raw_data = image_rdata_section_header->pointer_to_raw_data + debug_directory_rdata_start + sizeof(*debug_directory_entry);
        
        debug_directory_entry->characteristics = 0;
        debug_directory_entry->time_date_stamp = time(NULL);
        debug_directory_entry->major_version = 0;
        debug_directory_entry->minor_version = 0;
        debug_directory_entry->type = /*IMAGE_DEBUG_TYPE_CODEVIEW*/2;
        debug_directory_entry->size_of_data = rsds_debug_information_size;
        debug_directory_entry->data_rva = debug_data_relative_virtual_address + sizeof(*debug_directory_entry);
        debug_directory_entry->pointer_to_raw_data = rsds_pointer_to_raw_data;
        
        optional_header->data_directory[6].virtual_address = debug_data_relative_virtual_address;
        optional_header->data_directory[6].size            = sizeof(*debug_directory_entry);
        
        struct _RSDS_DEBUG_DIRECTORY{
            char RSDS[4]; // "RSDS"
            struct guid{
                u32 data1;
                u16 data2;
                u16 data3;
                u8 data4[8];
            } pdb_guid;
            u32  pdb_age;
            char pdb_path[];
        } *rsds_debug_directory = (void *)(image_base + rsds_pointer_to_raw_data);
        memcpy(rsds_debug_directory->RSDS, "RSDS", 4);
        rsds_debug_directory->pdb_guid = (struct guid){0x13371337, 0x1337, 0x1337, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37};
        rsds_debug_directory->pdb_age = 1;
        memcpy(rsds_debug_directory->pdb_path, "C:/Projects/linker/brogueCE/a.pdb", sizeof("C:/Projects/linker/brogueCE/a.pdb"));
    }
    
    
    for(u64 section_index = 0; section_index < amount_of_sections_to_combine; section_index++){
        struct object_file *object_file = sections_to_combine[section_index].object_file;
        struct coff_section_header *relocation_section = sections_to_combine[section_index].section_header;
        
        // If this is a .bss-like section don't try to copy the data.
        if(/*UNINITIALIZED_DATA*/0x00000080 & relocation_section->characteristics) continue;
        
        // Copy in the section data.
        void *section_data = stream_read_range_by_pointer(&object_file->stream, relocation_section->pointer_to_raw_data, 1, relocation_section->size_of_raw_data);
        
        u8 *dest = 0;
        {
            u32 image_section_index = relocation_section->pointer_to_line_numbers; // @note: We store this index in this useless field.
            u32 offset_of_object_section_in_image_section = relocation_section->virtual_address;
            struct coff_section_header *image_section_header = &image_sections[image_section_index];
            
            dest = image_base + image_section_header->pointer_to_raw_data + offset_of_object_section_in_image_section;
        }
        memcpy(dest, section_data, relocation_section->size_of_raw_data);
        
        // Apply relocations.
        struct coff_relocation *relocations = stream_read_range_by_pointer(&object_file->stream, relocation_section->pointer_to_relocations, sizeof(struct coff_relocation), relocation_section->number_of_relocations);
        
        // @cleanup: Do the relocation overflow thing.
        
        struct coff_symbol *symbol_table = object_file->symbol_table;
        
        for(u32 relocation_index = 0; relocation_index < relocation_section->number_of_relocations; relocation_index++){
            struct coff_relocation *relocation = &relocations[relocation_index];
            
            u32 relocation_address = relocation->relocation_address;
            u32 symbol_table_index = relocation->symbol_table_index;
            u16 relocation_type    = relocation->relocation_type;
            
            if(relocation_type == /*IMAGE_REL_AMD64_ABSOLUTE*/0) continue;
            
            if(symbol_table_index > object_file->number_of_symbols){
                print("Error: Object %s contains corrupt relocation.\n", object_file->file_name);
                return 1;
            }
            
            struct coff_symbol *symbol = &symbol_table[symbol_table_index];
            
            struct string symbol_string = get_symbol_name(symbol, object_file);
            
            u32 symbol_relative_virtual_address = 0;
            
            if(symbol->storage_class == /*IMAGE_SYM_CLASS_EXTERNAL*/2){
                u64 name_hash = dbj2(symbol_string.data, symbol_string.size);
                
                struct external_symbol *found = 0;
                
                for(u64 table_index = 0; table_index < external_symbols_capacity; table_index++){
                    u64 hash_index = (name_hash + table_index) & (external_symbols_capacity - 1);
                    
                    struct external_symbol *external_symbol = &external_symbols[hash_index];
                    
                    if(external_symbol->name.size == symbol_string.size && strncmp(external_symbol->name.data, symbol_string.data, symbol_string.size) == 0){
                        found = external_symbol;
                        break;
                    }
                }
                
                if(found->is_defined){
                    struct object_file *external_symbol_object_file = &object_files[found->object_file_index];
                    struct coff_section_header *source_object_section = &external_symbol_object_file->section_headers[found->section_number-1]; // @note: One-based.
                    
                    u32 offset_of_object_section_in_image_section = source_object_section->virtual_address;
                    u32 image_section_index = source_object_section->pointer_to_line_numbers; // @note: We store this index in this useless field.
                    
                    struct coff_section_header *image_section_header = &image_sections[image_section_index];
                    
                    symbol_relative_virtual_address = image_section_header->virtual_address + offset_of_object_section_in_image_section + found->offset;
                    
                }else if(found->is_dllimport){
                    
                    // 
                    // Calculate the relative virtual address of the import address table entry.
                    // 
                    
                    symbol_relative_virtual_address = found->dll->import_address_table_relative_virtual_address + 8 * found->dllimport_index;
                }else if(found->is_ImageBase){
                    symbol_relative_virtual_address = 0;
                }else{
                    symbol_relative_virtual_address = image_bss_section_header->virtual_address + uninitialized_externals_bss_start + found->offset;
                }
            }else if(symbol->storage_class == /*IMAGE_SYM_CLASS_STATIC*/3 || symbol->storage_class == /*IMAGE_SYM_CLASS_LABEL*/6){
                
                struct coff_section_header *source_object_section = &object_file->section_headers[symbol->section_number-1]; // @note: One-based.
                
                u32 image_section_index = source_object_section->pointer_to_line_numbers; // @note: We store this index in this useless field.
                u32 offset_of_source_object_section_in_image_section = source_object_section->virtual_address;
                
                struct coff_section_header *image_section_header = &image_sections[image_section_index];
                
                symbol_relative_virtual_address = image_section_header->virtual_address + offset_of_source_object_section_in_image_section + symbol->value;
            }else{
                print("TODO: non-external symbol {.*s} storage_class %d\n", symbol_string.size, symbol_string.data, (int)symbol->storage_class);
            }
            
            if(relocation_type == /*IMAGE_REL_AMD64_ADDR64*/1){
                
                if((u64)relocation_address + sizeof(u64) > relocation_section->size_of_raw_data){
                    print("Error: Object %s contains corrupt relocation.\n", object_file->file_name);
                    return 1;
                }
                
                *(u64 *)(dest + relocation_address) = optional_header->image_base + symbol_relative_virtual_address;
            }else if(relocation_type == /*IMAGE_REL_AMD64_REL32NB*/3){
                
                if((u64)relocation_address + sizeof(u32) > relocation_section->size_of_raw_data){
                    print("Error: Object %s contains corrupt relocation.\n", object_file->file_name);
                    return 1;
                }
                
                *(u32 *)(dest + relocation_address) += symbol_relative_virtual_address;
            }else if(/*IMAGE_REL_AMD64_REL32*/4 <= relocation_type && relocation_type <= /*IMAGE_REL_AMD64_REL32_5*/9){
                
                u32 rip_offset = relocation_type - 4;
                
                if((u64)relocation_address + sizeof(u32) > relocation_section->size_of_raw_data){
                    print("Error: Object %s contains corrupt relocation.\n", object_file->file_name);
                    return 1;
                }
                
                
                // 
                // rip-relative relocation for jumps.
                // 
                
                u32 image_section_index = relocation_section->pointer_to_line_numbers; // @note: We store this index in this useless field.
                u32 offset_of_object_section_in_image_section = relocation_section->virtual_address;
                
                struct coff_section_header *image_section_header = &image_sections[image_section_index];
                
                u32 relocation_virtual_address = image_section_header->virtual_address + offset_of_object_section_in_image_section + /*offset in section*/relocation_address;
                
                // @cleanup: is + correct?
                *(u32 *)(dest + relocation_address) += symbol_relative_virtual_address - (relocation_virtual_address + 4 + rip_offset);
            }else{
                print("Error: Object %s uses unhandled relocation type %hu.\n", object_file->file_name, relocation_type);
                return 1;
            }
        }
    }
    
    u64 check_image_size = (u8 *)memory_arena_allocate_bytes(&arena, 0, FILE_ALIGNMENT) - image_base;
    assert(check_image_size == image_physical_size);
    
    optional_header->size_of_image = (u32)image_virtual_size;
    
    {
        struct object_file *external_symbol_object_file = &object_files[entry_point_symbol->object_file_index];
        struct coff_section_header *source_object_section = &external_symbol_object_file->section_headers[entry_point_symbol->section_number-1]; // @note: One-based.
        
        u32 offset_of_object_section_in_image_section = source_object_section->virtual_address;
        u32 image_section_index = source_object_section->pointer_to_line_numbers; // @note: We store this index in this useless field.
        
        struct coff_section_header *image_section_header = &image_sections[image_section_index];
        
        optional_header->address_of_entry_point = image_section_header->virtual_address + offset_of_object_section_in_image_section + entry_point_symbol->offset;
    }
    
    optional_header->size_of_initialized_data   = size_of_initialized_data;
    optional_header->size_of_uninitialized_data = size_of_uninitialized_data;
    
    FILE *out = fopen("a.exe", "wb");
    fwrite(image_base, image_physical_size, 1, out);
    
    struct stream *type_information_per_object = push_array(&arena, struct stream, amount_of_object_files);
    
    for(u32 object_file_index = 0; object_file_index < amount_of_object_files; object_file_index++){
        struct object_file *object_file = &object_files[object_file_index];
        
        for(u32 section_index = 0; section_index < object_file->number_of_sections; section_index++){
            struct coff_section_header *section_header = &object_file->section_headers[section_index];
            
            if(strncmp(section_header->name, ".debug$T", 8) == 0){
                u32 size_of_raw_data    = section_header->size_of_raw_data;
                u32 pointer_to_raw_data = section_header->pointer_to_raw_data;
                u8 *debug_data = stream_read_range_by_pointer(&object_file->stream, pointer_to_raw_data, 1, size_of_raw_data);
                assert(debug_data);
                
                type_information_per_object[object_file_index] = (struct stream){.data = debug_data, .size = size_of_raw_data};
            }
        }
    }
        
    struct write_pdb_information write_pdb_information = {0};
    write_pdb_information.amount_of_object_files = amount_of_object_files;
    write_pdb_information.type_information_per_object = type_information_per_object;
    
    write_pdb(&write_pdb_information);
    
    return 0;
}

