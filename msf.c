#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <assert.h>

typedef unsigned __int8  u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;

typedef __int8  s8;
typedef __int16 s16;
typedef __int32 s32;
typedef __int64 s64;

struct msf_stream{
    u8 *data;
    u32 size;
    u32 offset;
};

// 
// Write an MSF from a set of streams.
// The general layout will be as follows:
//     
//     MSF file-header page
//     Free Page Map (Used)
//     Free Page Map (Unused)
//     
//     <Stream Table Stream Page list>
//     <Stream Table Stream>
//     <streams[0]>
//     ...
//     <streams[amount_of_streams]>
// 
// Here, 'stream[index]' has stream index 'index + 1', to make space for the 
// "Old stream table"-stream. Furthermore, everything past the first 3 pages 
// is potentially "interrupted", by the later pages of the Free Page Maps.
// 
void write_msf(char *file_name, struct msf_stream *streams, u32 amount_of_streams){
    
    // 
    // Figure out the size the on-disk size of the specified streams.
    u64 aligned_total_size = 0;
    for(u32 index = 0; index < amount_of_streams; index++){
        aligned_total_size += (streams[index].size + 0xfff) & ~0xfff;
    }
    
    //
    // The stream table stream contains information about where all the other streams are located.
    // It has the following layout:
    //     u32 amount_of_streams;
    //     u32 stream_sizes[amount_of_streams];
    //     u32 stream_one_pages[];
    //     u32 stream_two_pages[];
    //     ...
    //
    u64 stream_table_stream_size = 4 + (4 * (u64)(amount_of_streams + /*old stream table stream*/1)) + 4 * (aligned_total_size/0x1000);
    u32 stream_table_stream_size_in_pages = (u32)((stream_table_stream_size + 0xfff)/0x1000);
    
    // The MSF-header refers to the page-list for the stream table stream.
    u64 stream_table_page_list_size = 4 * stream_table_stream_size_in_pages;
    
    aligned_total_size += (stream_table_stream_size    + 0xfff) & ~0xfff;
    aligned_total_size += (stream_table_page_list_size + 0xfff) & ~0xfff;
    
    // Every page with page index equal to 1 or 2 modulo 0x1000, is reserved for the Free Page Map.
    // Equivilantly, not counting the header every page with page index equal to 0 or 1 modulo 0x1000,
    // is reserved for the Free Page Map. Quick toy example shows the formular 
    //     '2 * ceil(pages/(0x1000 - 2))'
    // for the amount of Free Page Map pages:
    // 
    //     20 Pages every page equal to 0 or 1 mod 5 is a FPM:
    // 
    //         x, x,  1,  2,  3  ( 5)
    //         x, x,  4,  5,  6  (10)
    //         x, x,  7,  8,  9  (15)
    //         x, x, 10, 11, 12  (20)
    //         x, x, 13, 14, 15  (25)
    //         x, x, 16, 17, 18, (30)
    //         x, x, 19, 20,     (34)
    //    
    //     18/3 = 6   (30 = 18 + 12)
    //     19/3 = 6.3 (33 = 19 + 14)
    //     20/3 = 6.6 (34 = 20 + 14)
    //     21/3 = 7   (35 = 21 + 14)
    //     
    u64 amount_of_pages = aligned_total_size/0x1000;
    amount_of_pages += 2 * ((amount_of_pages + ((0x1000 - 2) - 1))/(0x1000 - 2));
    
    // Add in the header page.
    amount_of_pages += 1;
    
    aligned_total_size = amount_of_pages * 0x1000;
    
    // 
    // Create "extra streams" for the stream table stream and the stream table stream page list.
    // 
    u32 *stream_table_stream    = malloc(stream_table_stream_size);
    u32 *stream_table_page_list = malloc(stream_table_page_list_size);
    
    u32 stream_table_page_list_size_in_pages = (u32)((stream_table_page_list_size + 0xfff)/0x1000);
    
    // Fill in the stream table stream page number list.
    u32 stream_table_page_list_end   = 3 + stream_table_page_list_size_in_pages;
    u32 stream_table_stream_page_end = 3 + (stream_table_page_list_size_in_pages + stream_table_stream_size_in_pages);
    
    // Add the pages potentially required for free page maps.
    // @note: This formular is what you get in the above, if you put the x's last.
    //        The ceil turns into a floor.
    stream_table_page_list_end   += 2 * (stream_table_page_list_size_in_pages/(0x1000 - 2));
    stream_table_stream_page_end += 2 * ((stream_table_page_list_size_in_pages + stream_table_stream_size_in_pages)/(0x1000 - 2));
    
    {
        u32 index = 0;
        for(u32 page_index = stream_table_page_list_end; page_index < stream_table_stream_page_end; page_index++){
            if((page_index & 0xfff) == 1 || (page_index & 0xfff) == 2) continue;
            stream_table_page_list[index++] = page_index;
        }
        assert(index == stream_table_page_list_size/4);
    }
    
    {   // Fill in the stream table stream.
        // This is a bit annoying, as we have not yet written the pages
        // and have to recreate the algorithm here, which we are going to
        // use below when writing the file.
        // 
        // Here is the layout again:
        //     u32 amount_of_streams;
        //     u32 stream_sizes[amount_of_streams];
        //     u32 stream_one_pages[];
        //     u32 stream_two_pages[];
        //     ...
        u32 *it = stream_table_stream;
        *it++ = amount_of_streams + /*old stream table stream*/1;
        *it++ = /*size of old stream table stream*/0;
        for(u32 stream_index = 0; stream_index < amount_of_streams; stream_index++){
            *it++ = streams[stream_index].size;
        }
        
        for(u32 page_index = stream_table_stream_page_end; page_index < amount_of_pages; page_index++){
            if((page_index & 0xfff) == 1 || (page_index & 0xfff) == 2) continue;
            *it++ = page_index;
        }
        assert(it == (u32 *)((u8 *)stream_table_stream + stream_table_stream_size));
    }
    
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
    } *msf_header = (void *)(u8 [0x1000]){0};
    memcpy(msf_header->signature, "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0\0", sizeof(msf_header->signature));
    msf_header->page_size = 0x1000;
    msf_header->active_free_page_map_number = 1;
    msf_header->amount_of_pages = amount_of_pages;
    msf_header->stream_table_stream_size = stream_table_stream_size;
    
    u64 max_size = (0x1000 - (u64)&((struct msf_header *)0)->page_list_of_stream_table_stream_page_list)/4;
    if(stream_table_page_list_size_in_pages > max_size){
        printf("ars\n");
        return;
    }
    
    for(u32 index = 0; index < stream_table_page_list_size_in_pages; index++){
        msf_header->page_list_of_stream_table_stream_page_list[index] = 3 + index;
    }
    
    u8 zero_buffer[0x1000] = {0}; // Used to align writes.
    u8 ones_buffer[0x1000]; // Used to write free page maps.
    memset(ones_buffer, 0xff, 0x1000);
    
    FILE *file_handle = fopen(file_name, "wb");
    
    fwrite(msf_header, 0x1000, 1, file_handle);
    
    u64 write_offset = 0x1000;
    u64 next_free_page_maps = 0x1000;
    
    for(s64 stream_index = -2; stream_index < amount_of_streams; stream_index++){
        
        struct msf_stream stream = {0};
        if(stream_index == -2){
            stream.data = (u8 *)stream_table_page_list;
            stream.size = stream_table_page_list_size;
        }else if(stream_index == -1){
            stream.data = (u8 *)stream_table_stream;
            stream.size = stream_table_stream_size;
        }else{
            stream = streams[stream_index];
        }
        
        u32 offset_in_stream = 0;
        while(offset_in_stream < stream.size){
            
            if(write_offset == next_free_page_maps){
                u64 free_page_map_page = (next_free_page_maps / 0x1000)/0x1000;
                u64 range_start = (free_page_map_page + 0) * 0x8000;
                u64 range_end   = (free_page_map_page + 1) * 0x8000;
                
                if(range_end <= amount_of_pages){
                    // If the range covered by this free page map is entirely in the file,
                    // write all zeros (all allocated).
                    fwrite(zero_buffer, 0x1000, 1, file_handle);
                }else if(amount_of_pages < range_start){
                    // If the range covered by this free page map is entirely outside the file,
                    // write all ones (all free).
                    fwrite(ones_buffer, 0x1000, 1, file_handle);
                }else{
                    u8 buffer[0x1000] = {0};
                    
                    for(u64 page_index = amount_of_pages; page_index < range_end; page_index++){
                        
                        u64 relative_page_index = page_index - range_start;
                        
                        u64 byte_index = relative_page_index/8;
                        u64 bit_index  = relative_page_index%8;
                        
                        buffer[byte_index] |= (u8)(1 << bit_index);
                    }
                    fwrite(buffer, 0x1000, 1, file_handle);
                }
                
                fwrite(zero_buffer, 0x1000, 1, file_handle); // Ignored free page map.
                
                write_offset += 0x2000;
                next_free_page_maps += 0x1000 * 0x1000;
            }
            
            // Write till the next free page map or till the end of the stream.
            u32 size_to_write = stream.size - offset_in_stream;
            if(size_to_write > (next_free_page_maps - write_offset)){
                size_to_write = next_free_page_maps - write_offset;
            }
            fwrite(stream.data + offset_in_stream, 1, size_to_write, file_handle);
            
            if(size_to_write & 0xfff){
                u32 size_to_zero = 0x1000 - (size_to_write & 0xfff);
                fwrite(zero_buffer, size_to_zero, 1, file_handle); // Ignored free page map.
                size_to_write += size_to_zero;
            }
            
            write_offset     += size_to_write;
            offset_in_stream += size_to_write;
        }
    }
    
    fclose(file_handle);
}

//_____________________________________________________________________________________________________________________
// 


__declspec(noreturn) void error(char *format, ...){
    va_list va;
    va_start(va, format);
    vprintf(format, va);
    va_end(va);
    
    printf("\n");
    
    fflush(0);
    
    _exit(1);
}

struct msf_streams{
    u32 amount_of_streams;
    struct msf_stream *streams;
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
            error("MSF Error: Free page map page at %d is marked as free in the free page map.", page_number);
        }
        if(test_and_set_page(page_number + 1)){
            error("MSF Error: Free page map page at %d is marked as free in the free page map.", page_number + 1);
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
    // Resolve the first layer of indirection, building the stream table stream.
    // 
    
    // printf("stream_table_stream: ");
    
    u8 *stream_table_stream = malloc(stream_table_stream_page_size * page_size);
    for(u32 index = 0; index < stream_table_stream_page_size; index++){
        u32 page_number = ((u32 *)stream_table_stream_page_number_list)[index];
        
        // printf("%x, ", page_number);
        
        if((page_number == 0) || (page_number >= amount_of_pages) || (page_number & (page_size - 1)) == 1 || (page_number & (page_size - 1)) == 2){
            error("MSF Error: Page number %u (%u) inside the stream table stream page number list is invalid.", index, page_number);
        }
        
        if(test_and_set_page(page_number)){
            error("MSF Error: Page number %u (%u) inside the stream table stream page number list is marked as free.", index, page_number);
        }
        
        memcpy(stream_table_stream + page_size * index, msf_base + page_number * page_size, page_size); 
    }
    // printf("\n");
    
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
        
        if(stream_index == 0){
            // 
            // @cleanup: what to detect here, It seems these pages are already marked as free.
            //           Or they alias to other pages (in the case where it did not need to change ?).
            //           Maybe we just ignore this stream entirely.
            // 
            stream_page_base += stream_page_size;
            continue;
        }
        
        if(stream_size == 0) continue;
        
        printf("stream %d: ", stream_index);
        
        for(u32 stream_page_index = 0; stream_page_index < stream_page_size; stream_page_index++){
            u32 page_number = stream_pages[stream_page_base + stream_page_index];
            
            printf("%x, ", page_number);
            
            if((page_number == 0) || (page_number >= amount_of_pages) || (page_number & (page_size - 1)) == 1 || (page_number & (page_size - 1)) == 2){
                error("MSF Error: Page number %u (%u) inside the page list of stream %u is invalid.", stream_page_index, page_number, stream_index);
            }
            
            if(test_and_set_page(page_number)){
                error("MSF Error: Page number %u (%u) inside the page list of stream %u is marked as free.", stream_page_index, page_number, stream_index);
            }
            
            memcpy(stream_data + stream_page_index * page_size, msf_base + page_number * page_size, page_size);
        }
        printf("\n");
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

