
# Introduction

The Program Database Format is the debugging symbol (container) format used by debuggers on Windows.
It contains type, symbol, file and line information for an executable file.
Though this makes the format arguably very important, it remains largely undocumented.
The best sources of documentation are

   * The cryptic [source code](https://github.com/microsoft/microsoft-pdb) for `mspdbcore.dll`, which was published by Microsoft, 
     which they claimed they would keep up to date, then never updated and is now archived.
   * The LLVM-implementation and [wiki articles](https://llvm.org/docs/PDB/), which while they are really good, they are incomplete
     and contains some minor mistakes.
   * Random implementations like [pdb_raw](https://github.com/MolecularMatters/raw_pdb), 
     [dump_syms](https://github.com/mozilla/dump_syms/tree/main/src/windows),
     [willglynn/pdb](https://github.com/willglynn/pdb) or the [raddebugger](https://github.com/EpicGamesExt/raddebugger/).
     
Microsoft also published the [DIA SDK](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/debug-interface-access-sdk?view=vs-2022)
or Debug Interface Access SDK, which is for example used by [x64dbg](https://github.com/x64dbg/x64dbg).
Furthermore, the sample program for the DIA SDK is a dumping utility called `Dia2Dump` and the `microsoft-pdb` 
repository also contains a dumping utility called `cvdump`.

Armed with these sources, the plan for this repository is to provide technical documentation, a validation utility (`validate.c`) and
a toy-linker (`linker.c`) with PDB support (`pdb_writer.c`) to hopefully provide a complete picture of the PDB format.
The validation utility tries to check much about the PDB format and has a `-dump` option. The toy linker tries to be compatible with:
```
link.exe /NODEFAULTLIB /ENTRY:_start /SUBSYSTEM:console /DYNAMICBASE:no /DEBUG:FULL <.obj-files> <.lib-files>
```
for simple object files.

Note that all information in this repository is from XX.XX.XXXX and is might change when Microsoft updates their tools.
For reference, the MSVC version I am using is 19.28.29336.

Any sample code inside the `Readme.md` is only intended to clarify the layout and algorithms used.
No security checks are performed and the code might not even have been tested.
For "tested" (but overly strict) parsing code see `validate.c` and for tested writer code see `write_pdb.c`.


# Content

# Finding the PDB

PDBs are used by debuggers for type, symbol, file and line information. 
They are produced or incrementally updated by the linker.

When a debugger wants to load the debugging symbols for an executable, it looks at the [debug directories](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only) 
contained in the data directory of the optional header. This entry points to the [.debug](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-debug-section) 
section of the executable (usually not its own section but contained in the `.rdata` section).

```
> C:\Projects\pdb>dumpbin /HEADERS test.exe
  <...>

  Debug Directories

        Time Type        Size      RVA  Pointer
    -------- ------- -------- -------- --------
    63B5B505 cv            31 00066EF4    648F4    Format: RSDS, {E3A31305-D0BA-41A3-9847-DB3EEAF39ECA}, 3, C:\Projects\pdb\test.pdb
    63B5B505 feat          14 00066F28    64928    Counts: Pre-VC++ 11.00=0, C/C++=203, /GS=203, /sdl=0, guardN=202
    63B5B505 coffgrp      320 00066F3C    6493C
    
  <...>
```

This sections can contain various forms of debugging information, but the one we are interested in is `IMAGE_DEBUG_TYPE_CODEVIEW` or `cv` in the table.
It contains a `RSDS` structure, which to my knowledge in only documented in [locator.h](https://github.com/microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/dbi/locator.h#L33)
of the microsoft-pdb repository.
The structure looks as follows:

```c
struct RSDSI                       // RSDS debug info
{
    DWORD   dwSig;                 // RSDS
    GUID    guidSig;
    DWORD   age;
    char    szPdb[_MAX_PATH * 3];
};
```

The [GUID](https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid) is a unique _number_ which 
is used to match the PDB to the EXE and the `age` is used for incremental linking. Here, on a incremental relink, 
the GUID stays the same, but the age is incremented.
Finally, the `szPdb` is the zero-terminated path to the PDB. Per default, MSVC uses the full path of the PDB for `szPdb`, but a alternate PDB path can be specified using the liker option [`/PDBALTPATH`](https://learn.microsoft.com/en-us/cpp/build/reference/pdbaltpath-use-alternate-pdb-path?view=msvc-170). 
All this information is also displayed by `dumpbin`.

For most Microsoft executables the `szPdb` stored, is simply the name of the PDB, for example:
```
C:\Windows\System32>dumpbin notepad.exe
  <...>

  Debug Directories

        Time Type        Size      RVA  Pointer
    -------- ------- -------- -------- --------
    BDD4ADCD cv            24 0002B4E4    2A0E4    Format: RSDS, {67D551E7-B9BB-3B68-E823-F5B998BD9453}, 1, notepad.pdb
    BDD4ADCD coffgrp      43C 0002B508    2A108    4C544347 (LTCG)
    BDD4ADCD repro         24 0002B944    2A544    E7 51 D5 67 BB B9 68 3B E8 23 F5 B9 98 BD 94 53 44 48 7F BC E6 DD A7 40 F1 EA 86 46 CD AD D4 BD

  <...>
```
The debugger can then download the PDB from the [Microsoft public symbol server](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols).
This simply means downloading the PDB from `https://msdl.microsoft.com/download/symbols/<pdb-name>/<guid><age>/<pdb-name>`.
In the case of `notepad.pdb` this would be `https://msdl.microsoft.com/download/symbols/notepad.pdb/67D551E7B9BB3B68E823F5B998BD94531/notepad.pdb`.
Per default, Microsoft tools like WinDbg then store the PDB under `C:\ProgramData\dbg\sym\<pdb-name>\<guid><age>\<pdb-name>`.

WinDbg then uses the [DbgHelp](https://learn.microsoft.com/en-us/windows/win32/debug/dbghelp-functions) API to parse the PDB.
As mentioned before, [x64dbg](https://github.com/x64dbg/x64dbg/tree/development/src/dbg/msdia) uses the DIA SDK. LLDB and the raddebugger parse the PDB directly.

To understand the PDB format, one has to understand three different concepts:

1) [The Multistream File Format](#multistream-file--msf-)

   This format determines the overall shape of the PDB. It more or less is a file system inside of a file.
   It partitions the PDB into so-called _streams_ (think files) which consists of non-contiguous pages (think sectors),
   which are given by a stream table stream (think File Allocation Table).
   
2) [The PDB stream layout](#pdb-format)

   There are a bunch of PDB specific streams. Some contain debugging information, 
   some information about the PDB itself, and some other speedup structures for incremental linking.
   We will go in detail over every single stream in the `PDB-Format` section.

3) [CodeView](#codeview)

   CodeView is the Windows debugging information format. It encompasses type information, symbol information, 
   file and line number information. This information is produced by the compiler on a per compilation unit bases
   and stored in the object files. It is then _merged_ or incrementally updated into the PDB by the linker.
   
We will go into detail about each of these three concepts in the next sections.

# Multistream File (MSF)

The Multistream File Format determines the on disk layout of the PDB. The best source of documentation is the 
[LLVM-wiki article](https://llvm.org/docs/PDB/MsfFile.html) which is based on the [implementation](https://github.com/microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/msf/msf.cpp) release by Microsoft.

There are two versions of the MSF format, an older one referred to as _SmallMsf_ and the current one (from 1999) 
referred to as _BigMsf_. We only document the _BigMsf_ file format here.

The MSF considers the file as an array of _pages_, the first page is reserved for the file header.
The page size is determined from the header.
All pages with index 1 modulo the page size are reserved for the first _Free Page Map_.
All pages with index 2 modulo the page size are reserved for the second _Free Page Map_.
For example, if the page size is `0x1000` (as it usually is), then the first Free Page Map would consist of the 
pages `1, 0x1001, 0x2001, 0x3001, ...` and the second Free Page Map would consist of the pages `2, 0x1002, 0x2002, 0x3002, ...`.

Only one of the two free page maps is active at any given time. 
The active Free Page Map holds one bit per page, indicating whether the page free or not. `1` meaning free, `0` meaning used.
Note that as one page holds `0x8000` bits one could only allocate a new page for the Free Page Map every `8 * page size`
pages, but due to backwards compatibility this behavior must remain.

The header page (index 0) and the Free Page Map pages must be marked as allocated in the active free page map.
All other (allocated) pages are assigned to be part of so-called _streams_. 
This assignment is realized using a special stream called the _stream table stream_, which can be found from the information stored in the header.

The motivation for this format is to provide a way to append, read and write these stream, without changing the current data.
This is realized by allocating a new stream table stream (allowing for copy-on-write access) and using the _other_ Free Page Map.
Now, if at any point we notice an error, we can just _forget_ we ever did anything. Else, at _commit_ time, the 
stream table streams and the Free Page Map are "atomically" swapped changing the meaning of the MSF.

## MSF file header

The MSF file header (at page 0) looks as follows:
```c
struct msf_header{
    u8  signature[32];
    u32 page_size;
    u32 active_free_page_map;
    u32 amount_of_pages;
    u32 stream_table_stream_size;
    u32 unused;
    u32 page_list_of_stream_table_stream_page_list[];
};
```
* `signature`

  The signature for a MSF formatted file is `"Microsoft C/C++ MSF 7.00\r\n\032DS\0\0\0"`.

* `page_size`
   
   The size of a page in bytes. Usually this value is `0x1000` on x64, but values of `0x200`, 
   `0x400` and `0x800` are also allowed. 
  
* `active_free_page_map`

   The currently active Free Page Map. This value should only ever be one or two. Meaning either the 
   first (pages `1`, `0x1001`, `0x2001`, ...) or second Free Page Map (pages `2`, `0x1002`, `0x2002`, ...) is active. 
   
* `amount_of_pages`
   
   The amount of pages contained in the file. The size of the file should be equal to `page_size * amount_of_pages`.
   
* `stream_table_stream_size`

   The size in bytes of the special stream table stream. 
   From this value one can deduce the amount of pages occupied by the stream table stream via 
   `stream_table_stream_size_in_pages = ceil(stream_table_stream_size/page_size)`.
   
* `unused`

   In the old _SmallMsf_ format a (32-bit) pointer was stored here for convenience.
   
* `page_list_of_stream_table_stream_page_list`

   Following the MSF header is a list of page numbers. The corresponding pages make up the stream table stream page list.
   This double indirection is introduced to allow for larger stream table streams.
   There are `stream_table_stream_size_in_pages` 32-bit integers in the stream table stream page list.
   This means there are `ceil((stream_table_stream_size_in_pages * sizeof(u32))/page_size)` 32-bit integers in the 
   `page_list_of_stream_table_stream_page_list`.
   As one might imagine, usually there is exactly one entry in this list, allowing for a stream table stream of size
   `0x400000` or 4 MiB (assuming `0x1000` page size).

## Stream Table Stream

The _stream table stream_ stores size and page information for each stream. 
It can be reconstructed from the information present in the MSF file header.
The layout of the stream table stream is as follows:
```c
    u32 amount_of_streams;
    u32 streams_sizes[amount_of_streams];
    u32 stream_one_pages[];
    u32 stream_two_pages[];
             ...
```
Importantly, streams can be marked as being _deleted_ in which case their stream size is `0xffffffff` (or -1 as a signed integer).
For example, one might encounter this stream table stream:

```c
amount_of_streams  = 4;
stream_sizes       = {8, 0x2000, 0xffffffff, 0, 0x1001};
stream_one_pages   = {3};    // page 0, 1, 2 are header, and Free Page Maps, 
                             // 3 is the first data page
stream_two_pages   = {4, 8}; // pages in a stream do not have to be contiguous
stream_three_pages = {};     // Deleted streams have no pages
stream_four_pages  = {};     // Empty streams have no pages
stream_five_pages  = {5, 6}; // Even though the second page has only one
                             // byte used, it is still allocated
```
Also note that in this example page 7 is not used and would be marked in the Free Page Map (unless it is used by the stream table stream or the stream table stream page list).

## Old Stream Table Stream

One final quirk of the MSF format is the _Old Stream Table Stream_. This stream is at the fixed stream index `0`.
As the name implies, this stream contains an old (unused) stream table stream. 
At parse time, the current Stream Table Stream (parsed from the header) is written to the old directory stream (at stream index `0`).
At commit time, after (potentially) changing the current Stream Table Stream, the old one is freed in the Free Page Map.
Hence, when parsing the PDB, the pages "allocated" to the Old Stream Table Stream are not marked as allocated in the active Free Page Map.


# PDB-Format

In this section we will go over all the different streams defined by the PDB format, when they are present and how to find them.
The best sources are 
* The [LLVM-Wiki](). While it is somewhat incomplete and contains some minor mistakes, this is by far the best documentation for the PDB format.
* The [microsoft-pdb]() repository. While the source code is fairly cryptic, somewhat dated and contains barely any comments, 
  it provides a good _ground truth_, when you are already sort of know what is going on.
* The [LLVM implementation](). Notably, [lld/COFF/PDB.cpp](https://github.com/llvm/llvm-project/blob/main/lld/COFF/PDB.cpp), [llvm/lib/DebugInfo/PDB/PDB.cpp](https://github.com/llvm/llvm-project/blob/main/llvm/lib/DebugInfo/PDB/PDB.cpp) and [lldb/source/Plugins/SymbolFile/NativePDB/SymbolFileNativePDB.cpp](https://github.com/llvm/llvm-project/blob/main/lldb/source/Plugins/SymbolFile/NativePDB/SymbolFileNativePDB.cpp).
* Finally, the [pdb](https://github.com/willglynn/pdb) repository by willglynn on github contains a lot good documentation in the form of comments.

## Overview

Overall, one should look at the PDB format as a container format for CodeView, which contains speed up structures to enable incremental linking.
The following is an overview over all _important_ streams.

| stream name                | stream index                        | availability                                            | description | 
|----------------------------|-------------------------------------|---------------------------------------------------------| -------------|
| PDB Information Stream     | Fixed index 1                       | Always present                                          | Contains information about the PDB and the GUID and age. |
| TPI Stream                 | Fixed index 2                       | Always present                                          | Contains CodeView Type Records. (This is the stream that contains the type information) | 
| DBI Stream                 | Fixed index 3                       | Always present, can be empty for type servers           | Contains various information about the executable and how to relate address ranges to symbol information. | 
| IPI Stream                 | Fixed index 4                       | Present based on PDB Information stream                 | Contains CodeView Id Records. | 
| TPI hash stream            | Defined by TPI header               | Present based on TPI header                             | Contains hashes for all type records, as well as speed up structures to lookup type records by type index and vice versa. |
| IPI hash stream            | Defined by IPI header               | Present based on IPI header                             | Contains hashes for all ID records, as well as speed up structures to lookup ID records by id index and vice versa. |
| Module symbol stream       | Defined in DBI stream               | Usually one for each module                             | Contains symbol and line information for the module (compilation unit). |
| Symbol record stream       | Defined by DBI stream header        | Present based on DBI header                             | Contains references to all global symbols defined in the individual modules, as well as "public symbols". | 
| Global symbol index stream | Defined by the DBI header           | Present based on DBI header                             | Contains a speedup structure to lookup symbols in the symbol record stream by name. Only global symbols "hit" by the global symbol stream are valid. | 
| Public symbol index stream | Defined by the DBI header           | Present based on DBI header                             | Contains a speedup structure to lookup public symbols by name or address. Also contains information about the incremental linking table inside the exe. | 
| /names                     | Defined in the _named stream table_ | Technically optional, but required for line information | A global string table. This allows for specifying strings by index instead of redundantly storing them everywhere. | 
| Section Header Dump Stream | Defined in DBI stream               | Technically optional, but always observed               | Contains a copy of the section headers of the executable. This is used to resolve section:offset addresses to relative virtual addresses. |

## PDB Information stream

The PDB Information stream contains information about the PDB itself, as well as the `GUID` and `age` to match the PDB to its executable.
It has the fixed stream index `1` and starts with the following header:

```c
struct pdb_information_stream_header{
    u32 version;
    u32 timestamp;
    u32 age;
    GUID guid;
};
```
* The current `version` is `PDBImpvVC70 = 20000404` (read 04.04.2000). While there are more versions (and also newer versions)
  defined in the [pdb.h](https://github.com/microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/langapi/include/pdb.h)
  from the microsoft-pdb repository, this version is the only one observed.
  The newer "versions" seem to be used as _feature codes_ (see below).
  
* The `timestamp` is generated by calling `time(0)` at the time the PDB is written.
* The `age` is the amount of times the PDB was written.
* The `guid` has to match the `guid` of the `RSDS` debug directory of the executable.

The header is followed by a serialized hash table. This hash table defines the "named streams".
The hash table maps names of streams (e.g. "/names") to a stream index.
Known named streams are 

| stream name         | description                                                                           | 
|---------------------|---------------------------------------------------------------------------------------|
| "/names"            | A file global string pool, mostly used for file names.                               |
| "/LinkInfo"         | Optionally, contains a `LinkInfo` structure.                                           | 
| "/src/headerblock"  | Contains information about .natvis files contained in the PDB.  These files are also named streams. | 
| "/TMCache"          | A relatively new stream, which contains a cache for the type maps defined in [tm.h](https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/tm.h) |
| "/UDTSRCLINEUNDONE" | This stream is sometimes present but its meaning is unknown and it seems to be empty. | 

The layout of this serialized hash table is as follows:
```c
    u32 string_buffer_size;
    u8  string_buffer[string_buffer_size];
    u32 amount_of_entries;
    u32 capacity;
    struct bit_array present_bits;
    struct bit_array deleted_bits;
    struct {
        u32 key;
        u32 value;
    } entries[amount_of_entries];
    u32 unused;
```
Where `bit_array` has the following layout:
```c
    struct bit_array{
        u32 word_count;
        u32 words[word_count];
    };
```
**Importantly**, after the string table, the rest of the stream does not have any defined alignment anymore.

A `key` for the named stream table is an offset into the `string_buffer`. 
A `value` is the stream index, for the stream of that name.
The hash table uses [linear probing](https://en.wikipedia.org/wiki/Linear_probing) and [lazy deletion](https://en.wikipedia.org/wiki/Lazy_deletion) using tombstone values.
The `present_bits` and `deleted_bits` tell you which slots of the hash table are present and occupied by a tombstone value respectively.
Both these `bit_array`s have their own `word_count` value. Hence, they need not hold a bit for every slot in the hash table. 
For example, if there are no tombstone entries in the hash table, `deleted_bits.word_count` might be `0`. 
There should be `amount_of_entries` bits set in the `present_bits`.
The algorithm to recreate the hash table works as follows:
```c
struct hash_table_entry *table_entries = calloc(capacity, sizeof(*table_entries));
for(u32 index = 0, entry_index = 0; index < capacity && entry_index < amount_of_entries; index++){
    u32 word_index = index / (sizeof(u32) * 8);
    u32 bit_index  = index % (sizeof(u32) * 8);
    
    if(word_index < present_bits.word_count && (present_bits.words[word_index] & (1u << bit_index))){
        // Entry is present.
        table_entries[index] = entries[entry_index++];
        continue;
    }
}
```
As a hash it uses a hash of the string inside the string buffer corresponding to the `key` (the key is an offset into the string buffer).
The string hash function is derived from a common hash function used throughout the PDB format.

```c
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
    return (u16)pdb_hash_index(string, strlen(string), (u32)-1);
}
```
(See [`hashSz`](https://github.com/microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/include/misc.h#L86))
A modulus of `-1` does not change the value. Afterward, the index is computed as a modulus of the `hash` and the `capacity`, i.e
```c 
u32 named_stream_table_get_index(struct named_stream_table *table, char *stream_name){
    u16 hash = hash_string(stream_name);
    
    for(u32 hash_index = 0; hash_index < table->capacity; hash_index++){
        u32 index = (hash_index + hash) % table->capacity;
        
        // If this is a deleted entry search the next one.
        if(bit_array_is_set(&table->deleted_bits, index)) continue;
        
        // If we hit an entry which was not present, the 'stream_name' is not defined.
        if(!bit_array_is_set(&table->present_bits, index)) return -1;
        
        if(strcmp(stream_name, table->string_buffer + table->entries[index].key) == 0){
            return table->entries[index].value;
        }
    }
    return -1;
}
```
Finally, the `unused` value comes from the fact that this is "general purpose" template. If no specialized "index allocation function" is provided, 
this value is used to generate a unique `value` for each inserted string. Here, the index allocation function allocates stream indices.

You can find the original source code for this hash table [here](https://github.com/microsoft/microsoft-pdb/blob/master/PDB/include/nmtni.h). 

After the _named stream table_ the rest of the pdb stream is used for a set of feature codes. The following feature codes are defined:

| feature code       | value    |
|--------------------|----------|
| impvVC110          | 20091201 | 
| impvVC140          | 20140508 |
| featNoTypeMerge    | "NOTM"   |
| featMinimalDbgInfo | "MINI"   |

If either `impvVC110` or `impvVC140` is present, the PDB has a valid IPI stream (see later).
`impvVC110` must be the last feature code. If `featNoTypeMerge` is present the PDB was produced with the 
undocumented linker flag `/DEBUG:CTypes` if `featMinimalDbgInfo` is present, the PDB was produces with the 
`/DEBUG:FASTLINK` (or equivalently `/DEBUG:MINI`). 
For more information on both of these flags see the CodeView section.


## /names Stream

The _/names_ stream is the only named stream which is always present. It contains a string table which is primarly used by filenames in the line information.
Conceptually, this stream is used to store u32 offsets into a string buffer instead of actual strings.

It has the following layout:
```c
    u32 signature;
    u32 hash_version;
    u32 string_buffer_size;
    u8  string_buffer[string_buffer_size];
    u32 bucket_count;
    u32 buckets[bucket_count];
    u32 amount_of_strings;
```
* `signature`

The signature of the string table is `0xEFFEEFFE`.

* `hash_version`

In the [microsoft-pdb source files](https://github.com/microsoft/microsoft-pdb/blob/master/PDB/include/nmt.h),
two different string hash functions are defined `LHashPbCb` and `LHashPbCbV2` and corresponding constants
`verLongHash = 1`, and `verLongHashV2 = 2`. In practice only `verLongHash` is observed.
The [`LHashPbCb`](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/PDB/include/misc.h#L77) is a version of `pdb_string_hash` which returns a u32 instead of truncating to a u16.

* `string_buffer_size`, `string_buffer`

The buffer holds the actual zero-terminated strings. The first string inside the string buffer always has to be the zero-sized string, 
as a zero offset is also used as an invalid offset in the hash table.
Importantly, the size of the string buffer is not aligned, thus usually the rest of the stream is unaligned.

* `bucket_count`, `buckets`

A hash table, which maps strings to the offsets of the corresponding string in the `string_buffer`.
This hash table uses the hash function specified by `hash_version` and linear probing to resolve collisions.

* `amount_of_strings`

The amount of strings in the string buffer, not counting the zero-sized string. Also corresponds to the amount of set entries in the hash table.

## TPI Stream

The _TPI Stream_ contains the type information for all types used in the executable. It is always present and located at the fixed stream index `2`.
The TPI Stream starts with the following header:
```c
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
```
* `version` 

The current `version` is `20040203`. 

* `header_size`

The size of the header, should be `sizeof(struct tpi_stream_header)`. 
Specifying the size of a header is a common versioning scheme in Windows.

* `minimal_type_index`

The base for the type indices. This value is usually `0x1000` as the first `0x1000` type indices are reserved for basic types.

* `one_past_last_type_index`, `byte_count_of_type_record_data_following_the_header`

There should be `one_past_last_type_index - minimal_type_index` type records following the header, 
occupying `byte_count_of_type_record_data_following_the_header` bytes.

In this way, each type record is assigned a type index, which the CodeView format uses to reference types.
Each type record starts out with a header:

```c
struct codeview_type_record_header{
    u16 length;
    u16 kind;
};
```
Here, the `length` field itself is not included in the length, hence iterating all type records would look as follows:
```c
struct tpi_stream_header *tpi = (void *)tpi_base;
u32 type_index = tpi->minimal_type_index;
for(u32 offset = 0; offset < tpi->byte_count_of_type_record_data_following_the_header; ){
    struct codeview_type_record_header *header = (void *)(tpi_base + tpi->header_size + offset);
    
    printf("type_index %x, kind %x, length %x\n", type_index++, header->kind, header->length);
    
    offset += header->length + sizeof(header->length);
}
```
To interpret these type records see [`cvinfo.h`](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h) and 
the CodeView section.

An example of the type information for the structure `struct structure{ int member; };` would be:

```
0x1000 : Length = 18, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_MEMBER, public, type = T_INT4(0074), offset = 0
		member name = 'member'

0x1001 : Length = 30, Leaf = 0x1505 LF_STRUCTURE
	# members = 1,  field list type 0x1000, 
	Derivation list type 0x0000, VT shape type 0x0000
	Size = 4, class name = structure, UDT(0x00001001)
```
Printout produced by the [cvdump utility](https://github.com/microsoft/microsoft-pdb/tree/master/cvdump) included in the microsoft-pdb repository.

Importantly, a type record can only refer (by type index) to earlier type records. This means that types which are self referential, e.g.:
```c
struct structure{
    struct structure *next;
};
```
need a "FORWARD REF":

```
0x1000 : Length = 30, Leaf = 0x1505 LF_STRUCTURE
        # members = 0,  field list type 0x0000, FORWARD REF,
        Derivation list type 0x0000, VT shape type 0x0000
        Size = 0, class name = structure, UDT(0x00001003)

0x1001 : Length = 10, Leaf = 0x1002 LF_POINTER
        Pointer (__ptr64), Size: 8
        Element type : 0x1000

0x1002 : Length = 18, Leaf = 0x1203 LF_FIELDLIST
        list[0] = LF_MEMBER, public, type = 0x1001, offset = 0
                member name = 'next'

0x1003 : Length = 30, Leaf = 0x1505 LF_STRUCTURE
        # members = 1,  field list type 0x1002,
        Derivation list type 0x0000, VT shape type 0x0000
        Size = 8, class name = structure, UDT(0x00001003)
```
For a more detailed description, see the _Type Index_ subsection of the CodeView section.

* `stream_index_of_hash_stream`

The index of the _TPI hash stream_, which contains speedup structures to search up type records by index and vice versa.
All other members inside the `tpi_stream_header` structure describe speedup structures located inside the TPI hash stream.
This index can in theory be `(u16)-1`, in which case the TPI hash stream is not present, but seems to be always present.

* `stream_index_of_auxiliary_hash_stream`

Presumably, this is an index to a different hash stream. In practice, this value is always `(u16)-1`.
The member name in the in the `microsoft-pdb` repository is `snPad` (stream number padding?), 
but there is a comment claiming it to contain "auxiliary hash data if necessary".

* `hash_key_size`, `number_of_hash_buckets`, `hash_table_index_buffer_offset`, `hash_table_index_buffer_length`

These values describe information inside the `TPI hash stream` used to recreate a hash table mapping type records to type indices.
This table is used to deduplicate type records during (incremental) linking and (because of the choice of hash function) to look up type records by name.

The `hash_key_size` can be `2` or `4` but in practice is always `4`.
Depending on the `hash_key_size` the `number_of_hash_buckets` is bounded to a specific range.
For `hash_key_size == 4` the `number_of_hash_buckets` has to be in the range of `0x1000` and `0x40000`.

The `hash_table_index_buffer` contains a _hash table index_ for each type record. 
Each of these indices has `hash_key_size`.
This means one should have `hash_table_index_buffer_length = hash_key_size * (one_past_last_type_index - minimal_type_index)`.
All _hash table indices_ should be between `0` and `number_of_hash_buckets`, as they are the hash modulo the `number_of_hash_buckets`. 
The type record with type index `i` is in the `hash_table_index_buffer[i]`-th bucket inside the recreated hash table.
This hash table uses [chaining](https://en.wikipedia.org/wiki/Hash_table#Separate_chaining) to resolve collisions.

The following code can be used to recreate the hash table:
```c
struct hash_bucket{
    struct hash_bucket *next;
    u32 type_index;
} **buckets = calloc(tpi->number_of_hash_buckets, sizeof(*buckets));

u32 *hash_indices = (u32 *)(tpi_hash_stream_base + tpi->hash_table_index_buffer_offset);
for(u32 type_index = tpi->minimal_type_index; type_index < tpi->one_past_last_type_index; type_index++){
    u32 hash_index = hash_indices[type_index - tpi->minimal_type_index];
    
    assert(hash_index < tpi->number_of_hash_buckets); // The indices are stored, not the hashes.
    
    // Insert the record in the front.
    struct hash_bucket *bucket = malloc(sizeof(struct hash_bucket));
    bucket->type_index = type_index;
    bucket->next = buckets[hash_index];
    buckets[hash_index] = bucket;
}
```
The hash function used for type records is somewhat complicated, the original source code can be found [here](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/PDB/dbi/tpi.cpp#L1296C15-L1296C15) 
and the llvm-reimplementation can be found [here](https://github.com/llvm/llvm-project/blob/bb32e91f33f64af279b3d8aa72c53f8c6c49a317/llvm/lib/DebugInfo/PDB/Native/TpiHashing.cpp#L105).
For compound types (`LF_CLASS`, `LF_STRUCTURE`, `LF_UNION`, `LF_INTERFACE`, `LF_ENUM`) definitions, 
which are not anonymous, the hash is simply the `pdb_string_hash` of the name. 
For `LF_UDT_SRC_LINE` and `LF_UDT_MOD_SRC_LINE` the hash is the `pdb_string_hash` over the type_index.
For all other type records the hash is a CRC32 over the entire type record.
Also see the reimplementation (`tpi_hash_table_index_for_record`) inside `write_pdb.c`.

* `index_offset_buffer_offset`, `index_offset_buffer_length`

The _index offset buffer_ is an arrays of `struct { u32 type_index; u32 type_record_offset; }` located inside the TPI hash stream.
These entries are intended to speed up searching for type records by type index. 
There is one entry for about every 8 KiB of type record data. 
One can achieve a `O(log n)` lookup using a binary search by `type_index` followed by a linear search for at most 8 KiB of type record data.
The `type_record_offset` is an offset in the type record data. To get the offset in the TPI stream one must add `tpi_stream_header->header_size`.

* `udt_order_adjust_table_offset`, `udt_order_adjust_table_length`

The udt (user defined type) order adjust table is only relevant for incremental linking. It is used to fix up the order of `hash_bucket`s inside the hash table recreated above.
This is necessary because during incremental linking, old type records do not get removed. 
Usually, if a newer version of a type is added to the table it will land in the same bucket, because the hash function is based on the name of the type 
and will be placed *before* the older value in the hash collision chain. This means the newer version will be found first during lookup.
Now, if a type gets changed, but then the change is reverted, no new type record will be inserted as a matching record is already present.
In this case, the order of the entries needs to be adjusted after loading the table.

The udt order adjust table contains the information to make this adjustment happen. 
It maps type names (strings) to the type index which should be reinserted at the front of the collision chain.
The strings (type names) are contained in the /names steam and only the offset is stored in the hash table itself.

The hash table is the same template used by the named stream table (the named stream table is also a template, but it uses a `Map`-template). Hence, the layout on disk is as follows:
```c
u32 amount_of_entries;
u32 capacity;
struct bit_array present_bits;
struct bit_array deleted_bits;
struct {
    u32 key;   // Offset of the string in "/names"
    u32 value; // Type index which should be adjusted to the start of the collision list.
} entries[amount_of_entries];
```
The original source code for this generic template can be found [here](https://github.com/microsoft/microsoft-pdb/blob/master/PDB/include/map.h).

To apply the adjustments, one can simply iterate then entries:
```c
for(u32 index = 0; index < amount_of_entries; index++){
    u32 offset     = entires[index].key;
    u32 type_index = entires[index].value;
    
    u32 hash_index = hash_indices[type_index - minimal_type_index];
    
    struct hash_bucket **prev = &buckets[hash_index];
    struct hash_bucket *hash_bucket = buckets[hash_index];
    
    for(; hash_bucket; prev = &hash_bucket->&next, hash_bucket = hash_bucket->next){
        if(hash_bucket->type_index == type_index) break;
    }
    
    // Move 'hash_bucket' to the start of the list.
    *prev = hash_bucket->next;
    hash_bucket->next = buckets[hash_index];
    buckets[hash_index] = hash_bucket;
}
```

## DBI Stream

The DBI or _DeBug Information_ stream is the most complicated stream defined by the PDB format. 
It provides ways to match address ranges inside the executable to their debug symbols. 
It has the following header:
```c
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
        u16 the_pdb_allows_conflicting_types : 1; // undocumented /DEBUG:CTYPES flag.
    } flags;
    
    u16 machine_type;
    u32 reserved_padding;
};
```

* `version_signature`

This value has to be `-1`. This exist because there was an earlier version of this stream which did not include a versioned header.

* `version`

The current version of the DBI stream is `19990903`. 

* `age` 

The age of the DBI stream gets set to the age of the PDB whenever the DBI stream is written.

* `stream_index_of_the_global_symbol_index_stream`, `stream_index_of_the_public_symbol_index_stream`, `stream_index_of_the_global_symbol_index_stream`

For these streams see later sections. These stream indices can technically be `-1` meaning they are not present, but they seem to be always present.

* `toolchain_version`,
  `version_number_of_mspdb_dll_which_build_the_pdb`, `build_number_of_mspdb_dll_which_build_the_pdb`

The version number of the `mspdbXXX.dll`, which build/rebuild this PDB last. `XXX` can be `core`, `st` or `140`.
These four version numbers together make up the `product version`, which can be seen in the properties dialog for `mspdbXXX.dll`.
Looks something like: `14.29.30151.0`

[According to llvm](https://github.com/llvm/llvm-project/blob/95c0e03376a4699c38cd3e37a3b6fdad0549cd52/lld/COFF/PDB.cpp#L1666), there are known cases, where specifying the particular toolchain version matters.
Hence, one should provide a version for compatibility.

* `byte_size_of_the_*_substream`

Immediately following the header, there are a variety of substreams one after the other.
For information on them see their respective subsection. Notice the non-linear order and the offset member in the middle.

* `index_of_the_MFC_type_server_in_type_server_map_substream` 

The released version of `mspdbcore.dll` does not define the `PDB_TYPESERVER` hence this value and the `byte_size_of_the_type_server_map_substream` are always zero.
The MFC presumably stands for "Microsoft Foundation Class" see [here](https://learn.microsoft.com/en-us/cpp/mfc/mfc-desktop-applications?view=msvc-170).

* `flags`

The `was_linked_incrementally` flag is set whenever an incremental linking table is present.
The `private_symbols_were_stripped` flag is set when the `PDBCopy` utility was used to remove private symbol information.
The `the_pdb_allows_conflicting_types` flag is set when the PDB was created using the undocumented `/DEBUG:CTypes` linker flag.

* `machine_type` 

An identifier for the target processor, also see the `CV_CPU_TYPE_e` inside `cvconst.h` or this [MSDN link](https://learn.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-2015/debugger/debug-interface-access/cv-cpu-type-e?view=vs-2015&redirectedfrom=MSDN).

* `reserved_padding`

Padding to 64 bytes for "future growth".

### Module Information Substream

Immediately after the DBI header, there is the _Module Information Substream_. 
It consists of an _array_ of variable length module structures.
The index into this array determines the _module index_, which is referenced by other information later on.
Each module structure has the following layout:
```c
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
};
```
* `unused`, `unused2`

Both of these were 32-bit pointers, which were written out for convenience. If the PDB was produced by a 64-bit version of 
`mspdbcore.dll` these members are `NULL`, but otherwise also unused.

* `first_code_contribution`

A copy of the first entry in the Section Contribution Substream (see below) for this module which has the 'IMAGE_SCN_CNT_CODE' characteristic set. 
If this module does not contribute to the code of the executable this entry can be the _invalid section contribution_, which 
has `section_id`, `size` and `module_index` of `-1` and everything else `0` (see below for the definition of `pdb_section_contribution`).

* `flags`

The `was_written` flag is only used on the in-memory version of this structure and is initialized to `FALSE` uppon load.
It then gets set to `TRUE` whenever the DBI was written.

The `edit_and_continue_enabled` flag is set when the object file was build using the `/ZI` flag.

The `TSM_index` has to do with the disabled `PDB_TYPESERVER` capability. So it is always 0.

* `stream_index_of_module_symbol_stream`

The index of the stream which contains the actual private symbol information for the module (compilation unit).
This index can be `(u16)-1` if no private symbol information for this module is present.
For more information about this stream see the _Module Symbol Stream_ section.

* `byte_size_of_*_information`

These fields relate to the content of the module symbol stream for this module.

* `amount_of_source_files`

The amount of source files which contributed to this module. This value includes any header files.

* `edit_and_continue_source_file_string_index`, `edit_and_continue_pdb_file_string_index`

If these are set, they are offsets into the _Edit And Continue Substream_ string buffer.
The `edit_and_continue_source_file_string_index` is sometimes set by MASM for `.asm` files like 
`memcpy.asm`. The `edit_and_continue_pdb_file_string_index` only seems to be set for the special
`* Linker *` module (see below). It has this field set to point at the full path to the PDB.

* `module_name_and_file_name` 

This member makes the `struct pdb_module_information` variable sized. 
First there is a zero-terminated string which is the module name, then there a zero-terminated string which is the _file name_.
If the module is a simple object file, then both string are just the full path of the object file.
E.g.: `module_name = "C:\Path\to\object.obj"` and `file_name = "C:\Path\to\object.obj"`.
If the object file is part of an archive file (`.lib`), then the file name is the full path of the archive file and the module name is the name of the object.
E.g.: `module_name = "object.obj"` and `file_name = "C:\Path\to\archive.lib"`.
Note that the module name in this case is the module name specified in the archive, which can also be full path.
For example for `LIBCMT.lib` we might have:
* `module_name = "d:\agent\_work\63\s\Intermediate\vctools\libcmt.nativeprjr\amd64\exe_main.obj"` and 
* `file_name = "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.28.29333\lib\x64\LIBCMT.lib"`

#### Special `* Linker *` module

The last module is the special `* Linker *` module. It works exactly like any other module, only that its symbol record stream contains 
special symbols which contain information about stuff the linker added. 
The `first_section_contribution` tells you where to find the incremental linking table.
The `edit_and_continue_pdb_file_string_index` is an index into the _Edit and Continue_ substream to the full path of the PDB.
Sometimes this stream might also be called differently, e.g: `* CIL *`.

### Section Contribution Substream

The _Section Contribution Substream_ contains information on how to map offsets in the executable to module indices.
It begins immediately after the _Module Information Substream_ and starts with a `u32` version followed by an array of either
```c 
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
```
if the version is `DBISCImpv = 0xeffe0000 + 19970605` or
```c
struct pdb_section_contribution_v2{
    struct pdb_section_contribution base;
    
    u32 segment_id_in_object_file;
};
```
if the version is `DBISCImpv2 = 0xeffe0000 + 20140516`.
The new version of the structure is only used if the `/DEBUG:FASTLINK` flag was used.

The entries in this array are sorted first by `section_id` then by `offset`, allowing for binary searching 
for the `module_index`. One can then search the _module symbol stream_ of the associated module to find 
the symbol for a given section id and offset.

Terminology gets a little hard here:

* `module_index`: 0-based index in the `pdb_module_information` array.
* `section_id`: 1-based index in the section table of the executable.
* `segment_id`: 1-based index in the section table of an object file.

In general, there is one section contribution for every segment from an object file, which contributed to the executable.
The new `segment_id_in_object_file` links back to this segment.

The `characteristics` field has the same layout as the `characteristics` field of the section header.

### Section Map Substream

The _Section Map Substream_ starts with the following header: 
```c
struct pdb_section_map_stream_header{
    u16 number_of_section_descriptors;
    u16 number_of_logical_section_descriptors;
};
```
In practice, both of these values are equal to one plus the section count.
The header is followed by an array of one plus the section count many entries with the following layout:
```c
struct pdb_section_map_entry{
    u16 flags;
    u16 logical_overlay_number;
    u16 group;
    u16 frame;
    u16 section_name;
    u16 class_name;
    u32 offset;
    u32 section_size;
};
```
This table seems to be related to some older object format (Object Module Format used by DOS and 16-bit Windows). 
In practice, this table always seems to look as follows:
```
Sec  flags  ovl   grp   frm sname cname    offset    cbSeg
 01  010f  0000  0000  0001  ffff  ffff  00000000 00037864
 02  010d  0000  0000  0002  ffff  ffff  00000000 0007a9d4
 03  0109  0000  0000  0003  ffff  ffff  00000000 00015426
 04  010b  0000  0000  0004  ffff  ffff  00000000 000030b1
 05  0109  0000  0000  0005  ffff  ffff  00000000 000067e0
 06  0109  0000  0000  0006  ffff  ffff  00000000 00000f7f
 07  0109  0000  0000  0007  ffff  ffff  00000000 00000151
 08  0109  0000  0000  0008  ffff  ffff  00000000 000001b5
 09  0109  0000  0000  0009  ffff  ffff  00000000 00001226
 0a  0208  0000  0000  0000  ffff  ffff  00000000 ffffffff
```
(This was dumped using the `cvdump` utillity).
Notice that for each section the `cbSeg` or `section_size` is the virtual size of the corresponding section.
According to llvm the flags can be derived from the following enum:
```c++
enum class SectionMapEntryFlags : uint16_t {
    Read = 1 << 0,              // Segment is readable.
    Write = 1 << 1,             // Segment is writable.
    Execute = 1 << 2,           // Segment is executable.
    AddressIs32Bit = 1 << 3,    // Descriptor describes a 32-bit linear address.
    IsSelector = 1 << 8,        // Frame represents a selector.
    IsAbsoluteAddress = 1 << 9, // Frame represents an absolute address.
    IsGroup = 1 << 10           // If set, descriptor represents a group.
};
```
See [this link](https://llvm.org/docs/PDB/DbiStream.html).

It seems this array does not serve any purpose in the current version of the PDB format and is mostly ignored.

### Source Information Substream

The _Source Information Substream_ contains the file name of files compiled for each module.
In practice, this substream seems to be mostly unused as the C13 line information does not reference it.

This substream has the following layout
```c
    u16 amount_of_modules;
    u16 truncated_amount_of_source_files;
    u16 source_file_base_index_per_module[amount_of_modules];
    u16 amount_of_source_files_per_module[amount_of_modules];
    u32 source_file_name_offset_in_string_buffer[amount_of_source_files];
    u8  string_buffer[];
    u8 align_to_4_bytes[];
```
* `amount_of_modules`

This field should be equal to the amount of modules computed by walking the module information substream.
Note that this includes the special `* Linker *` module.

* `truncated_amount_of_source_files`

This field used to represent the amount of source files which contributed to the executable.
For large projects (projects which use more then 65535 source files), this value is truncated to a 16-bit value.
The actual amount of source files has to be computed by walking the `amount_of_source_files_per_module` array.

* `source_file_base_index_per_module` 

This array has the same issue as the `truncated_amount_of_source_files` value.
For small projects the source files for module `module_index` are (using slice notation):
```c
u16 base   = source_file_base_index_per_module[module_index];
u16 amount = amount_of_source_files_per_module[module_index];

source_file_offsets = source_file_name_offset_in_string_buffer[base : base + amount];
```
For large projects, the values in this array are also truncated, rendering them useless.

* `amount_of_source_files_per_module`

This array contains the amount of source files which contributed to each module.

* `source_file_name_offset_in_string_buffer`

This array contains a u32-offset for each source file. This is used to deduplicate source files.
If a header file is used several times in different modules (compilation units) it only appears once in the `string_buffer`.
Each string is a full path.
Note that for large projects the `amount_of_source_files` should **not** be obtained from the `truncated_amount_of_source_files` 
but rather by summing all entries in `amount_of_source_files_per_module`.

* `string_buffer` 

This contains the zero-terminated file names.

* `align_to_4_bytes`

The source information substream is aligned to the file alignment of 4 bytes.

### Type Server Map Substream

We will not document this substream as the all implementation is `#if 0` out by the `PDB_TYPESERVER` define.

### Edit and Continue Substream

The _Edit and Continue Substream_ has the same layout as the "/names" stream.
We have already seen its use as the string table stream for the `edit_and_continue_source_file_string_index` 
and `edit_and_continue_pdb_file_string_index` members of the `pdb_module_information` structure.

#### Warning:
The size of the edit and continue substream is not aligned to any particular boundary, 
this means the following substream is unaligned.
Luckily, there is only the _Optional Debug Header Substream_ left.

### Optional Debug Header Substream

The _Optional Debug Header Substream_ is an array of (optional) stream indices, which contain debug information about the executable.
The following entries are currently defined:
```c
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
};
```
The most important of which is the `stream_index_of_section_header_dump` which is always present.
All other stream indices can be `(u16)-1` which indicates that they are not present.
The section header dump stream contains a copy of the section headers inside the executable.
These section headers can be used to translate from `section_id:offset` addressing usually used in the PDB 
to relative virtual addresses, which are more useful during debugging.
Microsoft symbol server PDBs often also contain a `.pdata` and `.xdata` stream, which contain copies of the `.pdata` and `.xdata` section of 
the executable and can be used for function unwinding in situations where the respective sections are corrupted or not present 
(for example in a kernel debugger context, these sections might be mapped out).

The following are the contents of all optional streams (if they are present):

* `fpo_data`

This is an array of [`FPO_DATA`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-fpo_data) structures.
These are used for frame pointer omission on 32-bit x86 systems.

* `exception_data`

This is an array of [`IMAGE_FUNCTION_ENTRY`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_function_entry).
This stream is deprecated in favor of the `pdata` stream, which has a header.

* `fixup_data`

This is an array of `XFIXUP_DATA` structures. 
The definition of this structure is contained in [cvinfo.h](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h)
This array is present when specifying [/DEBUGTYPE:FIXUP](https://learn.microsoft.com/en-us/cpp/build/reference/debugtype-debug-info-options?view=msvc-170#arguments).

* `omap_to_src`, `omap_from_src`

These entries are for translating addresses spaces between the original and a patched executable.
It consists of a sorted array of 
```c
struct OMAP_DATA {
    DWORD       rva;
    DWORD       rvaTo;
};
```
structures, see [here](https://github.com/microsoft/microsoft-pdb/blob/0fe89a942f9a0f8e061213313e438884f4c9b876/PDB/dbi/dbi.h#L18).

For more information there is a really good comment in this [file](https://github.com/google/breakpad/blob/main/src/common/windows/omap.cc) by google 
and in this [pdb library](https://github.com/willglynn/pdb/blob/b052964e09d03eb190c8a60dc76344150ff8a9df/src/omap.rs#L91).


* `clr_token_to_clr_record_id`

This is an array of `u32`. This has something to do with `.NET`.

* `pdata`, `xdata` 

A copy of the `.pdata` and `.xdata` sections of the executable.
These are present when specifying [/DEBUGTYPE:PDATA](https://learn.microsoft.com/en-us/cpp/build/reference/debugtype-debug-info-options?view=msvc-170#arguments).

Both of these streams have the following header before the actual section data:

```
typedef struct DbgRvaVaBlob {
    ULONG       ver;
    ULONG       cbHdr;
    ULONG       cbData;
    ULONG       rvaDataBase;
    DWORDLONG   vaImageBase;
    ULONG       ulReserved1;    // reserved, must be 0
    ULONG       ulReserved2;    // reserved, must be 0
    //BYTE      rgbDataBlob[];  // Data follows, but to enable simple embedding,
                                // don't use a zero-sized array here.
} DbgRvaVaBlob;
```
see [here](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/langapi/include/pdb.h#L479).

* `new_fpo_data`

This is an array of `FRAMEDATA` entries. See [`cvinfo.h`](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h)
for the definition of `FRAMEDATA`.

* `original section header dump`

This stream is again, like the `OMAP`, related to binary patching and contains the section headers prior to the binary patch.

## IPI Stream

The _IPI Stream_ contains id information. It has the exact same layout as the TPI stream, 
but it differs in what CodeView records are contained within. While the TPI stream contains 
type records like `LF_STRUCTURE`, the IPI stream contains "id" records `LF_FUNC_ID` or `LF_UDT_MOD_SRC_LINE`, 
which tell you information about functions or user defined types. For more information see the CodeView section later on.

## Module Symbol Streams

The _Module Symbol_ streams contain the private symbol information for each module. A _module_ is more or less a pseudonym for compilation unit i.e. obj-file,
but there also exists the special `* LINKER *` module. The information inside the module symbol stream comes in large part from the `.debug$S` section of the corresponding object file.
The module symbol stream index for each module is contained in the 
module information substream contained in the DBI stream. The layout of the module symbol stream is as follows:

```c
u8 symbol_information[byte_size_of_symbol_information];
u8 c11_line_information[byte_size_of_c11_line_information];
u8 c13_line_information[byte_size_of_c13_line_information];
u32 global_references_bytes_size;
u32 global_references[global_references_bytes_size/4];
```
where the `byte_size_of_*_information` members are also contained in the `pdb_module_information` structure inside the module information substream.

### Symbol Information

The `symbol_information` starts out with the `u32` CodeView signature. The current CodeView signature is `CV_SIGNATURE_C13` or `4`. 
Afterwards, it consists of CodeView symbol records, each of which starts with a 4-byte header:
```c
struct codeview_symbol_header{ // Also see SYMTYPE in cvinfo.h
    u16 length;
    u16 kind;
};
```
The `length` field itself is not contained in the `length` of the record. 
Each record should begin on a 4-byte boundary. The symbol kind is one of the [SYM_ENUM_e](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L2735) 
contained in `cvinfo.h`. 
As described below, the global data symbols (`S_GDATA32` and `S_LDATA32`) are split between the symbol record stream (see below) and the module symbol streams.
On the contrary the procedure records (`S_GPROC32` and `S_LPROC32`) are always contained in the module symbol stream.
For more information see the CodeView section.

### Line Information

C11 line information is not present anymore. Therefore, we will only document C13 line information.

The C13 line information consists of _subsections_. Each subsection start with the following 8-byte header:

```c
struct codeview_subsection_header{
    u32 type;
    u32 length;
};
```
The type is one of [`DEBUG_S_SUBSECTION_TYPE`](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4576C23-L4576C23) most important ones being.
`DEBUG_S_LINES` and `DEBUG_S_FILECHKSMS`, which contain the actual file and line information.
Object files also contain a `DEBUG_S_STRINGTABLE` to contain the filenames, but inside the PDB these are merged into the /names stream.
There is only ever one `DEBUG_S_FILECHKSMS` subsection but there maybe many `DEBUG_S_LINES` subsections (in fact there is usually one per function). 

The `DEBUG_S_FILECHKSMS` subsection contains an array of variable sized structures:
```c
struct codeview_file_checksum{
    u32 offset_in_string_table;
    u8  checksum_size;
    u8  checksum_kind;
    u8  checksum[];
};
```
Each of these structures is padded to be 4-byte aligned. The `checksum_kind` field is one of [`CV_SourceChksum_t `](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvconst.h#L88C11-L88C11).

The `DEBUG_S_LINES` subsection starts with a header:
```c
struct codeview_line_header{
    u32 contribution_offset;
    u16 contribution_section_id;
    u16 flags;
    u32 contribution_size;
};
```
Which specifies the part of the executable which the line information corresponds to. 
The only define flag is `CV_LINES_HAVE_COLUMNS (0x0001)`, but this flag seems to be never present.
After the header there is a set of blocks. Each block again starts of with a header:

```c
struct codeview_line_block_header{
    u32 offset_in_file_checksums;
    u32 amount_of_lines;
    u32 block_size;
};
```
The `offset_in_file_checksums` is an offset in the `DEBUG_S_FILECHKSMS` subsection. 
**WARNING:** The `DEBUG_S_FILECHKSMS` subsection can occur after a `DEBUG_S_LINES` subsection. Hence, when parsing, one first has to find the `DEBUG_S_FILECHKSMS` subsection, before being able to process the `DEBUG_S_LINES` subsection.

Assuming the `CV_LINES_HAVE_COLUMNS` flag is not set, the block consists of 
```c
struct codeview_line{
    u32 offset;
    u32 start_line_number     : 24;
    u32 optional_delta_to_end : 7;
    u32 is_a_statement        : 1;
};
```
structures. The `offset` field is an offset inside the contribution described by the `codeview_line_header`.
The `optional_delta_to_end` is usually zero, but can be used to indicate the end of the code defined by the line.
MSVC always sets the `is_a_statement` bit to `1`.

In theory, it seems one `DEBUG_S_LINES` is enough to cover each section of the executable, but in practice 
MSVC only emits one `codeview_line_block_header` per subsection and emits one `DEBUG_S_LINES` section per function.

### Global References

The global references are an array of `u32`-offsets into the symbol record stream (see below),
one for each global symbol referenced by this module. In this way, the PDB _remembers_ how the 
reference counts inside the global symbol index stream (see below) came to be. 
On a relink of a compilation unit, the reference counts of the global symbols referenced by the compilation unit are decremented.

@cleanup: talk about whats in the special * LINKER * module.

## Symbol Record Stream

The symbol records stream contains CodeView symbols which reference symbols in the modules symbol streams for all modules, as well as public (`S_PUB32`) symbols.
Its stream index can be found in the DBI stream. It contains no header and thus just immediately starts off with the first CodeView symbol record.
CodeView symbol records start off with a 4-byte header:
```c
struct codeview_symbol_header{ // Also see SYMTYPE in cvinfo.h
    u16 length;
    u16 kind;
};
```
All symbol records in the symbol record stream are produced by `link.exe`/`mspdbcode.dll` and are based on the symbols provided by the compiler in the object files.


**WARNING:** Symbol records in the _Symbol Record Stream_ are **not** necessarily valid. 
They should only be considered valid, if they are referenced by either the Global Symbol Index Stream (for non-`S_PUB32` symbols), or the Public Symbol Index Stream (for `S_PUB32` symbols).

The symbol record stream contains one `S_PROCREF` or `S_LPROCEREF` for every procedure, a `S_GDATA32` or `S_LDATA32` 
for global declarations, a `S_CONSTANT` for every named constant (enum or const expr) and a `S_UDT` for every typedef.
The `S_LPROCREF` and `S_LDATA32` reference static declarations while the other symbol references exported symbols. 
For `S_CONSTANT` and `S_UDT` there is only every one symbol for a given name. 
For example, if there are two compilation units:
```c
// compilation_unit_one.c
typedef int my_type;
enum { my_constant = 1 };
```
```c
// compilation_unit_two.c
typedef float my_type;
enum { my_constant = 2 };
```
Then only one of the `my_constant` and `my_type` are referenced in the symbol record stream. 
The other is contained in the module symbol stream of the module which declares it.

The code which produces the symbol records can be found [here](https://github.com/microsoft/microsoft-pdb/blob/0fe89a942f9a0f8e061213313e438884f4c9b876/PDB/dbi/mod.cpp#L2587).
In cvinfo.h the symbol `S_DATAREF` is also defined, but seems to be unused at this point.

**WARNING:** These reference symbols (`S_PROCREF`, `S_LPROCREF`, `S_ANNOTATIONREF`) use a one-based module id, instead of zero-based module index.

## Global Symbol Index Stream (GSI)

The _global symbol index_  or _GSI_ stream contains information to reconstruct a hash table which maps names to _hash records_.
```c
struct pdb_hash_record{
    u32 offset_in_symbol_record_stream_plus_one;
    u32 reference_counter;
};
```
Every _hash record_ references a symbol in the symbol record stream, as well as how many modules (compilation units) reference the symbol.
**WARNING:** These symbol offsets incremented by one.


The hash table has a fixed amount of buckets and uses [chaining]((https://en.wikipedia.org/wiki/Hash_table#Separate_chaining)) to resolve collisions. 
The bucket count of the hash table is `0x3ffff` if the `/DEBUG:FASTLINK` option was used and `4096` otherwise.
The on disk datum consists of 
1) An array of _hash records_ in hash table order.
2) A bitmap which indicates which buckets contain hash records.
3) An offset into the hash record array for each filled bucket.
    

**WARNING:** These offsets have to be adjusted. They assume the size of a `struct pdb_hash_record` to be 12-bytes.
This is because after loading the hash records, they have the following layout:
```c
struct pdb_loaded_hash_record{
    struct pdb_loaded_hash_record *next;
    struct codeview_record_header *symbol_record;
    u32 reference_counter;
};
```
which totals 12-bytes on a 32-bit system.
In practice this means each offset has to be divided by 12 (instead of 8) to get the `pdb_hash_record` index.

The actual on disk layout of the global symbol index stream is as follows:
```c
    u32 version_signature;
    u32 version;
    u32 hash_records_byte_size;
    u32 bucket_information_byte_size;

    struct pdb_hash_record hash_records[hash_records_byte_size/8];
    
    u32 bucket_present_bitmap[(hash_table_size/32) + 1];
    u32 bucket_hash_record_offsets[amount_of_present_buckets];
```
* `version_signature`

The version signature has to be `-1`.

* `version`

The current version of the GSI stream is `0xeffe0000 + 19990810`.

* `hash_records_byte_size`
 
The on disk byte size of the `hash_records` array.
 
* `bucket_information_byte_size`

The  combined size of the `bucket_present_bitmap` and the `bucket_hash_record_offsets`.

The following code can be used to reconstruct the hash table:

```c
// Load all hash records and chain them up, we will adjust entries which should not be chained later.
u32 amount_of_hash_records = hash_records_byte_size/8;
struct pdb_loaded_hash_record *loaded_hash_records = allocate(amount_of_hash_records * sizeof(*hash_records));
for(u32 hash_record_index = 0; hash_record_index < amount_of_hash_records; hash_record_index++){
    struct pdb_loaded_hash_record *hash_record = &loaded_hash_records[hash_record_index];
    hash_record->next              = hash_record + 1;
    hash_record->symbol_record     = symbol_record_stream_base + hash_records[hash_record_index].offset_in_symbol_record_stream;
    hash_record->reference_counter = hash_records[hash_record_index].reference_counter;
}
loaded_hash_records[amount_of_hash_records-1].next = NULL;

// Link the hash records into the hash table, based on the 'bucket_information'.
u32 gsi_hash_table_size = is_fastlink_pdb ? 0x3ffff : 4096;
struct pdb_loaded_hash_record **table = allocate(hash_table_size * sizeof(*table));

for(u32 table_index = 0, offsets_index = 0; table_index < gsi_hash_table_size; table_index++){
    u32 bitmap_index = (table_index / 32);
    u32 bit_index    = (table_index % 32);

    u32 bitmap_entry = bucket_present_bitmap[bitmap_index];
    if(bitmap_entry & (1u << bit_index)){
        u32 hash_record_offset = bucket_hash_record_offsets[offsets_index++];
        u32 hash_record_index  = hash_record_offset/12;
        
        table[table_index] = &loaded_hash_records[hash_record_index];
        if(hash_record_index > 0){
             loaded_hash_records[hash_record_index - 1].next = NULL;
        }
    }
}
```
The hash function used for the hash table is the common `pdb_hash_index` function (also see the _PDB Information Stream_ section),
i.e. the index for a string is calculated using
```c
// For reference see `GSI1::hashSz` in `microsoft-pdb/PDB/dbi/gsi.cpp`
u16 gsi_string_hash_index(char *string, u32 gsi_hash_table_size){
    return pdb_hash_index(string, strlen(string), gsi_hash_table_size);
}
```
**WARNING:** In particular this means that if the PDB was created using `/DEBUG:FASTLINK`, the `gsi_hash_table_size` is `0x3ffff`, 
but the `gsi_string_hash` function truncates the value to a `u16`.
Hence, more then 50% of the hash buckets are always empty. Also notice that the truncation occurs **AFTER** the modulation
by `0x3ffff`, which changes the resulting hash index.

The hash table contains a hash record for every non-`S_PUB32` symbol record in the symbol record stream.
This is maybe unexpected based on the this being the _global_ symbol index stream, 
but in this case the _global_ in this case is means in a C-way, where the global can be either static or exported, 
and not in a linker-way, where global and local are usually used for external, and internal linkage.

It is important to note, that `pdb_hash_index` is case invariant, i.e "asd" and "ASD" produce the same hash index 
and thus the symbols would end up in the same bucket.
Within a bucket first should be exported symbols (`S_PROCREF`, `S_GDATA32`, ...)
such that if one attempts to look up a symbol one will first find the exported symbol, before potentially
finding a static symbols with the same name.

The code in the [microsoft-pdb](https://github.com/microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/dbi/gsi.cpp#L1218)
repository maintains this invariant by appending new static symbols, and prepending exported ones.

## Public Symbol Index Stream

The _public symbol index_ or _PSI_ stream is somewhat similar to the global symbol index stream, 
only that it only refers to `S_PUB32` symbols and contains some additional information.
`S_PUB32` or _public symbols_ represent symbols in a way the linker cares about, just names and addresses.
They have the following layout:
```c
struct codeview_public_symbol{
    struct codeview_symbol_header header;
    u32 flags;
    u32 offset_in_section;
    u16 section_id;
    char name[];
};
```
* `flags`

The following flags are defined:
```c
enum codeview_public_symbol_flags{ // ref 'CV_PUBSYMFLAGS' in 'cvinfo.h'
    CODEVIEW_PUBLIC_SYMBOL_FLAG_code            = 1, // (cvpsfCode)
    CODEVIEW_PUBLIC_SYMBOL_FLAG_function        = 2, // (cvpsfFunction)
    CODEVIEW_PUBLIC_SYMBOL_FLAG_managed_code    = 4, // (cvpsfManaged)
    CODEVIEW_PUBLIC_SYMBOL_FLAG_managed_il_code = 8, // (cvpsfMSIL)
};
```

* `offset_in_section`, `section_id`

A section_id:offset address of the symbol.

* `name`

The zero-terminated name of the symbol.

There is one `S_PUB32` for every exported symbol as well as for special symbols like dll-imports and -exports.
These records are important for incremental linking, but they are also present, when using `/INCREMENTAL:no`.
Microsoft public symbol server PDBs (mostly) only contain these sort of symbol records.

### Layout
The _Public Symbol Index Stream_ starts off with a header:
```c
struct public_symbol_index_stream_header{
    u32 hash_table_information_bytes_size;
    
    u32 address_map_byte_size;
    
    u32 number_of_thunks;
    u32 thunk_bytes_size;
    u16 thunk_table_section_id;
    u16 padding;
    u32 thunk_table_offset_in_section;
    u32 number_of_sections_in_thunk_section_map;
};
```
* `hash_table_information_byte_size`

Immediately following the header, there is a variant of the global symbol index stream used to map symbol names to 
`S_PUB32`-symbol records. 
As it is not allowed for two exported symbols to have the same name, this table only holds one 
record for any given name.

* `address_map_byte_size`

The byte size of the _address map_. 
The address map is an array of `u32`-offsets to `S_PUB32`-symbol records, 
ordered first by section then by offset and lastly by name.

This array can be used to binary search for a `S_PUB32` by address:

```c
u16 section_id = ???; // Section of the S_PUB32 we are searching for.
u32 offset     = ???; // Offset in section of the S_PUB32 we are searching for.
u32 *address_map = (u32 *)(public_symbol_index_stream.base + public_symbol_index_stream_header.hash_table_information_byte_size);

int min = 0, max = public_symbol_index_stream_header.address_map_byte_size/sizeof(*address_map) - 1;

int found = -1;

while(min < max){
    int mid = min + (max - min) / 2;
    
    struct codeview_public_symbol *public_symbol = (void *)(symbol_record_stream.data + /*C13 signature*/4 + address_map[mid]);
    
    if(section_id < public_symbol->section_id){
        max = mid - 1;
    }else if(section_id > public_symbol->section_id){
        min = mid + 1;
    }else if(offset < public_symbol->offset){
        max = mid - 1;
    }else if(offset > public_symbol->offset){
        min = mid + 1;
    }else{
        found = mid;
        break;
    }
}
```


* `number_of_thunks`, `thunk_byte_size`, `thunk_table_section_id`, `thunk_table_offset_in_section`

These members describe the incremental linking table. The incremental linking table is usually located at the beginning of the `.text` section and looks as follows:

```
@ILT+0(float_function):
  0000000140001005: E9 36 01 00 00     jmp         float_function
@ILT+5(function9):
  000000014000100A: E9 F1 00 00 00     jmp         function9
@ILT+10(function4):
  000000014000100F: E9 9C 00 00 00     jmp         function4
@ILT+15(function3):
  0000000140001014: E9 87 00 00 00     jmp         function3
@ILT+20(function5):
  0000000140001019: E9 A2 00 00 00     jmp         function5
@ILT+25(function8):
  000000014000101E: E9 CD 00 00 00     jmp         function8
@ILT+30(function7):
  0000000140001023: E9 B8 00 00 00     jmp         function7
@ILT+35(main):
  0000000140001028: E9 E3 00 00 00     jmp         main
```
After the address map, there is the _thunk map_. The thunk map is an array of `u32` relative virtual addresses, one for every thunk.
The relative virtual address points to the function pointed to by the incremental linking thunk.


* `number_of_section_in_thunk_section_map`

Following the _thunk map_ there is an array of relative virtual addresses and corresponding section ids, i.e.
```c
struct pdb_thunk_section_map_entry{
    u32 relative_virtual_address;
    u16 section_id;
    u16 padding;
};
```
This array is used to lookup whether a given virtual address is part of the incremental linking table.
As a result, there seems to be only ever one entry in this array corresponding the the `.text` section.


## Named streams

Named streams are streams referenced by the named stream table inside the PDB Information Stream.
Besides the /names stream (which we already documented above) they are all optional.
Named streams allow application to add arbitrary data to PDBs. As such some named streams are not understood.

### /LinkInfo

The /LinkInfo stream is sometimes present but I could only find it empty. Based on the source code it 
seems can hold a [LinkInfo](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/langapi/include/pdb.h#L500)
structure

```c
struct LinkInfo{
    u32 size;
    u32 version;
    u32 offset_to_current_working_directory;
    u32 offset_to_command;
    u32 offset_to_output_file_in_command;
    u32 offset_to_libraries;
};
```
followed by the three zero terminated strings; the "current working directory", the link command 
and the libraries used during linking.
The `offset_to_output_file_in_command` is an offset inside the command string, which point to
the filename in `-out:filename.exe`, which is guaranteed to be at the end of the command string.

### /src/headerblock

The /src/headerblock stream is used to embedd .natvis files into the .pdb. This can be done using 
the /NATVIS linker option. These files allow you to specify custom debugging visualizations for types.
For more information see [here](https://learn.microsoft.com/en-us/visualstudio/debugger/create-custom-views-of-native-objects?view=vs-2022).
The layout of this stream can be inferred from the [structures](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/langapi/include/pdb.h#L662C11-L662C11) provided in the microsoft-pdb repository
or the [implementation by llvm](https://github.com/llvm/llvm-project/blob/main/llvm/lib/DebugInfo/PDB/Native/InjectedSourceStream.cpp).

(Sorry I don't care enough about C++ to make it more debuggable)

### /TMCache

This stream is relativly new (the version is `0x20200229` or 29.02.2020) and 
seems to be a cache for the type maps ([tm.h](https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/tm.h) and [tm.cpp](https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/tm.cpp)).
You can dump its contents using the functions `DBIFSetPfnDumpTMCache` and `DBIDumpTMCache` from `mspdbcore.dll`, to get a printout like this:

```
 ** Version : 538968617 (0x20200229)

 ** Modules
    #0000 checksum = F452FB84F3460CC2, cache = #0009
    #0001 checksum = 16B47A3BA60C2DEA, cache = #0008
    #0002 checksum = 1F4D35502B41B232, cache = #000A

 ** Cache #0009

    TYPE (8)

   00001000: 00001000 00001001 00000000 00000000 00001002 00001003 00000000 00000000

    ID (25)

   00001000: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
   00001008: 00000000 00001000 00001002 00001003 00001006 00001007 00001008 00001009
   00001010: 00001004 00001005 0000100A 00000000 00000000 00000000 00000000 00000000
   00001018: 00000000

    Func ID to TI mapping

   00001009->00001009

 ** Cache #0008

    TYPE (8)

   00001000: 00001000 00001001 00000000 00000000 00000000 00000000 00001004 00001005

    ID (25)

   00001000: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
   00001008: 00000000 00001000 00001002 00001003 00001006 00001007 00001008 00001009
   00001010: 00001004 00001005 0000100A 00000000 00000000 00000000 00000000 00000000
   00001018: 00000000

    Func ID to TI mapping

   00001009->00001009

 ** Cache #000A

    TYPE (8)

   00001000: 00001000 00001001 00000000 00000000 00001002 00001003 00000000 00000000

    ID (25)

   00001000: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
   00001008: 00000000 00001000 00001002 00001003 00001006 00001007 00001008 00001009
   00001010: 00001004 00001005 0000100A 00000000 00000000 00000000 00000000 00000000
   00001018: 00000000

    Func ID to TI mapping

   00001009->00001009
```
Doing some debugging/reversing we can see, that the /TMCache stream has the following layout
```c
    u32 version;
    u32 header_size;
    u32 stream_indices_byte_size;
    u32 checksum_offset;
    u32 checksum_byte_size;
    u16 module_cache_stream_index[stream_indices_byte_size/2];
    struct{
       u32 module_index;
       u32 not_sure;
       u8 checksum[8];
    } checksums; // DBI1::TMCacheModInfo
```
and the cache stream for each module (`module_cache_stream_index[module_index]`) has one of the following layouts:

```c
    u32 version; // 1
    u32 amount_of_type_indices;
    u32 amount_of_offsets;
    u32 type_indices[];
    u32 offsets[]; // specifies offsets in the tpi or ipi stream
```
or 
```c
    u32 version; // 2
    u16 PCH_TMCache_stream_index; // PCH - precompiled header
    u16 padding;
    u32 signature;
    u32 minimal_type_index;
    u32 amount_of_type_indices_following_the_header;
    
    u32 type_indices[amount_of_type_indices_following_the_header];
    u32 offsets[amount_of_type_indices_following_the_header + 1];
   
    struct{
        u32 func_id;    // An "id index" inside the ipi stream of an LF_FUNC_ID.
        u32 type_index; // The type index of the type of the corresponding function.
    } func_id_to_ti_mapping[];
```
This stream only seems to be here to speed up incremental linking in some way and hence nobody 
cares probably, but I felt I should do some digging for completeness sake.

# CodeView

As stated in the overview, CodeView is the debugging information format created by Microsoft.
It has quite the history, its inception probably dating back to the 1985 CodeView debugger created
by David Norris (at least according to [Wikipedia](https://en.wikipedia.org/wiki/CodeView)).
As such there are a lot of quirks and old definitions.

The best sources for CodeView are by far the header files [cvinfo.h](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h) and [cvconst.h](https://github.com/microsoft/microsoft-pdb/blob/master/include/cvconst.h) released by microsoft.
They contain all the symbol and structure definitions, which is most of what one needs as this is simply a 
serialized symbol/type format. There also is an old [Tool Interface Standards (TIS) document](https://www.openwatcom.org/ftp/devel/docs/CodeView.pdf)
describing some of the CodeView type and symbol records.

## CodeView Format Overview

There are three parts to CodeView, there are type records ([`LEAF_ENUM_e`](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L772C14-L772C26)), 
symbol records ([`SYM_ENUM_e`](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L2735C14-L2735C25)) and line information ([`DEBUG_S_SUBSECTION_TYPE`](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4576C14-L4576C14`)).
We have already provided some documentation about these inside the `TPI Stream` and `Module Symbol Stream` sections above.

Each of these consist of an "array" of serialized variable length structures. Each of these structures starts of with a header describing its length in some way.
Type and symbol records start with the following header:

```c
struct record_header{
    u16 length;
    u16 kind;
};
```
Here, the `length` of the record does not include the `length` field itself. There is some [helper](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L1175) [code]((https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3156)) inside cvinfo.h.
All records _should_ (microsoft does not honor this themselfs) start on a 4-byte boundary and the be padded using the bytes `0xf3` `0xf2` and `0xf1`.

The "line information" has a similar 8-byte header:
```c
struct codeview_debug_subsection_header{
    DEBUG_S_SUBSECTION_TYPE type;
    u32 length;
};
```
Here, the whole header is not part of the `length`.
We have already documented this inside the Line Information subsection of the Module Symbol Stream section.
One remark is that inside object files, the symbol records are contained inside a debug subsection with type `DEBUG_S_SYMBOLS (0xf1)`,
but inside the .pdb, it has its own place at the start of the module symbol stream.

### Type Indices

The order of type records gives rise to so called type indices. The first 0x1000 type indices are reserved for basic types.
The `i`'th  type record has the type index `0x1000 + i`:
```
*** TYPES

0x1000 : Length = 10, Leaf = 0x1201 LF_ARGLIST argument count = 1
	list[0] = T_NOTYPE(0000)

0x1001 : Length = 14, Leaf = 0x1008 LF_PROCEDURE
	Return type = T_INT4(0074), Call type = C Near
	Func attr = none
	# Parms = 0, Arg list type = 0x1000

0x1002 : Length = 22, Leaf = 0x1506 LF_UNION
	# members = 0,  field list type 0x0000, FORWARD REF, Size = 0	,class name = u, unique name = .?ATu@@, UDT(0x00001005)

0x1003 : Length = 10, Leaf = 0x1002 LF_POINTER
	Pointer (__ptr64), Size: 8
	Element type : 0x1002

0x1004 : Length = 14, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_MEMBER, public, type = 0x1003, offset = 0
		member name = 'u'

0x1005 : Length = 22, Leaf = 0x1506 LF_UNION
	# members = 0,  field list type 0x1004, SEALED, Size = 8	,class name = u, unique name = .?ATu@@, UDT(0x00001005)

...
```
(Generated with cvdump.exe). These type indices allow types to refer to other types. 
For example, the procedure type at type index `0x1001` has an argument list type of `0x1000`.
We can also see the interpretation of the type records below `0x1000`. These are from the [`TYPE_ENUM_e`](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L328) enum and are fixed basic types.
Type record `0x1000` corresponds to the argument list `(void)`. Type record `0x1001` corresponds to the function type `int (void)`.

One other invariant can be observed in the later records: Type records can only refer to type records which have a lower type index.
Because of this the pointer type at type index `0x1003` referes to the type record `0x1002` which is a forward reference, 
instead of the type record at type index `0x1005` which is the definition. Decoding the type records we can see that the type is:
```c
union u{
    union u *u;
};
```

One more interesting thing is the structure of an `LF_FIELDLIST`. It starts out with the usual header, 
but is then immediately followed by a sequence of `LF_MEMBER` entries. Each has the following layout:
```c
typedef struct lfMember {
    unsigned short  leaf;           // LF_MEMBER
    CV_fldattr_t    attr;           // attribute mask
    CV_typ_t        index;          // index of type record for field
    unsigned char   offset[CV_ZEROLEN];       // variable length offset of field followed
                                    // by length prefixed name of field
} lfMember;
```
Definition taken from [here](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L2580C1-L2587C1).
Each of these members is aligned on a 4-byte boundary. The "variable length offset" is a numeric leaf (see below). 
The "length prefixed string" is just a zero-terminated string. The comment probably dates back to when pascal strings were used (see "Old CodeView Symbols" section).

As there can be an arbitrary amount of members inside of the `LF_FIELDLIST`, the size needed could exceed the bounds of the `u16` `length` field.
For this case there exists the `LF_INDEX` type record:
```
0x1018 : Length = 64250, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_MEMBER, public, type = T_INT4(0074), offset = 16060
		member name = 'a4015'
<...>

0x1019 : Length = 64250, Leaf = 0x1203 LF_FIELDLIST
	list[0] = LF_MEMBER, public, type = T_INT4(0074), offset = 0
		member name = 'a0'
<...>
	list[4014] = LF_MEMBER, public, type = T_INT4(0074), offset = 16056
		member name = 'a4014'
	list[4015] = LF_INDEX, Type Index = 0x1018
```
In "theory" the length field could still overflow if a large enough `name` is specified, but MSVC limits its tokens to `4095` bytes.

### Numeric leaves

A lot of symbol and type records contain variable length integers called _numeric leaves_.
We have already seen this in the `LF_MEMBER` structure. Inside `cvinfo.h` they are usually only indicated by a comment,
but (e.g. `LF_MEMBER`) but sometimes there is also a `unsigned short` in its place:
```c
typedef struct CONSTSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_CONSTANT or S_MANCONSTANT
    CV_typ_t        typind;     // Type index (containing enum if enumerate) or metadata token
    unsigned short  value;      // numeric leaf containing value
    unsigned char   name[CV_ZEROLEN];     // Length-prefixed name
} CONSTSYM;
```
(See [here](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L3257C1-L3263C12)).
Numeric leaves are used to indicate `size`, `count` or `value` fields. They are at least 2 bytes, i.e a `u16` (unsigned short).
If this `u16` does NOT have its top-most bit set, i.e `(numeric_leaf & 0x8000) == 0` the value is simply this `u16`.
Otherwise, this specifies which type of value comes after. [Here](https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L937) is a list of these values. 
For example:
```
01 00                         -> Top bit not set -> value = 1
00 80 ff                      -> LF_CHAR         -> value = (char)-1
0a 80 00 00 00 00 00 00 00 00 -> LF_UQUADWORD    -> value = (u64)0
```

### Symbol Records

Symbols records are in some sense simpler than type records, because there is no concept of _symbol indices_. 
There are also a lot of "random" symbol records, e.g: `S_TRAPOLINE`, `S_SEPCODE`, `S_FRAMECOOKIE`, ...
Documenting all of these is out of scope, but we will provide some documentation on procedure debug information,
as it has an interesting hierarchy.

For each function there is a `S_GPROC32` or `S_LPROC32` symbol (inside the object files these are `S_GPROC32_ID` and `S_LPROC32_ID` for some reason):
```c
typedef struct PROCSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GPROC32, S_LPROC32, S_GPROC32_ID, S_LPROC32_ID, S_LPROC32_DPC or S_LPROC32_DPC_ID
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    unsigned long   len;        // Proc length
    unsigned long   DbgStart;   // Debug start offset
    unsigned long   DbgEnd;     // Debug end offset
    CV_typ_t        typind;     // Type index or ID
    CV_uoff32_t     off;
    unsigned short  seg;
    CV_PROCFLAGS    flags;      // Proc flags
    unsigned char   name[1];    // Length-prefixed name
} PROCSYM32;
```
Implicitly, this opens a "block". The end of the block is an `S_END` symbol. 
The `pEnd` member is the offset from the base of the symbol records to the `S_END` symbol of the initial block created by the `PROCSYM32`.
This can be used to skip the debugging information for a function and "walk" to the next symbol.
One remark here, is that inside .obj files `pEnd` is zero and the terminating `S_END` is instead a `S_PROC_ID_END`.

New blocks can be opened using the `S_BLOCK32` symbol record:
```c
typedef struct BLOCKSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_BLOCK32
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   len;        // Block length
    CV_uoff32_t     off;        // Offset in code segment
    unsigned short  seg;        // segment of label
    unsigned char   name[1];    // Length-prefixed name
} BLOCKSYM32;
```
These blocks contain the debug information of local variables. 
There are two ways to define debug information for local variables.
The simple way (used by debug builds) is to use blocks and `S_REGREL32` symbols:
```c
typedef struct REGREL32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_REGREL32
    CV_uoff32_t     off;        // offset of symbol
    CV_typ_t        typind;     // Type index or metadata token
    unsigned short  reg;        // register index for symbol
    unsigned char   name[1];    // Length-prefixed name
} REGREL32;
```
The more complex way is to use `S_LOCAL` symbols:
```c
typedef struct LOCALSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_LOCAL
    CV_typ_t        typind;     // type index   
    CV_LVARFLAGS    flags;      // local var flags

    unsigned char   name[CV_ZEROLEN];   // Name of this symbol, a null terminated array of UTF8 characters.
} LOCALSYM;
```
Immediately followed by `S_DEFRANGE_*` symbols:

```c
typedef struct DEFRANGESYMREGISTER {    // A live range of en-registed variable
    unsigned short     reclen;     // Record length
    unsigned short     rectyp;     // S_DEFRANGE_REGISTER 
    unsigned short     reg;        // Register to hold the value of the symbol
    CV_RANGEATTR       attr;       // Attribute of the register range.
    CV_LVAR_ADDR_RANGE range;      // Range of addresses where this program is valid
    CV_LVAR_ADDR_GAP   gaps[CV_ZEROLEN];  // The value is not available in following gaps. 
} DEFRANGESYMREGISTER;

typedef struct DEFRANGESYMFRAMEPOINTERREL {    // A live range of frame variable
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_DEFRANGE_FRAMEPOINTER_REL

    CV_off32_t      offFramePointer;  // offset to frame pointer

    CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
    CV_LVAR_ADDR_GAP   gaps[CV_ZEROLEN];  // The value is not available in following gaps. 
} DEFRANGESYMFRAMEPOINTERREL;

<...>
```
This more complex version allows variables to be defined in arbitrary ranges in various locations,
like registers or multiple stack locations. This is used to for optimized code.
The `S_REGREL32` only allow for defining variables relative to some register, usually `rsp` or `rbp`.

### New CodeView Symbols
Since these header files were released, some new type/symbol records have been released.
There are tables inside of `mspdbcore.dll`. Dumping these table, the new type records are:

```c
enum LEAF_ENUM_e{
    // ...
    
    LF_CLASS2     = 0x1608,
    LF_STRUCTURE2 = 0x1609,
    LF_UNION2     = 0x160a,
    LF_INTERFACE2 = 0x160b,
};
```
These new type records are of the form:
```c
struct lfClass2 {
    unsigned short  leaf;           // LF_CLASS2, LF_STRUCTURE2, LF_INTERFACE2
    CV_prop32_t     property;       // property attribute field (prop_t)
    CV_typ_t        field;          // type index of LF_FIELD descriptor list
    CV_typ_t        derived;        // type index of derived from list if not zero
    CV_typ_t        vshape;         // type index of vshape table for this class

    u8 data[CV_ZEROLEN];            // variable length data specifying count, length
                                    // name and mangled name
};
```
Here the `data`, contains two _numeric leaves_ (see above) which specify the count, i.e. 
the amount of member of the structure/class/interface and the length, i.e. the size in bytes.
The are followed by two zero-terminated strings.

Extrapolating from the difference between `lfClass` and `lfUnion` this would presumably mean `lfUnion2` looks as follows:

```c
struct lfUnion2 {
    unsigned short  leaf;           // LF_UNION2
    CV_prop32_t     property;       // property attribute field (prop_t)
    CV_typ_t        field;          // type index of LF_FIELD descriptor list

    u8 data[CV_ZEROLEN];            // variable length data specifying count, length
                                    // name and mangled name
};
```
But it seems this symbol is currently not in use (using MSVC 19.28.29336).

The newly added symbols are:
```c
enum SYM_ENUM_e{
    // ...
    
    S_FRAMEREG                    = 0x1166,
    S_REF_MINIPDB2                = 0x1167,
    S_INLINEES                    = 0x1168,
    S_HOTPATCHFUNC                = 0x1169,
    S_BPREL32_INDIR               = 0x1170,
    S_REGREL32_INDIR              = 0x1171,
    S_GPROC32EX                   = 0x1172,
    S_LPROC32EX                   = 0x1173,
    S_GPROC32EX_ID                = 0x1174,
    S_LPROC32EX_ID                = 0x1175,
    S_STATICLOCAL                 = 0x1176,
    S_DEFRANGE_REGISTER_REL_INDIR = 0x1177,
    S_BPREL32_ENCTMP              = 0x1178,
    S_REGREL32_ENCTMP             = 0x1179,
    S_BPREL32_INDIR_ENCTMP        = 0x117a,
    S_REGREL32_INDIR_ENCTMP       = 0x117b,
};
```
The `S_REF_MINIPDB2` symbol corresponds to a version of the `REFMINIPDB` structure which drops the `imod` field,
as these structures are contained in the module symbol stream of module `imod`. Hence, you can always infer it. 
```c
typedef struct REFMINIPDB2 {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_REF_MINIPDB2
    union {
        unsigned long  isectCoff;       // coff section
        CV_typ_t       typind;          // type index
    };
    unsigned short  fLocal   :  1;      // reference to local (vs. global) func or data
    unsigned short  fData    :  1;      // reference to data (vs. func)
    unsigned short  fUDT     :  1;      // reference to UDT
    unsigned short  fLabel   :  1;      // reference to label
    unsigned short  fConst   :  1;      // reference to const
    unsigned short  reserved : 11;      // reserved, must be zero
    unsigned char   name[1];            // zero terminated name string
} REFMINIPDB2;
```
The `S_INLINEES` symbol corresponds to a `FUNCTIONLIST` structure. For llvm code see [here](https://github.com/llvm/llvm-project/blob/a7e20dd664bbce6e87b1fdad88d719e497902a42/llvm/lib/DebugInfo/CodeView/TypeIndexDiscovery.cpp#L412C15-L412C15).
All other structures are currently unknown.

The `S_HOTPATCHFUNC` symbol probably corresponds to the new [hotpatch](https://learn.microsoft.com/en-us/cpp/build/reference/hotpatch-create-hotpatchable-image?view=msvc-170)
functionality. 

### Old CodeView Symbols

There are two old CodeView symbol versions. Ones, postfixed `_16t` which means they have 
type indices that are 16-bits instead of the 32-bits used in the current version and 
ones, which are postfixed `_ST` which means any string contained in the records are "u8 pascal strings",
meaning of the form:
```c
struct pascal_string{
    u8 length;
    u8 string[/*length*/];
};
```
Instead of zero-terminated strings. Both of these versions are not really used anymore.

## CodeView Uses

In the following, we will discuss the different kind of files that contain CodeView information.
We will only mention symbols used by C code.

### Object files (.obj)

The Compiler emits two special sections into the object file. The `.debug$S` and the `.debug$T` sections.
(Technically, there is also a `.debug$P` for precompiled header files and a deprecated `.debug$F` see [here](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debugf-object-only)).
The `.debug$T` section contains the type and id information, while the `.debug$S` contains symbol, file and line information.
When COMDAT sections are present (for example extern inline functions or `/Gy`), there sometimes are multiple `.debug$S` sections, but only one not marked `COMDAT` which contains the `DEBUG_S_FILECHKSMS` subsection.

Both of these sections start with the CodeView signature, a 4-byte value of `CV_SIGNATURE_C13 (4)`.
The `.debug$T` then just contains the type and id records for the types used in the object file.
The `.debug$S` section continues with a sequence of `DEBUG_S_SUBSECTIONS`, each of which starts with the following header
```c
struct codeview_debug_subsection_header{
    DEBUG_S_SUBSECTION_TYPE type;
    u32 length;
};
```
as already discussed above. Usually, the following subsections are present:
* `DEBUG_S_SYMBOLS (0xf1)`  
   This subsection contains the symbol records for this object file.

* `DEBUG_S_LINES (0xf2)`
   This subsection contains the line information for this object file.

* `DEBUG_S_STRINGTABLE (0xf3)`   
   This subsection mainly contains the filenames used in the `DEBUG_S_FILECHKSMS` table.
   
* `DEBUG_S_FILECHKSMS (0xf4)`
   This section contains a checksum for each file which is used for line information.

All of these were discussed [above](#line-information).

The following type and id records are usually present inside a `.debug$T` section:

```
LF_PROCEDURE    - function types (and therefore LF_ARGLIST)
LF_STRUCTURE(2) - structures     (and therefore LF_FIELDLIST)
LF_UNION        - unions
LF_POINTER      - pointer types
LF_ENUM         - enums and subsequently LF_ENUMERATE.
LF_ARRAY        - array types
LF_BITFIELD     - Bitfield types
LF_MODIFIER     - For volatile and so on.

LF_UDT_SRC_LINE - one for each union, enum or structure.
LF_FUNC_ID      - for each function

LF_STRING_ID    - for each file name and then for build info
LF_SUBSTR_LIST  - One for build info.
LF_BUILDINFO    - Contains compiler invokation and so on.
```

The following symbol records are usually present inside a `.debug$S` section:
```
S_OBJNAME  - One which contains the name of the object.
S_COMPILE3 - Some information on compile flags and so on.

S_GPROC32_ID - One for each function with external storage class.
S_LPROC32_ID - One for each function with static storage class.
    S_FRAMEPROC, S_BLOCK32, S_END, S_LABEL32, S_REGREL32, S_CALLSITEINFO, ...
S_PROC_ID_END

S_CONSTANT - One for each enum value.
S_UDT      - One for each typedef.

S_GDATA32  - One for each global with external storage class.
S_LDATA32  - One for each global with static storage class.
```
This is obviously just a random sample and there might be many more symbols and types which may be interesting based on the use case.

**WARNING:** Tools like `cvdump.exe` use the `machine` field of the `S_COMPILE3` symbol to decide how to dump certain section of the PDB.

#### Relocations

Because the `.debug$S` sections are contained in object files, which still have to be linked,
they cannot know the location of symbols they refer to. Therefore, there are relocations that have to be applied.
There are two specially designed relocation types for debug information, namely `IMAGE_REL_AMD64_SECTION` and `IMAGE_REL_AMD64_SECREL`.

#### `LF_TYPESERVER2`

When using the [`/Zi` compiler option](https://learn.microsoft.com/en-us/cpp/build/reference/z7-zi-zi-debug-information-format?view=msvc-170#zi) MSVC will split the `.debug$T` section into a PDB.
This PDB, usually named `vc140.pdb` is a _Type Server PDB_ (see below). In this case the only entry inside the 
`.debug$T` section is an `LF_TYPESERVER2` entry:
```c
typedef struct lfTypeServer2 {
    unsigned short  leaf;       // LF_TYPESERVER2
    SIG70           sig70;      // guid signature
    unsigned long   age;        // age of database used by this module
    unsigned char   name[CV_ZEROLEN];     // length prefixed name of PDB
} lfTypeServer2;
```
The output of cvdump.exe is:
```
*** TYPES

0x1000 : Length = 50, Leaf = 0x1515 LF_TYPESERVER2
		GUID={52AFA78E-B63A-4E40-BD69-301A48DF7060}, age = 0x0000001a, PDB name = 'C:\Projects\pdb\vc140.pdb
```
The _advantage_ of this is, that instead writing out all types for all compilation units and then 
deduplicating during the link step, it will deduplicate the type records _on the fly_.

### Type Server PDB

Type Server PDBs are produced during compile time (not link time!) if the [`/Zi` compiler option](https://learn.microsoft.com/en-us/cpp/build/reference/z7-zi-zi-debug-information-format?view=msvc-170#zi) was used. They are usually named `vc140.pdb`.
These PDBs contain 7 Streams: The 4 fixed streams (PDB Information, TPI, DBI, IPI), the /names stream and the TPI and IPI hash streams.
Most notable, the DBI stream is empty. In other words, these PDBs only really contain type records, id records and the associated speed-up structures.

These type server PDBs are referenced by the object files using the `LF_TYPESERVER2` type record.
During linking (using /DEBUG:FULL), the linker then includes the type records in the final PDB.

### /DEBUG:FULL PDB

This is the _standard_ PDB. As we have already seen above, what information is provided to the linker,
we can now try to understand what the linker does to this information and where it is saved.


