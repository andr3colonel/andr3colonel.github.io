---
layout: post
title:  "Writing a wasm loader for Ghidra. Part 2: Implementing loader"
date: 2019-17-03
categories: ghidra
tags: ghidra, WebAssembly
excerpt: 
mathjax: true
---


In the previous article I’ve described how to build the simple module to parse WebAssembly binary loader for the Ghidra. The module, that I created, contains blank loader, blank analyzer, and placeholder for the processor. The only functionality it provides -- verification of the header and suggesting the loader to parse input file. 

In this article I’m going to finish implementation of the loader. As the result, I expect to human-readable structure of the file and set of the methods exposed by the binary. Methods should be named according to the meta-information, contained in the input file.

But before I dive into coding, I propose to review the workflow of file analysis and understand what callbacks Ghidra provides to the developer.






After the user creates project, and choses what file he wants to import, Ghidra calls method getSupportedLoadSpecs of the class LoaderService. The method tries to find all the loaders, that can process choosen file. It gathers all the objects, instantiated from the AbstractProgramLoader or it’s sublasses (loaders) and calls the method findSupportedLoadSpecs from each of them. This method is abstract and should be implemented by the loader. Because I’ve already implemented it in the previous article, I won’t stop on details of it’s implementation here. 

The method checks is loader able to process given file, and returns back array of the LoadSpelic objects. Each object contains information of those who will further process the file and what Processor will be used to disassembly instructions. 

Ghidra takes the output of query to LoaderService and use it to fill the fields of import dialog, allowing user to choose which loader Ghidra will use to process the file.

After the user chooses parameters and clicks OK button, Ghidra calls method load of chosen loader. The method creates and returns back object of the class Program, which represents the memory, the symbols and the listing of processed file. 
There are number of template classes, inherited from the AbstractProgram, taking initial setup and initialisation of the Program. I’ve decided to use AbstractLibrarySupportLoader as base class for my loader, because, according documentation, it provides “provides a framework to conveniently load Programs with support for linking against libraries contained in other Programs”. As far as binary contains import section, it would be convenient to use this class to show import methods from there. Fortunately, this class already implemented initialization of the default application and allocating of the memory, chosen for the default processor. After default allocation has done, it calls abstract method load, which should be overridden by developer in the subclass. This method allocates addition program memory, processes relocations and add symbols.

Now it’s left to implement the method load, which will parse input wasm file, extract information about methods and create symbols for them. The methods will be handy to do this are:

MemoryBlockUtil.createInitializedBlock. The method creates block in the virtual memory of the program and fills it with the values from the source. Ghidra will shows created blocks in the UI window “Program Trees


DataUtilities.createData. It takes the structure, introduced by the object of DataType class, and applies it to the given address. Ghidra will annotate the data at the address according to the format of the structure:

FunctionManager.CreateFunction. It marks range of memory as function. In the listing ghidra adds headers before the addresses marked as function.

Symbols, marked as methods, are exposed to the Function directory of the Symbols tree.


Now, let’s see how is wasm format works and what information I can get from there to achieve the goal. Unfortunately I’m not have too much time to implement everything, so I will focus on structures, helping to solve the challenge. 

You can read the comprehensive description of the wasm format at this outstanding repository of Dan Gohman. I’ll highlight only the parts, required for the reverse engineering. In high-level terms, structure of the wasm file can be represented by the following table: 



File starts with a header, containing magic identifier “\0asm” and version of the file format. The header is followed by a sequence of sections. Each section contains identifier, length of the data (in bytes) and, actually data. Format of the data depends on the ty. of the section. 
There are two categories of the sections. Custom section is aimed to extencion of the format by developer, has 0 in the id field, and is out of scope of this article. Known section has Id in range 1-11, and defined in the  specification of the format. 
The most interesting sections from reverse-engineering perspective are those which are contain metadata and instructions for the methods. I’ve represented them as entity-relation diagram:



Section “functions” binds entities from types and export with code entries. Exports and type contain information about method: name and parameters, while the entries from code section contain code instructions. 
All the numbers in wasm are represented by LEB128 format.

Now it’s time to implement obtained knowledge into the code. As usual, you can get the full code from the repository. In the article I’ll tell stop on the code, essential to understanding development process of the loader.

All the classes, describing the structures of wasm in my module consist of two parts. First part is placed in constructor and deserialize data from BinaryReader to java objects. Second part converts analyse read data and returns description of its structure. To build it, I make every structure class to implement interface StuctureConverter. It introduces contract, obligating it’s subclases to return DataType object. This object later will be used to map structures to address space and make it human-readable. 

Easiest example is the header structure: it has fixed eight bytes size and only two fields: string magic and double word version. 

    private byte[] magic;
    private int version;

public WasmHeader(BinaryReader reader) throws IOException {
        magic = reader.readNextByteArray( WasmConstants.WASM_MAGIC_BASE.length() );
        version = reader.readNextInt();
        if (!WasmConstants.WASM_MAGIC_BASE.equals(new String(magic))) {
            throw new IOException("not a wasm file.");
        }
  }

Method describing this structure is pretty straight-forward. It creates structure and adds to it fields, with the method add, taking as arguments field’s type, size and name. 

@Override
    public DataType toDataType() throws DuplicateNameException, IOException {
    //create named structure
        Structure structure = new StructureDataType("header_item", 0);
    //the first item of the structure is a string, it’s size is four bytes
        structure.add(STRING, 4, "magic", null);
       //the second of the structure is a string, it’s size is four bytes
        structure.add(DWORD, 4, "version", null);
        return structure;
    }

Later on, structure is passed to method createData, telling Ghidra, that data on start of program has a header format. 

Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
createData(program, program.getListing(), start, header.toDataType());

Result of execution of the code on picture:


It works for the fixed-size structures, but very often size of structure is variable and depends on data. As I told before, all the numbers in wasm format are encoded into the Leb128 format. Parsing this format, application reads bytes one-by-one, until it met byte which highest bit is non-zero. In other words, result size may be from one to five bytes. I convert it to data type, returning one of the predefined method, depends on data size. 
@Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        length = Leb128.unsignedLeb128Size(value);
        switch (length) {
            case 1:
                return ghidra.app.util.bin.StructConverter.BYTE;
            case 2:
                return ghidra.app.util.bin.StructConverter.WORD;     
            case 4:
                return ghidra.app.util.bin.StructConverter.DWORD;
        }
        return null;        
    }

Let’s see how it works on real word. For example we have structure with two fields: body_size and local_count, encoded to Leb128 format

private Leb128 body_size; // 0x99 0x02
private Leb128 local_count; // 0x01

During initialization they read their values from BinaryReader object. Let’s assume that body_size has two-bytes lengths and local_count is just one byte. 

private Leb128 body_size = new Leb128(reader); // 0x99 0x02
private Leb128 local_count  = new Leb128(reader); // 0x01

As before, method toDataType creates structure, but instead of usage of predefined types and hardcoded length, it uses type returned by Leb128 object

@Override
    public DataType toDataType() throws DuplicateNameException, IOException {
    //create named structure
        Structure structure = new StructureDataType("function_1", 0);
    //this time type and the length of the field is depends on data. 
    //in this case type of the body_size is WORD and size is two bytes
        structure.add(body_size.toDataType(), body_size.toDataType().getLength(), "body_type", null);
       //type of the local_count is BYTE and size is one byte
        structure.add(local_count.toDataType(), local_count.toDataType().getLength(), "local_count", null);
        return structure;
    }

When this data type will be mapped on data, it will looks like that, correctly representing the variable LEB128 format. 



Parsing of the whole section is bit more complex, but is based on the same principle: it’s need to create structure and add fields, considering that field can have composed type. 
I’ll demonstrate it on example of exports section. As every section, it starts with the id and size, followed by the sequence of export entries.

private byte id;
private Leb128 size; 
private Leb128 entries_count; 
private List<WasmExportEntry> exports = new ArrayList<WasmExportEntry>();

Export entry implements interface StructureConverter, and returns own structure from method toDataType as well. Method toDataType of the class ExportSection takes the returned structure and adds it to own result, creating hierarchical type. 

@Override
public DataType toDataType() throws DuplicateNameException, IOException {
        Structure structure = new StructureDataType("ExportSection", 0);
    //adds field of primitive type, returned by Leb128 structure
        structure.add(count.toDataType(), count.toDataType().getLength(), "count", null);
    //adds to result complex structure returned by WasmExportEntry
        for (int i = 0; i < count.getValue(); ++i) {
structure.add(exports.get(i).toDataType(), exports.get(i).toDataType().getLength(), "export_"+i, null);
       }        
return structure;
}

After mapping the structure on data, we’ll see hierarchy of nested structures:

There’s a main structure .code, containing payload structure CodeSection, which in his turn includes structure function. Data became structured and easy to read.

The only problem is that instructions, marked as part of structure can’t be decompiled, but in this case it’s possible to find workaround. The this is WebAssembly instructions are high-level, and don’t operate addresses, calling methods by their indexes, which made them position indepened. Therefore, I can move one more “virtual” space, and copy there the code of all methods contained in application:

//Create memory block for the instructions
Address address = Utils.toAddr( program, Utils.METHOD_ADDRESS );
MemoryBlock block = program.getMemory( ).createInitializedBlock( "method_bytecode", address, length, (byte) 0xff, monitor, false );

//for each method copy instructions to virtual memory
for (WasmFunctionBody method: codeSection.getFunctions()) {
    long method_offset = code_offset + method.getOffset();
 method.getInstructions().length);
    Address methodAddress = Utils.toAddr( program, Utils.METHOD_ADDRESS + method_offset );
    byte [] instructionBytes = method.getInstructions();
    program.getMemory( ).setBytes( methodAddress, instructionBytes );
}

After this, I mark each created method as function.

program.getFunctionManager().createFunction("Method_" + lookupOffset, methodAddress, new AddressSet(methodAddress, methodend), SourceType.ANALYSIS);

As result having a nice picture of parsed data and marked instructions, placed in separate memory zones

In next article I’ll try to implement WebAssembly processor, able to disassembly the code



